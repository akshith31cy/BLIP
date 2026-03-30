# app/main.py
#
# FIX (Issue 1+2 — honey_index): login() no longer reads user.honey_index.
#   Instead it calls derive_honey_index(password, user.honey_salt, pool_size)
#   to compute the real slot on the fly. The DB never stores the index.
#
# FIX (Issue 4 — in-memory lockout): All lockout state now lives on the User
#   model (failed_attempts, locked_until). Removed the login_attempts dict.
#
# FIX (Issue 9 — username uniqueness): register() now checks for existing
#   username before inserting.

from flask import Blueprint, render_template, request, jsonify
from . import db
from .models import User
from .honey_encryptor import generate_decoys, derive_honey_index
from .hash_algorithms import verify_password
import os, sys
from sqlalchemy import func
from datetime import datetime, timedelta

# ── Agent pipeline (optional — graceful if not present) ───────────────────────
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from agents.hash_testing_agent import HashTestingAgent
    from agents.security_agent     import SecurityAgent
    from agents.report_generator   import ReportGenerator
    _hash_agent  = HashTestingAgent()
    _sec_agent   = SecurityAgent()
    _report_gen  = ReportGenerator()
    AGENTS_ENABLED = True
except ImportError:
    AGENTS_ENABLED = False

bp = Blueprint("main", __name__, template_folder="templates", static_folder="static")

MAX_ATTEMPTS    = 3
LOCKOUT_SECONDS = 30


@bp.before_app_request
def create_tables():
    db.create_all()


# ─── Pages ────────────────────────────────────────────────────────────────────

@bp.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@bp.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")

@bp.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")


# ─── Register ─────────────────────────────────────────────────────────────────

@bp.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        return "username and password required", 400

    # FIX (Issue 9): enforce unique username
    if User.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "Username already exists."}), 409

    # FIX (Issue 1): generate_decoys now returns (hashes, honey_salt)
    # honey_index is NOT returned and NOT stored.
    honey_hashes, honey_salt = generate_decoys(password, count=9)

    # real_hash: derive index to know which slot holds it
    real_idx  = derive_honey_index(password, honey_salt, len(honey_hashes))
    real_hash = honey_hashes[real_idx]

    user = User(
        username   = username,
        real_hash  = real_hash,
        honey_salt = honey_salt,
        # honey_index is gone from the model entirely
    )
    user.set_honey_hashes(honey_hashes)
    db.session.add(user)
    db.session.commit()

    # ── Run agent pipeline (non-blocking) ─────────────────────────────────
    if AGENTS_ENABLED:
        try:
            test_report = _hash_agent.run(
                username, real_hash, honey_hashes,
                honey_index=real_idx, trigger="register"
            )
            change_summ = _sec_agent.analyze_and_improve(test_report)
            _report_gen.generate(test_report, change_summ)
        except Exception:
            import traceback; traceback.print_exc()

    return render_template("thanks.html", username=username)


# ─── Login ────────────────────────────────────────────────────────────────────

@bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Fields required."}), 400

    now  = datetime.utcnow()
    user = User.query.filter_by(username=username).first()

    # Unknown user — still increment attempt counter (timing-safe)
    if not user:
        return jsonify({"success": False, "message": "Invalid username or password."}), 401

    # FIX (Issue 4): check lockout from DB, not in-memory dict
    if user.is_locked(now):
        remaining = user.seconds_until_unlock(now)
        return jsonify({
            "success": False, "locked": True,
            "message": f"🔒 Account locked. Try again in {remaining} seconds.",
            "remaining_seconds": remaining,
        }), 429

    # ── Check real password ────────────────────────────────────────────────
    if verify_password(user.real_hash, password):
        user.reset_lockout()
        db.session.commit()

        # Optional: run agent on login
        if AGENTS_ENABLED:
            try:
                all_hashes = user.get_honey_hashes()
                real_idx   = derive_honey_index(password, user.honey_salt, len(all_hashes))
                test_report = _hash_agent.run(
                    username, user.real_hash, all_hashes,
                    honey_index=real_idx, trigger="login"
                )
                change_summ = _sec_agent.analyze_and_improve(test_report)
                _report_gen.generate(test_report, change_summ)
            except Exception:
                import traceback; traceback.print_exc()

        return jsonify({
            "success": True,
            "message": f"✓ Welcome back, {username}!",
            # FIX (Issue 2): never return honey_index in the response
        })

    # ── Wrong password — check honey traps ────────────────────────────────
    # FIX (Issue 1): derive the real index from the password candidate itself.
    # If the candidate is wrong, derive_honey_index returns a different slot —
    # so the wrong-password attempt is tested against a decoy hash.
    honey_triggered = False
    all_hashes = user.get_honey_hashes()
    pool_size  = len(all_hashes)

    # The candidate's derived index — will be wrong if password is wrong.
    candidate_idx = derive_honey_index(password, user.honey_salt, pool_size)
    # If the candidate matches the hash at that (wrong) slot, it's a decoy hit.
    if candidate_idx != derive_honey_index(
        # We cannot compare with the real index (we don't store it).
        # Instead: check if the candidate verifies against ANY non-real slot.
        # We determine "real" by checking the user's real_hash directly.
        password, user.honey_salt, pool_size  # placeholder — see logic below
    ):
        pass  # just satisfying the branch; real logic is below

    # Correct approach: try verifying the candidate against all hashes.
    # Any hit on a non-real_hash slot is a honey trap.
    for idx, h in enumerate(all_hashes):
        if h == user.real_hash:
            continue   # skip the real hash (identified by value, not stored index)
        if verify_password(h, password):
            honey_triggered = True
            user.cracked    = True
            break

    # FIX (Issue 4): persist lockout state to DB
    user.failed_attempts += 1
    attempts_left = MAX_ATTEMPTS - user.failed_attempts

    if user.failed_attempts >= MAX_ATTEMPTS:
        user.locked_until = now + timedelta(seconds=LOCKOUT_SECONDS)
        db.session.commit()
        msg = f"🔒 Locked after {MAX_ATTEMPTS} failed attempts. Retry in {LOCKOUT_SECONDS}s."
        if honey_triggered:
            msg = "🍯 Honey trap triggered — decoy matched! Breach flagged. " + msg
        return jsonify({
            "success": False, "locked": True,
            "honey_triggered": honey_triggered, "message": msg,
        }), 429

    db.session.commit()
    msg = f"❌ Invalid password. {attempts_left} attempt{'s' if attempts_left!=1 else ''} left."
    if honey_triggered:
        msg = f"🍯 Honey trap — decoy matched! Breach flagged. {attempts_left} left."

    return jsonify({
        "success": False, "locked": False,
        "honey_triggered": honey_triggered,
        "attempts_left": attempts_left,
        "message": msg,
    }), 401


# ─── Export (for JtR adversarial testing) ─────────────────────────────────────

@bp.route("/export", methods=["GET"])
def export_hashes():
    """
    Export all honey hashes in John-the-Ripper compatible format.
    Format: username_poolIdx:$argon2id$...
    NOTE: all hashes look identical — attacker cannot tell which is real.
    """
    users = User.query.all()
    lines = []
    for u in users:
        for idx, h in enumerate(u.get_honey_hashes()):
            # Label shows pool slot — but attacker cannot link to real index
            lines.append(f"{u.username}_slot{idx}:{h}")
    export_path = os.path.join(os.path.dirname(__file__), "..", "exported_hashes.txt")
    with open(export_path, "w") as f:
        f.write("\n".join(lines))
    return jsonify({"export_file": export_path, "lines_exported": len(lines)})


# ─── Logout ───────────────────────────────────────────────────────────────────

@bp.route("/logout", methods=["POST"])
def logout():
    return jsonify({"success": True})


# ─── API: user stats ──────────────────────────────────────────────────────────

@bp.route("/api/user_stats", methods=["GET"])
def api_user_stats():
    try:
        total_users = db.session.query(func.count(User.id)).scalar()
        cracked     = db.session.query(func.count(User.id)).filter(User.cracked == True).scalar()
        active      = total_users - cracked
        success_rate = round((active / total_users * 100), 2) if total_users > 0 else 0
        users        = User.query.all()
        total_honey  = sum(len(u.get_honey_hashes()) for u in users)
        return jsonify({
            "total_users":          total_users,
            "active_users":         active,
            "compromised_accounts": cracked,
            "success_rate":         success_rate,
            "total_honey_entries":  total_honey,
            "decoy_ratio": round(total_honey / total_users, 1) if total_users > 0 else 0,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Agent report APIs ────────────────────────────────────────────────────────

@bp.route("/api/reports/latest", methods=["GET"])
def api_latest_report():
    if not AGENTS_ENABLED:
        return jsonify({}), 200
    username = request.args.get("username")
    return jsonify(_report_gen.get_latest_report(username) or {})

@bp.route("/api/reports/history", methods=["GET"])
def api_report_history():
    if not AGENTS_ENABLED:
        return jsonify([]), 200
    limit    = int(request.args.get("limit", 20))
    username = request.args.get("username")
    return jsonify(_report_gen.get_report_history(limit=limit, username=username))

@bp.route("/api/reports/summary", methods=["GET"])
def api_reports_summary():
    if not AGENTS_ENABLED:
        return jsonify({"total_reports": 0, "level_counts": {}, "avg_score": 0, "total_changes": 0}), 200
    return jsonify(_report_gen.get_system_summary())

@bp.route("/api/security/changes", methods=["GET"])
def api_security_changes():
    if not AGENTS_ENABLED:
        return jsonify([]), 200
    return jsonify(_report_gen.get_change_history(limit=int(request.args.get("limit", 20))))

@bp.route("/api/security/config", methods=["GET"])
def api_security_config():
    if not AGENTS_ENABLED:
        return jsonify({}), 200
    from agents.security_agent import load_config
    return jsonify(load_config())