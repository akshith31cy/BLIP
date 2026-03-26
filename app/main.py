# app/main.py
from flask import Blueprint, render_template, request, jsonify
from . import db
from .models import User
from .honey_encryptor import generate_decoys
from .hash_algorithms import verify_password
import os
from sqlalchemy import func
from datetime import datetime, timedelta

bp = Blueprint("main", __name__, template_folder="templates", static_folder="static")

# In-memory lockout store: { username: { "attempts": int, "locked_until": datetime|None } }
login_attempts = {}
MAX_ATTEMPTS = 3
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

    honey_hashes, real_index = generate_decoys(password, count=9)
    real_hash = honey_hashes[real_index]

    user = User(username=username, real_hash=real_hash, honey_index=real_index)
    user.set_honey_hashes(honey_hashes)
    db.session.add(user)
    db.session.commit()

    return render_template("thanks.html", username=username)


# ─── Login (with lockout + honey trap detection) ──────────────────────────────

@bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required."}), 400

    now = datetime.utcnow()
    state = login_attempts.setdefault(username, {"attempts": 0, "locked_until": None})

    # ── 1. Check if currently locked out ──────────────────────────────────────
    if state["locked_until"] and now < state["locked_until"]:
        remaining = int((state["locked_until"] - now).total_seconds())
        return jsonify({
            "success": False,
            "locked": True,
            "message": f"🔒 Account locked. Try again in {remaining} seconds.",
            "remaining_seconds": remaining
        }), 429

    # ── 2. Look up user ───────────────────────────────────────────────────────
    user = User.query.filter_by(username=username).first()

    if not user:
        _increment_attempts(username, now)
        return jsonify({"success": False, "message": "Invalid username or password."}), 401

    # ── 3. Check real password ────────────────────────────────────────────────
    # hash_algorithms.verify_password signature: verify_password(hash_str, password)
    if verify_password(user.real_hash, password):
        login_attempts[username] = {"attempts": 0, "locked_until": None}
        return jsonify({
            "success": True,
            "message": f"✓ Welcome back, {username}!",
            "honey_index": user.honey_index
        })

    # ── 4. Wrong password — check if it matched a DECOY (honey trap!) ─────────
    honey_triggered = False
    all_hashes = user.get_honey_hashes()
    for idx, h in enumerate(all_hashes):
        if idx == user.honey_index:
            continue  # skip the real hash
        if verify_password(h, password):
            honey_triggered = True
            user.cracked = True      # flag account as compromised in DB
            db.session.commit()
            break

    # ── 5. Increment attempt counter / trigger lockout ─────────────────────────
    state["attempts"] += 1
    attempts_left = MAX_ATTEMPTS - state["attempts"]

    if state["attempts"] >= MAX_ATTEMPTS:
        state["locked_until"] = now + timedelta(seconds=LOCKOUT_SECONDS)
        msg = f"🔒 Account locked after {MAX_ATTEMPTS} failed attempts. Try again in {LOCKOUT_SECONDS}s."
        if honey_triggered:
            msg = "🍯 Honey trap triggered — decoy hash matched! Breach flagged. " + msg
        return jsonify({
            "success": False,
            "locked": True,
            "honey_triggered": honey_triggered,
            "message": msg
        }), 429

    msg = f"❌ Invalid password. {attempts_left} attempt{'s' if attempts_left != 1 else ''} remaining."
    if honey_triggered:
        msg = f"🍯 Honey trap triggered — decoy matched! Breach flagged. {attempts_left} attempt{'s' if attempts_left != 1 else ''} remaining."

    return jsonify({
        "success": False,
        "locked": False,
        "honey_triggered": honey_triggered,
        "attempts_left": attempts_left,
        "message": msg
    }), 401


def _increment_attempts(username: str, now: datetime):
    state = login_attempts.setdefault(username, {"attempts": 0, "locked_until": None})
    state["attempts"] += 1
    if state["attempts"] >= MAX_ATTEMPTS:
        state["locked_until"] = now + timedelta(seconds=LOCKOUT_SECONDS)


# ─── Export hashes for adversarial testing ────────────────────────────────────

@bp.route("/export", methods=["GET"])
def export_hashes():
    users = User.query.all()
    lines = []
    for u in users:
        for idx, h in enumerate(u.get_honey_hashes()):
            lines.append(f"{u.username}:{h}:{idx}")
    export_path = os.path.join(os.path.dirname(__file__), "..", "exported_hashes.txt")
    with open(export_path, "w") as f:
        f.write("\n".join(lines))
    return jsonify({"export_file": export_path, "lines_exported": len(lines)})


# ─── API metrics ──────────────────────────────────────────────────────────────

@bp.route("/api/metrics", methods=["GET"])
def api_metrics():
    total_users = db.session.query(func.count(User.id)).scalar()
    cracked = db.session.query(func.count(User.id)).filter(User.cracked == True).scalar()
    users = User.query.all()
    total_honey_entries = sum(len(u.get_honey_hashes()) for u in users)
    return jsonify({
        "total_users": total_users,
        "total_honey_entries": total_honey_entries,
        "cracked_users": cracked
    })


@bp.route("/api/user_stats", methods=["GET"])
def api_user_stats():
    try:
        total_users = db.session.query(func.count(User.id)).scalar()
        cracked = db.session.query(func.count(User.id)).filter(User.cracked == True).scalar()
        active_users = total_users - cracked
        success_rate = round((active_users / total_users * 100), 2) if total_users > 0 else 0
        users = User.query.all()
        total_honey_entries = sum(len(u.get_honey_hashes()) for u in users)
        return jsonify({
            "total_users": total_users,
            "active_users": active_users,
            "compromised_accounts": cracked,
            "success_rate": success_rate,
            "total_honey_entries": total_honey_entries,
            "decoy_ratio": round(total_honey_entries / total_users, 1) if total_users > 0 else 0
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500