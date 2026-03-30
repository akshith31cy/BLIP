#!/usr/bin/env python3
# tests/john_runner.py
#
# Full John the Ripper adversarial pipeline for LEAP.
#
# Steps:
#   1. Export hashes from the LEAP database in JtR format
#   2. Run john --wordlist attack (subprocess)
#   3. Run john --show to extract cracked passwords
#   4. Parse output into structured results
#   5. Compute metrics: crack rate, real vs decoy, time-to-crack
#
# Usage (from project root):
#   python tests/john_runner.py
#   python tests/john_runner.py --wordlist data/rockyou_top_10000.txt --format argon2id
#   python tests/john_runner.py --max-time 120 --runs 3
#
# Prerequisites:
#   john (Jumbo) installed:  sudo apt install john   OR   build from source
#   Verify with:             john --list=formats | grep argon

import os
import re
import csv
import sys
import json
import time
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT        = Path(__file__).parent.parent.resolve()
DB_PATH     = ROOT / "database" / "users.db"
EXPORT_DIR  = ROOT / "tests" / "john_exports"
LOG_DIR     = ROOT / "tests" / "john_logs"
RESULTS_DIR = ROOT / "tests" / "john_results"

for d in (EXPORT_DIR, LOG_DIR, RESULTS_DIR):
    d.mkdir(parents=True, exist_ok=True)

# ── JtR binary detection ───────────────────────────────────────────────────────
_JTR_CANDIDATES = [
    "john",
    os.path.expanduser("~/john-jumbo/run/john"),
    "/usr/sbin/john",
    "/usr/bin/john",
]

def find_john() -> str:
    for candidate in _JTR_CANDIDATES:
        try:
            result = subprocess.run(
                [candidate, "--list=formats"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    raise FileNotFoundError(
        "John the Ripper not found. Install with: sudo apt install john\n"
        "Or build Jumbo from: https://github.com/openwall/john"
    )


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: Hash Export
# ─────────────────────────────────────────────────────────────────────────────

def export_hashes(format_name: str = "argon2id") -> Path:
    """
    Export all honey pool hashes from the LEAP SQLite database
    in John the Ripper compatible format.

    Format (argon2id):  username_slotN:$argon2id$v=19$...
    Format (bcrypt):    username_slotN:$2b$12$...

    All pool slots are exported — attacker cannot distinguish real from decoy.
    Returns path to the exported file.
    """
    import sqlite3, json

    out_file = EXPORT_DIR / f"{format_name}_hashes.txt"
    conn     = sqlite3.connect(DB_PATH)
    cur      = conn.cursor()

    # Use SQLAlchemy-created table schema
    try:
        cur.execute("SELECT username, honey_hashes FROM users")
        rows = cur.fetchall()
    except Exception as e:
        print(f"[ERROR] DB query failed: {e}")
        print("       Is the database initialised? Run the Flask app first.")
        conn.close()
        sys.exit(1)

    conn.close()

    if not rows:
        print("[WARN] No users in database. Register users first via /register.")
        out_file.write_text("")
        return out_file

    written = 0
    with open(out_file, "w", encoding="utf-8") as f:
        for username, honey_hashes_json in rows:
            try:
                hashes = json.loads(honey_hashes_json)
            except Exception:
                continue
            for slot_idx, h in enumerate(hashes):
                label = f"{username}_slot{slot_idx}"
                # Filter by format
                if format_name in ("argon2id", "argon2i", "argon2") and h.startswith("$argon2"):
                    f.write(f"{label}:{h}\n")
                    written += 1
                elif format_name == "bcrypt" and h.startswith("$2"):
                    f.write(f"{label}:{h}\n")
                    written += 1
                elif format_name == "sha256":
                    # sha256 hashes are 64 hex chars
                    if re.fullmatch(r"[0-9a-f]{64}", h):
                        f.write(f"{label}:{h}\n")
                        written += 1

    print(f"[EXPORT] {written} hashes written → {out_file}")
    return out_file


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: Attack Execution
# ─────────────────────────────────────────────────────────────────────────────

def run_john_attack(
    hash_file: Path,
    wordlist:  Path,
    format_name: str,
    john_bin: str,
    max_time: int = 300,
    use_rules: bool = False,
    session_name: str = None,
) -> tuple[float, int, Path]:
    """
    Run John the Ripper dictionary attack.

    Returns:
        (elapsed_seconds, returncode, log_path)
    """
    session_name = session_name or f"leap_{format_name}_{int(time.time())}"
    log_path     = LOG_DIR / f"{session_name}.log"

    cmd = [
        john_bin,
        f"--wordlist={wordlist}",
        f"--format={format_name}",
        f"--max-run-time={max_time}",
        f"--session={session_name}",
        str(hash_file),
    ]
    if use_rules:
        cmd.insert(3, "--rules=Wordlist")

    print(f"[JtR] Running: {' '.join(cmd)}")
    t0 = time.perf_counter()

    with open(log_path, "w") as lf:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            lf.write(line)
            # Print progress lines (contain "g/s" or "p/s")
            if any(kw in line for kw in ["g/s", "p/s", "Loaded", "Remaining", "session"]):
                print(f"  {line.rstrip()}")
        proc.wait()

    elapsed = time.perf_counter() - t0
    print(f"[JtR] Finished in {elapsed:.1f}s — returncode={proc.returncode}")
    return elapsed, proc.returncode, log_path


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: Result Extraction (john --show)
# ─────────────────────────────────────────────────────────────────────────────

def extract_cracked(
    hash_file: Path,
    format_name: str,
    john_bin: str,
) -> list[dict]:
    """
    Run john --show to extract all cracked passwords.

    Returns list of dicts:
      { "label": "alice_slot3", "cracked_password": "password123" }
    """
    cmd = [john_bin, "--show", f"--format={format_name}", str(hash_file)]
    result = subprocess.run(cmd, capture_output=True, text=True)

    cracked = []
    for line in result.stdout.splitlines():
        # JtR show output: label:plaintext:... (at least 2 colon-separated fields)
        # Skip summary lines like "3 password hashes cracked, 7 left"
        if re.search(r"\d+ password hash", line):
            continue
        parts = line.strip().split(":")
        if len(parts) >= 2 and parts[1].strip():
            cracked.append({
                "label":            parts[0],
                "cracked_password": parts[1],
            })

    return cracked


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: Result Parsing — real vs decoy classification
# ─────────────────────────────────────────────────────────────────────────────

def classify_cracked(cracked: list[dict]) -> list[dict]:
    """
    Enrich cracked results with slot metadata.

    Label format: username_slotN
    We cannot know from the label alone if it is the real slot —
    that requires the HMAC derivation with the correct password.
    We mark is_real as None (unknown) — the security implication is that
    the attacker ALSO cannot know, which is the honey pool's purpose.

    For research analysis, if you have access to the HMAC salt + correct password,
    is_real can be computed separately (see analyse_crack_results()).
    """
    classified = []
    for item in cracked:
        label = item["label"]
        # Parse slot index from label
        m = re.search(r"_slot(\d+)$", label)
        slot_idx = int(m.group(1)) if m else None
        username = re.sub(r"_slot\d+$", "", label)

        classified.append({
            "username":         username,
            "slot_index":       slot_idx,
            "cracked_password": item["cracked_password"],
            "is_real":          None,   # cannot determine without HMAC derivation
            "label":            label,
        })
    return classified


def analyse_crack_results(classified: list[dict]) -> dict:
    """
    Fetch honey_salt from DB and compute is_real for each cracked entry.
    This is the RESEARCH/ANALYSIS path — requires DB access.
    """
    import sqlite3

    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    try:
        cur.execute("SELECT username, honey_salt, honey_hashes FROM users")
        user_rows = {row[0]: {"salt": row[1], "hashes": json.loads(row[2])} for row in cur.fetchall()}
    except Exception:
        conn.close()
        return {}
    conn.close()

    # Import derive function
    sys.path.insert(0, str(ROOT))
    from app.honey_encryptor import derive_honey_index

    for item in classified:
        uname = item["username"]
        if uname not in user_rows:
            continue
        info      = user_rows[uname]
        salt      = info["salt"]
        pool_size = len(info["hashes"])
        password  = item["cracked_password"]

        # Derive which slot this password maps to
        derived_idx = derive_honey_index(password, salt, pool_size)
        item["is_real"]          = (derived_idx == item["slot_index"])
        item["derived_slot_idx"] = derived_idx

    return classified


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5: Metrics
# ─────────────────────────────────────────────────────────────────────────────

def compute_metrics(
    classified:     list[dict],
    total_hashes:   int,
    elapsed_s:      float,
    format_name:    str,
    wordlist_size:  int,
    attack_type:    str,
) -> dict:
    """
    Compute and return the full metric set:
      - crack success rate (overall, real, decoy)
      - time to crack
      - honey pool effectiveness
    """
    total_cracked  = len(classified)
    real_cracked   = sum(1 for x in classified if x.get("is_real") is True)
    decoy_cracked  = sum(1 for x in classified if x.get("is_real") is False)
    unknown        = sum(1 for x in classified if x.get("is_real") is None)

    crack_rate_pct = round(total_cracked / total_hashes * 100, 2) if total_hashes else 0
    real_rate_pct  = round(real_cracked  / total_hashes * 100, 2) if total_hashes else 0
    hps            = round(wordlist_size / elapsed_s, 2)          if elapsed_s else 0

    return {
        "timestamp":      datetime.utcnow().isoformat(),
        "algorithm":      format_name,
        "attack_type":    attack_type,
        "wordlist_size":  wordlist_size,
        "total_hashes":   total_hashes,
        "total_cracked":  total_cracked,
        "real_cracked":   real_cracked,
        "decoy_cracked":  decoy_cracked,
        "unknown":        unknown,
        "crack_rate_pct": crack_rate_pct,
        "real_rate_pct":  real_rate_pct,
        "elapsed_s":      round(elapsed_s, 2),
        "hashes_per_sec": hps,
        "cracked_entries": classified,
    }


def save_metrics(metrics: dict, run_id: str):
    """Save full metrics to JSON and append summary row to CSV."""
    # JSON
    json_path = RESULTS_DIR / f"{run_id}_results.json"
    with open(json_path, "w") as f:
        json.dump(metrics, f, indent=2)

    # CSV (append)
    csv_path = RESULTS_DIR / "all_attack_results.csv"
    write_header = not csv_path.exists()
    with open(csv_path, "a", newline="") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow([
                "timestamp", "algorithm", "attack_type", "wordlist_size",
                "total_hashes", "total_cracked", "real_cracked", "decoy_cracked",
                "crack_rate_pct", "real_rate_pct", "elapsed_s", "hashes_per_sec",
            ])
        w.writerow([
            metrics["timestamp"], metrics["algorithm"], metrics["attack_type"],
            metrics["wordlist_size"], metrics["total_hashes"], metrics["total_cracked"],
            metrics["real_cracked"], metrics["decoy_cracked"],
            metrics["crack_rate_pct"], metrics["real_rate_pct"],
            metrics["elapsed_s"], metrics["hashes_per_sec"],
        ])

    print(f"\n[SAVED] JSON → {json_path}")
    print(f"[SAVED] CSV  → {csv_path}")
    return json_path


def print_summary(metrics: dict):
    print(f"\n{'='*58}")
    print(f"  LEAP JtR Attack Report — {metrics['algorithm'].upper()}")
    print(f"{'='*58}")
    print(f"  Attack type:       {metrics['attack_type']}")
    print(f"  Wordlist size:     {metrics['wordlist_size']:,} entries")
    print(f"  Total hashes:      {metrics['total_hashes']:,}")
    print(f"  Elapsed:           {metrics['elapsed_s']:.1f}s")
    print(f"  Speed:             {metrics['hashes_per_sec']:,.1f} H/s")
    print(f"  ─────────────────────────────────────────────────")
    print(f"  Total cracked:     {metrics['total_cracked']}  ({metrics['crack_rate_pct']}%)")
    print(f"  Real cracked:      {metrics['real_cracked']}  ({metrics['real_rate_pct']}%)")
    print(f"  Decoy cracked:     {metrics['decoy_cracked']}")
    print(f"  Unknown:           {metrics['unknown']}  (HMAC not resolved)")
    print(f"{'='*58}\n")

    if metrics["cracked_entries"]:
        print("  Cracked entries:")
        for e in metrics["cracked_entries"][:20]:
            real_str = {True: "REAL", False: "DECOY", None: "?"}[e.get("is_real")]
            print(f"    {e['label']:<30}  pw={e['cracked_password']!r:<20}  [{real_str}]")
    else:
        print("  No hashes cracked.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LEAP JtR Adversarial Attack Pipeline")
    parser.add_argument("--format",   default="argon2id",
                        help="Hash format: argon2id, bcrypt, sha256 (default: argon2id)")
    parser.add_argument("--wordlist", default=str(ROOT / "data" / "sample_10000.txt"),
                        help="Path to wordlist file")
    parser.add_argument("--max-time", type=int, default=120,
                        help="Max JtR runtime in seconds (default: 120)")
    parser.add_argument("--runs",     type=int, default=1,
                        help="Number of repeated runs (default: 1)")
    parser.add_argument("--rules",    action="store_true",
                        help="Enable JtR rule-based mangling")
    parser.add_argument("--export-only", action="store_true",
                        help="Only export hashes, do not run attack")
    args = parser.parse_args()

    john_bin  = find_john()
    print(f"[INFO] JtR binary: {john_bin}")

    wordlist  = Path(args.wordlist)
    if not wordlist.exists():
        print(f"[ERROR] Wordlist not found: {wordlist}")
        sys.exit(1)

    wordlist_size = sum(1 for _ in wordlist.open(encoding="utf-8", errors="ignore"))
    print(f"[INFO] Wordlist: {wordlist} ({wordlist_size:,} entries)")

    # Step 1: Export
    hash_file = export_hashes(args.format)
    total_hashes = sum(1 for line in hash_file.open() if line.strip())
    print(f"[INFO] Hash file: {hash_file} ({total_hashes} entries)")

    if args.export_only or total_hashes == 0:
        print("[INFO] Export-only mode. Done.")
        return

    all_metrics = []

    for run_id_n in range(1, args.runs + 1):
        run_tag    = f"{args.format}_run{run_id_n}_{int(time.time())}"
        attack_str = "wordlist+rules" if args.rules else "wordlist"
        print(f"\n[RUN {run_id_n}/{args.runs}] {attack_str}")

        # Step 2: Attack
        elapsed, rc, log_path = run_john_attack(
            hash_file   = hash_file,
            wordlist    = wordlist,
            format_name = args.format,
            john_bin    = john_bin,
            max_time    = args.max_time,
            use_rules   = args.rules,
            session_name = run_tag,
        )

        # Step 3: Extract
        cracked = extract_cracked(hash_file, args.format, john_bin)
        print(f"[SHOW] {len(cracked)} passwords cracked")

        # Step 4: Classify (resolve real vs decoy via HMAC)
        classified = classify_cracked(cracked)
        classified = analyse_crack_results(classified)

        # Step 5: Metrics
        metrics = compute_metrics(
            classified     = classified,
            total_hashes   = total_hashes,
            elapsed_s      = elapsed,
            format_name    = args.format,
            wordlist_size  = wordlist_size,
            attack_type    = attack_str,
        )
        save_metrics(metrics, run_tag)
        print_summary(metrics)
        all_metrics.append(metrics)

        if run_id_n < args.runs:
            time.sleep(2)   # brief pause between runs

    # Aggregate across runs if multiple
    if len(all_metrics) > 1:
        print("\n[AGGREGATE]")
        avg_crack = round(sum(m["crack_rate_pct"] for m in all_metrics) / len(all_metrics), 2)
        avg_real  = round(sum(m["real_rate_pct"]  for m in all_metrics) / len(all_metrics), 2)
        avg_time  = round(sum(m["elapsed_s"]       for m in all_metrics) / len(all_metrics), 2)
        print(f"  Avg crack rate:  {avg_crack}%")
        print(f"  Avg real cracked: {avg_real}%")
        print(f"  Avg elapsed:     {avg_time}s")


if __name__ == "__main__":
    main()