#!/usr/bin/env python3
import re, os, csv, glob
LOG_DIR = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/time_distribution"
OUT_DIR = LOG_DIR
OUT_COMBINED = os.path.join(OUT_DIR, "time_to_crack_per_password_exact.csv")

# Regexes to try (common John output patterns)
# 1) timestamp + Cracked: <password>
r1 = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*Cracked: (?P<pwd>\S+)")
# 2) timestamp + guessed: <password>
r2 = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*guessed: (?P<pwd>\S+)")
# 3) some john builds log just print plaintext alone, try to capture 'plaintext' patterns with timestamp prior
r3 = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*(?P<pwd>[^\s:]{3,})")  # last-resort, filtered by showfile

# Helper to load cracked set from show file
def load_show_set(show_path):
    s = set()
    if not os.path.exists(show_path):
        return s
    with open(show_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if ":" in line:
                parts = line.strip().split(":")
                if len(parts) >= 2 and parts[1].strip():
                    s.add(parts[1].strip())
    return s

rows = []
# find pairs: *.log and *_show.txt (or <prefix>_show.txt)
log_files = glob.glob(os.path.join(LOG_DIR, "*.log"))
for log in log_files:
    base = os.path.basename(log).rsplit(".log", 1)[0]
    # try show variants
    show_candidates = [
        os.path.join(LOG_DIR, f"{base}_show.txt"),
        os.path.join(LOG_DIR, f"{base}_show.txt"),
    ]
    show_path = None
    for sc in show_candidates:
        if os.path.exists(sc):
            show_path = sc
            break
    # fallback: try any show file that starts with base
    if not show_path:
        for f in glob.glob(os.path.join(LOG_DIR, f"{base}*show*.txt")):
            show_path = f
            break

    cracked_set = load_show_set(show_path) if show_path else set()
    if not cracked_set:
        # nothing cracked (skip)
        continue

    # parse log
    with open(log, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            for rx in (r1, r2):
                m = rx.search(line)
                if m:
                    pwd = m.group("pwd").strip()
                    ts = m.group("ts").strip()
                    if pwd in cracked_set:
                        rows.append([base, pwd, ts, log, show_path])
                        # remove from set to avoid duplicates
                        cracked_set.discard(pwd)
                    break

# Write CSV
with open(OUT_COMBINED, "w", newline="", encoding="utf-8") as out:
    w = csv.writer(out)
    w.writerow(["run_prefix","password","timestamp","logfile","showfile"])
    w.writerows(rows)

print("Exact parse finished. Rows:", len(rows))
print("Saved ->", OUT_COMBINED)
