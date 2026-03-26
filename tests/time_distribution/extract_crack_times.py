import re
import os
from datetime import datetime

RAW_LOG = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/time_distribution/bcrypt_dist_raw.log"
SHOW_FILE = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/time_distribution/bcrypt_dist_show.txt"
OUT_CSV = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/time_distribution/bcrypt_time_distribution.csv"

# Load cracked passwords from john --show output
cracked_passwords = set()
with open(SHOW_FILE, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        if ":" in line:
            parts = line.strip().split(":")
            if len(parts) >= 2 and parts[1].strip():
                cracked_passwords.add(parts[1].strip())

print(f"Loaded {len(cracked_passwords)} cracked passwords from show file.")

# Parse timestamps from raw John log
crack_times = []

timestamp_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?Cracked: (.+)$")

with open(RAW_LOG, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        match = timestamp_pattern.search(line)
        if match:
            timestamp, pwd = match.groups()
            pwd = pwd.strip()
            if pwd in cracked_passwords:
                crack_times.append((pwd, timestamp))

# Save as CSV
with open(OUT_CSV, "w", encoding="utf-8") as f:
    f.write("password,crack_time\n")
    for pwd, ts in crack_times:
        f.write(f"{pwd},{ts}\n")

print(f"Saved crack time CSV → {OUT_CSV}")
