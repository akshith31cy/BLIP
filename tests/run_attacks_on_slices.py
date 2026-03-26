import os
import subprocess
import time
from pathlib import Path
from tqdm import tqdm   # NEW

JOHN = os.path.expanduser("~/john-jumbo/run/john")
SLICES_DIR = "/mnt/c/Users/Akshith/wordlists/slices"
EXPORT_DIR = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_exports"
LOG_DIR = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs"

os.makedirs(LOG_DIR, exist_ok=True)

slices = [
    "rockyou_top_10000.txt",
    "rockyou_top_50000.txt",
    "rockyou_top_100000.txt",
    "rockyou_top_200000.txt",
    "rockyou_top_500000.txt",
    "rockyou_top_1000000.txt"
]

formats = [
    {"name":"bcrypt", "file": os.path.join(EXPORT_DIR, "bcrypt_hashes.txt")},
    {"name":"argon2i", "file": os.path.join(EXPORT_DIR, "argon2_hashes.txt")}
]

wordlist_template = os.path.join(SLICES_DIR, "{}")
max_run_time = 600
runs_per_setting = 1

def run_command(cmd, logfile):
    t0 = time.time()
    with open(logfile, "w", encoding="utf-8") as out:
        proc = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT, text=True)
    return time.time() - t0, proc.returncode

rows = []

# ---- CALCULATE TOTAL EXPERIMENTS FOR PROGRESS BAR ----
total_jobs = len(slices) * len(formats) * runs_per_setting * 2  # wordlist + rules

# ---- PROGRESS BAR ----
pbar = tqdm(total=total_jobs, desc="Running attacks", ncols=100)

for slice_fname in slices:
    wordlist = wordlist_template.format(slice_fname)
    if not os.path.exists(wordlist):
        print("Skipping missing slice:", wordlist)
        continue

    for fmt in formats:
        if not os.path.exists(fmt["file"]):
            print("Skipping missing hash file for", fmt["name"])
            continue

        for runid in range(1, runs_per_setting+1):

            # ---- WORDLIST ATTACK ----
            log_prefix = f"{fmt['name']}_{slice_fname.replace('.txt','')}_run{runid}"
            logpath = os.path.join(LOG_DIR, f"{log_prefix}_wordlist.log")

            cmd = [JOHN, f"--wordlist={wordlist}", f"--format={fmt['name']}",
                   f"--max-run-time={max_run_time}", fmt["file"]]

            print("RUN:", " ".join(cmd))
            elapsed, rc = run_command(cmd, logpath)

            # save --show
            showfile = os.path.join(LOG_DIR, f"{log_prefix}_wordlist_show_run{runid}.txt")
            subprocess.run([JOHN, "--show", fmt["file"]], stdout=open(showfile,"w"))

            cracked = sum(1 for _ in open(showfile, "r", errors="ignore"))
            rows.append([fmt["name"], slice_fname, "wordlist", runid, elapsed, cracked, logpath, showfile])

            pbar.update(1)  # UPDATE PROGRESS BAR

            # ---- WORDLIST + RULES ----
            logpath2 = os.path.join(LOG_DIR, f"{log_prefix}_rules.log")
            cmd2 = [JOHN, f"--wordlist={wordlist}", "--rules", f"--format={fmt['name']}",
                    f"--max-run-time={max_run_time}", fmt["file"]]

            elapsed2, rc2 = run_command(cmd2, logpath2)

            showfile2 = os.path.join(LOG_DIR, f"{log_prefix}_rules_show_run{runid}.txt")
            subprocess.run([JOHN, "--show", fmt["file"]], stdout=open(showfile2,"w"))

            cracked2 = sum(1 for _ in open(showfile2, "r", errors="ignore"))
            rows.append([fmt["name"], slice_fname, "wordlist+rules", runid, elapsed2, cracked2, logpath2, showfile2])

            pbar.update(1)  # UPDATE PROGRESS BAR

pbar.close()

# ---- SUMMARY CSV ----
import csv
csv_path = os.path.join(LOG_DIR, "john_attack_summary.csv")
with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["algorithm","slice","attack","runid","elapsed_s","cracked_count","log","show"])
    writer.writerows(rows)

print("Done. Summary ->", csv_path)
