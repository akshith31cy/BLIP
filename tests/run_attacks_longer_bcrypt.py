#!/usr/bin/env python3
"""
Run John the Ripper attacks over slices with tqdm progress bars and per-run live elapsed progress.
This variant increases bcrypt budget to 3600s (1 hour) to try to obtain cracked results.

Save as:
  tests/run_attacks_longer_bcrypt.py

Run:
  python3 tests/run_attacks_longer_bcrypt.py
"""

import os
import subprocess
import time
import csv
from pathlib import Path
from tqdm import tqdm

# === Configuration ===
JOHN_BIN = os.path.expanduser("~/john-jumbo/run/john")
SLICES_DIR = "/mnt/c/Users/Akshith/wordlists/slices"
EXPORT_DIR = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_exports"
OUT_LOG_DIR = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs"
os.makedirs(OUT_LOG_DIR, exist_ok=True)

# Slices to run (as requested)
TARGET_SLICES = [
    "rockyou_top_10000.txt",
    "rockyou_top_50000.txt",
    "rockyou_top_100000.txt",
    "rockyou_top_200000.txt"
]

BCRYPT_SLICES = TARGET_SLICES
ARGON2_SLICES = TARGET_SLICES

FORMATS = [
    {"name": "bcrypt", "export": os.path.join(EXPORT_DIR, "bcrypt_hashes.txt")},
    {"name": "argon2i", "export": os.path.join(EXPORT_DIR, "argon2_hashes.txt")},
]

ATTACKS = ["wordlist", "wordlist+rules"]  # extendable

# UPDATED per-format budgets (seconds) - increase bcrypt to 3600s (1 hour)
MAX_RUN_TIME_BY_FORMAT = {"bcrypt": 3600, "argon2i": 300}
PROGRESS_EVERY = 2   # passed to John
REPEATS = 3

SUMMARY_CSV = os.path.join(OUT_LOG_DIR, "john_attack_summary_longer_bcrypt.csv")


# === Helper: run a command and stream stdout to logfile while updating a tqdm timer ===
def run_john_with_elapsed_progress(cmd, logfile_path, max_run_time):
    """
    Launches cmd (list) as subprocess, writes stdout/stderr to logfile_path,
    and shows a tqdm progress bar for elapsed time up to max_run_time.
    Returns elapsed seconds and the process returncode.
    """
    t0 = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    with open(logfile_path, "w", encoding="utf-8") as lf:
        with tqdm(total=max_run_time, desc=os.path.basename(logfile_path), unit="s", leave=False) as pbar:
            last_update = 0.0
            try:
                while True:
                    line = proc.stdout.readline()
                    now = time.time()
                    elapsed = now - t0

                    if line:
                        lf.write(line)
                        lf.flush()

                    delta = int(elapsed) - int(last_update)
                    if delta > 0:
                        pbar.update(delta)
                        last_update = elapsed

                    if proc.poll() is not None:
                        for rem in proc.stdout:
                            lf.write(rem)
                            lf.flush()
                        break

                    if elapsed >= max_run_time:
                        try:
                            proc.terminate()
                        except Exception:
                            pass
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            try:
                                proc.kill()
                            except Exception:
                                pass
                        break

                    time.sleep(0.1)

            except KeyboardInterrupt:
                try:
                    proc.terminate()
                except Exception:
                    pass
                raise

    elapsed_final = time.time() - t0
    return elapsed_final, proc.returncode


# === Main runner ===
def main():
    rows = []

    for fmt in tqdm(FORMATS, desc="Algorithms", position=0):
        fmt_name = fmt["name"]
        export_file = fmt["export"]

        if not os.path.exists(export_file):
            print(f"[WARN] Missing export file for {fmt_name} -> {export_file}. Skipping.")
            continue

        slices = BCRYPT_SLICES if fmt_name == "bcrypt" else ARGON2_SLICES

        for slice_fname in tqdm(slices, desc=f"{fmt_name} slices", position=1, leave=False):
            slice_path = os.path.join(SLICES_DIR, slice_fname)
            if not os.path.exists(slice_path):
                print(f"[WARN] Missing slice file {slice_path}. Skipping.")
                continue

            for attack in tqdm(ATTACKS, desc="Attack type", position=2, leave=False):
                for runid in tqdm(range(1, REPEATS + 1), desc=f"Runs ({attack})", position=3, leave=False):
                    prefix = f"{fmt_name}_{slice_fname.replace('.txt','')}_{attack}_run{runid}"
                    # sanitize prefix for filenames (avoid '+' char in filename)
                    prefix_safe = prefix.replace("+", "plus")
                    logpath = os.path.join(OUT_LOG_DIR, prefix_safe + ".log")
                    showpath = os.path.join(OUT_LOG_DIR, prefix_safe + "_show.txt")

                    max_time = int(MAX_RUN_TIME_BY_FORMAT.get(fmt_name, 300))
                    cmd = [
                        JOHN_BIN,
                        f"--wordlist={slice_path}",
                        f"--format={fmt_name}",
                        f"--max-run-time={max_time}",
                        f"--progress-every={PROGRESS_EVERY}",
                        f"--session={prefix_safe}",
                        export_file,
                    ]
                    if attack == "wordlist+rules":
                        cmd.insert(3, "--rules")

                    print(f"\n[RUN] alg={fmt_name} slice={slice_fname} attack={attack} run={runid} max_time={max_time}s")

                    elapsed, rc = run_john_with_elapsed_progress(cmd, logpath, max_time)

                    with open(showpath, "w", encoding="utf-8") as out:
                        subprocess.run([JOHN_BIN, "--show", export_file], stdout=out, stderr=subprocess.DEVNULL, text=True)

                    cracked_count = 0
                    with open(showpath, "r", encoding="utf-8", errors="ignore") as sf:
                        for line in sf:
                            if ":" in line:
                                parts = line.strip().split(":")
                                if len(parts) >= 2 and parts[1].strip() and "password hashes cracked" not in line.lower():
                                    cracked_count += 1

                    rows.append([
                        fmt_name, slice_fname, attack, runid,
                        elapsed, cracked_count, logpath, showpath
                    ])

                    time.sleep(1)

    with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "slice", "attack", "runid", "elapsed_s", "cracked_count", "log", "show"])
        w.writerows(rows)

    print("\nAll done. Summary written to:", SUMMARY_CSV)


if __name__ == "__main__":
    main()
