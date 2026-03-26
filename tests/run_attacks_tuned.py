#!/usr/bin/env python3
"""
Run John the Ripper attacks over slices with tqdm progress bars and per-run live elapsed progress.
Saves logs, show files and a summary CSV.

Usage:
    python3 run_attacks_tuned_with_progress.py
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
    "rockyou_top_200000.txt",
    "rockyou_top_500000.txt",
    "rockyou_top_1000000.txt" 
]

BCRYPT_SLICES = TARGET_SLICES
ARGON2_SLICES = TARGET_SLICES

FORMATS = [
    {"name": "bcrypt", "export": os.path.join(EXPORT_DIR, "bcrypt_hashes.txt")},
    {"name": "argon2i", "export": os.path.join(EXPORT_DIR, "argon2_hashes.txt")},
]

ATTACKS = ["wordlist", "wordlist+rules"]  # extendable

# per-format budgets (seconds)
MAX_RUN_TIME_BY_FORMAT = {"bcrypt": 1200, "argon2i": 120}
PROGRESS_EVERY = 2   # passed to John
REPEATS = 3

SUMMARY_CSV = os.path.join(OUT_LOG_DIR, "john_attack_summary_tuned.csv")


# === Helper: run a command and stream stdout to logfile while updating a tqdm timer ===
def run_john_with_elapsed_progress(cmd, logfile_path, max_run_time):
    """
    Launches cmd (list) as subprocess, writes stdout/stderr to logfile_path,
    and shows a tqdm progress bar for elapsed time up to max_run_time.
    Returns elapsed seconds and the process returncode.
    """
    t0 = time.time()
    # start process with stdout redirected to logfile
    # we still capture stdout so we can stream to file while process runs
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    # open logfile for writing
    with open(logfile_path, "w", encoding="utf-8") as lf:
        # tqdm progress bar for elapsed seconds
        with tqdm(total=max_run_time, desc=os.path.basename(logfile_path), unit="s", leave=False) as pbar:
            last_update = 0.0
            try:
                while True:
                    # Read any available line (non-blocking readline used; will block briefly)
                    line = proc.stdout.readline()
                    now = time.time()
                    elapsed = now - t0

                    # write any captured line to logfile
                    if line:
                        lf.write(line)
                        lf.flush()

                    # update progress bar every second
                    delta = int(elapsed) - int(last_update)
                    if delta > 0:
                        pbar.update(delta)
                        last_update = elapsed

                    # if process finished, break after draining remaining output
                    if proc.poll() is not None:
                        # drain any remaining lines
                        for rem in proc.stdout:
                            lf.write(rem)
                            lf.flush()
                        break

                    # if elapsed exceeds max_run_time, terminate process
                    if elapsed >= max_run_time:
                        try:
                            proc.terminate()
                        except Exception:
                            pass
                        # give it a moment to terminate
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            try:
                                proc.kill()
                            except Exception:
                                pass
                        break

                    # short sleep to avoid busy loop
                    time.sleep(0.1)

            except KeyboardInterrupt:
                # if user interrupts, try to terminate gracefully and re-raise
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

    # Top-level algorithm loop (use tqdm)
    for fmt in tqdm(FORMATS, desc="Algorithms", position=0):
        fmt_name = fmt["name"]
        export_file = fmt["export"]

        if not os.path.exists(export_file):
            print(f"[WARN] Missing export file for {fmt_name} -> {export_file}. Skipping.")
            continue

        # select slices
        slices = BCRYPT_SLICES if fmt_name == "bcrypt" else ARGON2_SLICES

        # slice-level progress
        for slice_fname in tqdm(slices, desc=f"{fmt_name} slices", position=1, leave=False):
            slice_path = os.path.join(SLICES_DIR, slice_fname)
            if not os.path.exists(slice_path):
                print(f"[WARN] Missing slice file {slice_path}. Skipping.")
                continue

            # attack-level progress
            for attack in tqdm(ATTACKS, desc="Attack type", position=2, leave=False):

                # runs (repeats) progress
                for runid in tqdm(range(1, REPEATS + 1), desc=f"Runs ({attack})", position=3, leave=False):
                    prefix = f"{fmt_name}_{slice_fname.replace('.txt','')}_{attack}_run{runid}"
                    logpath = os.path.join(OUT_LOG_DIR, prefix + ".log")
                    showpath = os.path.join(OUT_LOG_DIR, prefix + "_show.txt")

                    # build john command
                    max_time = int(MAX_RUN_TIME_BY_FORMAT.get(fmt_name, 300))
                    cmd = [
                        JOHN_BIN,
                        f"--wordlist={slice_path}",
                        f"--format={fmt_name}",
                        f"--max-run-time={max_time}",
                        f"--progress-every={PROGRESS_EVERY}",
                        f"--session={prefix}",
                        export_file,
                    ]
                    if attack == "wordlist+rules":
                        # insert --rules after --format argument position to keep order readable
                        cmd.insert(3, "--rules")

                    # Informational print (summary)
                    print(f"\n[RUN] alg={fmt_name} slice={slice_fname} attack={attack} run={runid} max_time={max_time}s")

                    # Run John with elapsed tqdm progress (writes to logpath)
                    elapsed, rc = run_john_with_elapsed_progress(cmd, logpath, max_time)

                    # After run, save show output
                    with open(showpath, "w", encoding="utf-8") as out:
                        subprocess.run([JOHN_BIN, "--show", export_file], stdout=out, stderr=subprocess.DEVNULL, text=True)

                    # Count only real username:plaintext lines (ignore John's summary lines)
                    cracked_count = 0
                    with open(showpath, "r", encoding="utf-8", errors="ignore") as sf:
                        for line in sf:
                            if ":" in line:
                                parts = line.strip().split(":")
                                if len(parts) >= 2 and parts[1].strip() and "password hashes cracked" not in line.lower():
                                    cracked_count += 1

                    # Append to results
                    rows.append([
                        fmt_name, slice_fname, attack, runid,
                        elapsed, cracked_count, logpath, showpath
                    ])

                    # small pause between runs
                    time.sleep(1)

    # write summary CSV
    with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "slice", "attack", "runid", "elapsed_s", "cracked_count", "log", "show"])
        w.writerows(rows)

    print("\nAll done. Summary written to:", SUMMARY_CSV)


if __name__ == "__main__":
    main()
