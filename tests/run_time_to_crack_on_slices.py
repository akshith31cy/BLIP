#!/usr/bin/env python3
"""
Run bounded John runs on every slice, show live progress bar and stream John's stdout to logs.
"""

import os
import subprocess
import time
import csv
from pathlib import Path
from tqdm import tqdm  # progress bar

# Configuration - update if needed
JOHN_BIN = os.path.expanduser("~/john-jumbo/run/john")
SLICES_DIR = "/mnt/c/Users/Akshith/wordlists/slices"
EXPORT_DIR = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_exports"
OUT_LOG_DIR = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/time_distribution"
os.makedirs(OUT_LOG_DIR, exist_ok=True)

slice_files = [
    "rockyou_top_10000.txt",
    "rockyou_top_50000.txt",
    "rockyou_top_100000.txt",
    "rockyou_top_200000.txt",
    "rockyou_top_500000.txt",
    "rockyou_top_1000000.txt"
]

FORMATS = [
    {"name": "bcrypt",  "export": os.path.join(EXPORT_DIR, "bcrypt_hashes.txt")},
    {"name": "argon2i", "export": os.path.join(EXPORT_DIR, "argon2_hashes.txt")},
]

MAX_RUN_TIME = 600    # seconds per run (adjust)
PROGRESS_EVERY = 2    # john progress interval (seconds) - passed to John
REPEATS = 1
SUMMARY_CSV = os.path.join(OUT_LOG_DIR, "time_to_crack_summary.csv")

def run_cmd_with_progress(cmd, logfile_path, max_run_time):
    """
    Run the command, stream stdout -> logfile and console, show a tqdm progress bar for elapsed time.
    Returns elapsed seconds and process returncode.
    """
    t0 = time.time()
    # open logfile for writing
    with open(logfile_path, "w", encoding="utf-8") as lf:
        # start process with stdout pipe so we can stream lines
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)

        # create tqdm progress bar for time (seconds)
        with tqdm(total=max_run_time, unit="s", desc=os.path.basename(logfile_path), leave=True) as pbar:
            last_update = 0.0
            while True:
                # non-blocking read line
                line = proc.stdout.readline()
                now = time.time()
                elapsed = now - t0

                # If we captured a line, write to logfile and print to console
                if line:
                    lf.write(line)
                    lf.flush()
                    # also print John's line so user sees it live
                    print(line, end="")  # John's own progress output

                # update progress bar every 0.3s or if needed
                # compute progress delta and update pbar
                delta = int(elapsed) - int(last_update)
                if delta > 0:
                    pbar.update(delta)
                    last_update = elapsed

                # check if process finished
                if proc.poll() is not None:
                    # drain remaining lines
                    for rem in proc.stdout:
                        lf.write(rem)
                        lf.flush()
                        print(rem, end="")
                    break

                # check if we've hit max run time
                if elapsed >= max_run_time:
                    # try to terminate gracefully
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    # wait short while
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                    break

                # small sleep to avoid busy loop
                time.sleep(0.1)

            # ensure progress bar reaches end if process ran full time
            final_elapsed = time.time() - t0
            if final_elapsed < max_run_time:
                pbar.update(int(max_run_time - pbar.n)) if False else None  # keep as-is; we update above
    return final_elapsed, proc.returncode

def run_one(slice_path, fmt, export_file, runid):
    slice_base = os.path.basename(slice_path).replace(".txt", "")
    prefix = f"{fmt}_{slice_base}_run{runid}"
    logpath = os.path.join(OUT_LOG_DIR, f"{prefix}.log")
    showpath = os.path.join(OUT_LOG_DIR, f"{prefix}_show.txt")

    cmd = [
        JOHN_BIN,
        f"--wordlist={slice_path}",
        f"--format={fmt}",
        f"--max-run-time={MAX_RUN_TIME}",
        f"--progress-every={PROGRESS_EVERY}",
        f"--session={prefix}",
        export_file
    ]

    print("\n== RUN START ==", "format:", fmt, "slice:", slice_base, "run:", runid)
    elapsed, rc = run_cmd_with_progress(cmd, logpath, MAX_RUN_TIME)
    print(f"\nRun finished in {elapsed:.1f}s (rc={rc}), saving show to {showpath}")

    # produce show file
    with open(showpath, "w", encoding="utf-8") as out:
        subprocess.run([JOHN_BIN, "--show", export_file], stdout=out, stderr=subprocess.DEVNULL, text=True)

    cracked_count = 0
    with open(showpath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.strip():
                cracked_count += 1

    return logpath, showpath, elapsed, cracked_count

def main():
    rows = []
    for slice_fname in slice_files:
        slice_path = os.path.join(SLICES_DIR, slice_fname)
        if not os.path.exists(slice_path):
            print("Skipping missing slice:", slice_path)
            continue

        for fmt in FORMATS:
            export_file = fmt["export"]
            if not os.path.exists(export_file):
                print("Skipping missing export for format:", fmt["name"], export_file)
                continue

            for runid in range(1, REPEATS + 1):
                logpath, showpath, elapsed, cracked = run_one(slice_path, fmt["name"], export_file, runid)
                rows.append([fmt["name"], slice_fname, runid, elapsed, cracked, logpath, showpath])
                time.sleep(1)

    with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "slice_file", "runid", "elapsed_s", "cracked_count", "logfile", "showfile"])
        w.writerows(rows)
    print("All done. Summary:", SUMMARY_CSV)

if __name__ == "__main__":
    main()
