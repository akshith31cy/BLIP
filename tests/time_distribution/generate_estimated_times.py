#!/usr/bin/env python3
import csv, os, datetime

SUMMARY = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/time_distribution/time_to_crack_summary.csv"
OUT = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/time_distribution/time_to_crack_per_password_estimated.csv"

rows_out = []

def read_show_file(showpath):
    """Return ordered list of cracked passwords from show file"""
    if not os.path.exists(showpath):
        return []
    pwds = []
    with open(showpath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # typical john --show lines: username:plaintext:... or username:plaintext
            parts = line.split(":")
            if len(parts) >= 2:
                pwd = parts[1].strip()
                if pwd:
                    pwds.append(pwd)
    return pwds

with open(SUMMARY, "r", encoding="utf-8") as csvf:
    r = csv.DictReader(csvf)
    for rec in r:
        algo = rec.get("algorithm")
        slice_file = rec.get("slice_file")
        runid = rec.get("runid")
        try:
            elapsed = float(rec.get("elapsed_s") or 0.0)
        except:
            elapsed = 0.0
        logpath = rec.get("logfile")
        showpath = rec.get("showfile")

        # load cracked list (ordered)
        cracked = read_show_file(showpath)
        if not cracked:
            # no cracked, continue
            continue

        # determine logfile modification time (use end time)
        if logpath and os.path.exists(logpath):
            mtime = os.path.getmtime(logpath)
            end_time = datetime.datetime.fromtimestamp(mtime)
        else:
            # fallback: use now as end time
            end_time = datetime.datetime.now()

        # compute start time ≈ end_time - elapsed
        start_time = end_time - datetime.timedelta(seconds=elapsed)

        # distribute cracked passwords across [start_time, end_time]
        n = len(cracked)
        for i, pwd in enumerate(cracked):
            if n == 1:
                ts = end_time  # single cracked -> approximate at end
            else:
                frac = i / (n - 1)
                ts = start_time + datetime.timedelta(seconds=frac * elapsed)
            rows_out.append({
                "run_prefix": f"{algo}_{slice_file}_run{runid}",
                "password": pwd,
                "estimated_timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "algorithm": algo,
                "slice_file": slice_file,
                "runid": runid
            })

# write CSV
with open(OUT, "w", newline="", encoding="utf-8") as wf:
    w = csv.DictWriter(wf, fieldnames=["run_prefix","algorithm","slice_file","runid","password","estimated_timestamp"])
    w.writeheader()
    for r in rows_out:
        w.writerow(r)

print("Wrote estimated per-password times to:", OUT)
print("Rows:", len(rows_out))
