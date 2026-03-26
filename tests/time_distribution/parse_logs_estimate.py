#!/usr/bin/env python3
import os, glob, csv, re
LOG_DIR = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/time_distribution"
OUT_EST = os.path.join(LOG_DIR, "time_to_crack_per_password_estimated.csv")

# For each run: read log, read show, get cracked list order from show,
# estimate times by distributing cracked events across log duration proportionally using john progress lines (if any),
# else just use uniform spacing across elapsed run.

def parse_progress_times(logfile):
    # try to extract the run start and end timestamps and a few progress timestamps
    times = []
    ts_rx = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
    with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = ts_rx.search(line)
            if m:
                times.append(m.group(1))
    return times

rows = []
for showfile in glob.glob(os.path.join(LOG_DIR, "*_show.txt")):
    base = os.path.basename(showfile).replace("_show.txt","")
    # load cracked list order from show file
    cracked = []
    with open(showfile, "r", encoding="utf-8", errors="ignore") as sf:
        for line in sf:
            if ":" in line:
                parts = line.strip().split(":")
                if len(parts) >= 2 and parts[1].strip():
                    cracked.append(parts[1].strip())
    if not cracked:
        continue
    logpath = os.path.join(LOG_DIR, f"{base}.log")
    if not os.path.exists(logpath):
        # fallback: set timestamps blank
        for pwd in cracked:
            rows.append([base, pwd, ""])
        continue

    # try to get a first and last timestamp
    times = parse_progress_times(logpath)
    if len(times) >= 2:
        start = times[0]
        end = times[-1]
        # distribute times evenly between start and end
        from datetime import datetime, timedelta
        fmt = "%Y-%m-%d %H:%M:%S"
        try:
            ts0 = datetime.strptime(start, fmt)
            ts1 = datetime.strptime(end, fmt)
            total_secs = (ts1 - ts0).total_seconds()
            n = len(cracked)
            for i,pwd in enumerate(cracked):
                t = ts0 + timedelta(seconds = (i / max(1,n-1)) * total_secs)
                rows.append([base, pwd, t.strftime(fmt)])
        except Exception:
            # fallback blank
            for pwd in cracked:
                rows.append([base, pwd, ""])
    else:
        # no timestamps in log - estimate using uniform seconds based on file modify time
        import os, time
        mtime = os.path.getmtime(logpath)
        # assume run duration equal to file size / 10k as heuristic (very rough)
        size = os.path.getsize(logpath)
        est_duration = max(10, size // 10000)  # seconds heuristic
        from datetime import datetime, timedelta
        ts0 = datetime.fromtimestamp(mtime - est_duration)
        n = len(cracked)
        for i,pwd in enumerate(cracked):
            t = ts0 + timedelta(seconds = (i / max(1,n-1)) * est_duration)
            rows.append([base, pwd, t.strftime("%Y-%m-%d %H:%M:%S")])

# write csv
with open(OUT_EST, "w", newline="", encoding="utf-8") as out:
    import csv
    w = csv.writer(out)
    w.writerow(["run_prefix","password","estimated_timestamp"])
    w.writerows(rows)

print("Estimated parse finished. Rows:", len(rows))
print("Saved ->", OUT_EST)
