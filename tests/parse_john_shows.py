# tests/parse_john_shows.py
import os, csv, glob
SHOW_DIR = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs"
OUT = os.path.join(SHOW_DIR, "john_manual_summary.csv")

rows = []
for showfile in glob.glob(os.path.join(SHOW_DIR, "*_show_*.txt")):
    # count non-empty lines
    with open(showfile, "r", encoding="utf-8", errors="ignore") as f:
        count = sum(1 for line in f if line.strip())
    basename = os.path.basename(showfile)
    parts = basename.split("_")
    # crude parse: algorithm_slice_show_runX.txt
    rows.append([basename, count, showfile])

with open(OUT, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["showfile","cracked_count","path"])
    w.writerows(rows)

print("Parsed shows ->", OUT)
