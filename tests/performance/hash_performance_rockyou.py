#!/usr/bin/env python3
import os, time, random, csv
import hashlib
import bcrypt
from argon2 import PasswordHasher
import psutil

PROJECT = "/mnt/c/Users/Akshith/leakage_resilient_password_storage"

# ----------------------------------------
# *** NEW ROCKYOU DATASET DIRECTORY ***
# ----------------------------------------
SLICES_DIR = os.path.join(PROJECT, "data_rockyou")

OUT_CSV = os.path.join(
    PROJECT,
    "tests",
    "hash_performance_results_rockyou.csv"
)

# ----------------------------------------
# *** RockYou slices you created ***
# ----------------------------------------
SLICES = [
    "rockyou_top_10000.txt",
    "rockyou_top_50000.txt",
    "rockyou_top_100000.txt",
    "rockyou_top_200000.txt",
    "rockyou_top_500000.txt",
    "rockyou_top_1000000.txt"
]

# Performance settings
MAX_HASHES_PER_SLICE = 200
REPEATS = 3
BCRYPT_ROUNDS = 10    # safe + fast enough

# Argon2 settings
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 65536  # 64MB
ARGON2_PARALLELISM = 1

ph = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM
)

# ----------------------------------------
# Helper functions
# ----------------------------------------

def read_sample(path, n):
    if not os.path.exists(path):
        return []

    with open(path, "rb") as f:
        lines = [l.decode(errors="ignore").strip() for l in f if l.strip()]

    if not lines:
        return []

    return random.sample(lines, min(len(lines), n))

def snapshot():
    cpu = psutil.cpu_percent(interval=0.3)
    mem = psutil.virtual_memory()
    rss = psutil.Process().memory_info().rss / (1024*1024)
    return dict(cpu=cpu, mem_pct=mem.percent, rss_mb=round(rss,2))

def bench_sha256(pws):
    t0 = time.time()
    for p in pws:
        hashlib.sha256(p.encode()).hexdigest()
    return time.time() - t0

def bench_bcrypt(pws):
    t0 = time.time()
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    for p in pws:
        bcrypt.hashpw(p.encode(), salt)
    return time.time() - t0

def bench_argon2(pws):
    t0 = time.time()
    for p in pws:
        ph.hash(p)
    return time.time() - t0

def run_for_slice(slice_file):
    path = os.path.join(SLICES_DIR, slice_file)
    passwords = read_sample(path, MAX_HASHES_PER_SLICE)
    rows = []

    if not passwords:
        print("[WARN] Missing/empty slice:", slice_file)
        return rows

    for algo in ["sha256", "bcrypt", "argon2"]:
        for rep in range(1, REPEATS+1):

            sample = random.sample(passwords, len(passwords))
            before = snapshot()

            if algo == "sha256":
                elapsed = bench_sha256(sample)
            elif algo == "bcrypt":
                elapsed = bench_bcrypt(sample)
            else:
                elapsed = bench_argon2(sample)

            after = snapshot()

            avg = elapsed / len(sample)
            throughput = len(sample) / elapsed

            rows.append({
                "slice": slice_file,
                "slice_size": int(''.join(filter(str.isdigit, slice_file))),
                "algo": algo,
                "repeat": rep,
                "n_hashes": len(sample),
                "elapsed_s": round(elapsed,4),
                "avg_s_per_hash": round(avg,6),
                "hashes_per_sec": round(throughput,2),
                "bcrypt_rounds": BCRYPT_ROUNDS if algo=="bcrypt" else "",
                "argon2_time_cost": ARGON2_TIME_COST if algo=="argon2" else "",
                "cpu_before": before["cpu"],
                "cpu_after": after["cpu"],
                "mem_before_pct": before["mem_pct"],
                "mem_after_pct": after["mem_pct"],
                "rss_before_mb": before["rss_mb"],
                "rss_after_mb": after["rss_mb"]
            })

            print(f"[OK] {slice_file} | {algo} | rep {rep}: {elapsed:.2f}s")
            time.sleep(0.2)

    return rows

# ----------------------------------------
# Main
# ----------------------------------------
def main():
    all_rows = []
    random.seed(42)

    for s in SLICES:
        print("=== Running slice:", s)
        out = run_for_slice(s)
        all_rows.extend(out)

    if all_rows:
        keys = list(all_rows[0].keys())
        with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(all_rows)

        print("\nSaved results →", OUT_CSV)
    else:
        print("No results generated.")

if __name__ == "__main__":
    main()
