import time
import psutil
import os
import csv
import hashlib
import bcrypt
from argon2 import PasswordHasher
from tqdm import tqdm

# Optimized Argon2 parameters (FAST but still realistic)
ph = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=2)

# Hashing functions
def hash_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_bcrypt(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()

def hash_argon2(password):
    return ph.hash(password)

# Monitor CPU & Memory
def monitor():
    p = psutil.Process(os.getpid())
    return p.cpu_percent(interval=0.05), p.memory_info().rss / (1024 * 1024)

# Core test
def run_test(passwords, algo_name, func):
    cpu_samples, mem_samples = [], []
    start = time.perf_counter()

    for pwd in tqdm(passwords, desc=f"{algo_name} ({len(passwords)} passwords)"):
        func(pwd)
        cpu, mem = monitor()
        cpu_samples.append(cpu)
        mem_samples.append(mem)

    end = time.perf_counter()

    return {
        "algorithm": algo_name,
        "dataset_size": len(passwords),
        "total_time_s": end - start,
        "avg_cpu_percent": sum(cpu_samples) / len(cpu_samples),
        "peak_cpu_percent": max(cpu_samples),
        "avg_memory_mb": sum(mem_samples) / len(mem_samples),
        "peak_memory_mb": max(mem_samples),
    }

# Load passwords
def load_passwords(path, limit):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read().splitlines()[:limit]

if __name__ == "__main__":
    # FAST dataset sizes
    DATASET_SIZES = [10000, 50000, 100000, 200000]

    WORDLIST = "/mnt/c/Users/Akshith/wordlists/rockyou.txt"

    OUT_FILE = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs/resource_usage_results.csv"

    # Ensure output directory exists
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)

    # Create CSV & Write Header
    csv_exists = os.path.exists(OUT_FILE)
    f = open(OUT_FILE, "a", newline="")
    writer = csv.writer(f)

    if not csv_exists:
        writer.writerow([
            "algorithm", "dataset_size", "total_time_s",
            "avg_cpu_percent", "peak_cpu_percent",
            "avg_memory_mb", "peak_memory_mb"
        ])

    print("\n🚀 Running Resource Usage Benchmark\n")

    for size in DATASET_SIZES:
        print(f"\nLoading {size} passwords...")
        pwds = load_passwords(WORDLIST, size)

        # Run all three algorithms
        for algo, func in [
            ("SHA256", hash_sha256),
            ("bcrypt", hash_bcrypt),
            ("Argon2", hash_argon2)
        ]:
            print(f"\nRunning {algo} on {size} passwords...\n")
            result = run_test(pwds, algo, func)

            # Save incremental results
            writer.writerow([
                result["algorithm"],
                result["dataset_size"],
                result["total_time_s"],
                result["avg_cpu_percent"],
                result["peak_cpu_percent"],
                result["avg_memory_mb"],
                result["peak_memory_mb"],
            ])
            f.flush()  # ensure safe writing even if script is stopped

    f.close()
    print("\n✅ Resource Usage Analysis Complete!")
    print(f"📄 Results saved to: {OUT_FILE}")
