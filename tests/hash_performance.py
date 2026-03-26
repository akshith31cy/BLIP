import time, psutil, os, csv, hashlib, bcrypt
from argon2 import PasswordHasher

ph = PasswordHasher(time_cost=2, memory_cost=51200, parallelism=2)

def hash_sha256(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def hash_bcrypt(pwd):
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()

def hash_argon2(pwd):
    return ph.hash(pwd)

def run_benchmark(passwords, algo_name, func):
    proc = psutil.Process(os.getpid())
    times = []
    mem_before = proc.memory_info().rss

    start_total = time.perf_counter()
    for pwd in passwords:
        t0 = time.perf_counter()
        func(pwd)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000)  # ms per password
    total_time = time.perf_counter() - start_total

    mem_after = proc.memory_info().rss
    mem_used_mb = (mem_after - mem_before) / (1024 * 1024)

    avg_time = sum(times) / len(times)
    std = (sum((t - avg_time)**2 for t in times) / len(times))**0.5

    return total_time, avg_time, std, mem_used_mb, len(times)

def benchmark_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        passwords = f.read().splitlines()

    tests = [
        ("SHA256", hash_sha256),
        ("bcrypt", hash_bcrypt),
        ("Argon2", hash_argon2)
    ]

    results = []

    for name, func in tests:
        total, avg, std, mem, count = run_benchmark(passwords, name, func)
        results.append([path, name, count, total, avg, std, mem])

    return results

if __name__ == "__main__":
    dataset_sizes = [1000, 5000, 10000, 50000, 100000]
    
    with open("tests/hash_performance_results.csv", "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["dataset", "algorithm", "count", "total_time_s", "avg_ms", "std_ms", "memory_mb"])

        for s in dataset_sizes:
            path = f"data/sample_{s}.txt"
            results = benchmark_file(path)
            for row in results:
                writer.writerow(row)

    print("Benchmark complete. Results saved to tests/hash_performance_results.csv")
