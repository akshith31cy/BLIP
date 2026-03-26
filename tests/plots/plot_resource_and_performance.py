#!/usr/bin/env python3
import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

CSV = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs/resource_usage_results.csv"
OUT_DIR = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/hash_performance_graphs"
os.makedirs(OUT_DIR, exist_ok=True)

# Load CSV
df = pd.read_csv(CSV, encoding="utf-8", dtype={
    "algorithm": str,
    "dataset_size": int,
    "total_time_s": float,
    "avg_cpu_percent": float,
    "peak_cpu_percent": float,
    "avg_memory_mb": float,
    "peak_memory_mb": float
})

# Sort dataset sizes for consistent plotting
df = df.sort_values(["dataset_size", "algorithm"])

# 1) Total time vs dataset size (line plot)
plt.figure(figsize=(9,5))
for algo, g in df.groupby("algorithm"):
    plt.plot(g["dataset_size"], g["total_time_s"], marker='o', label=algo)
plt.xscale('log', base=10)
plt.xlabel("Dataset size (number of passwords) — log scale")
plt.ylabel("Total time (s)")
plt.title("Total hashing time vs dataset size")
plt.grid(True, which='both', axis='both', linestyle='--', linewidth=0.4)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "total_time_vs_size.png"), dpi=300)
plt.close()
print("Saved total_time_vs_size.png")

# 2) Throughput (hashes / sec) vs size — derived
df["throughput_hps"] = df["dataset_size"] / df["total_time_s"]
plt.figure(figsize=(9,5))
for algo, g in df.groupby("algorithm"):
    plt.plot(g["dataset_size"], g["throughput_hps"], marker='o', label=algo)
plt.xscale('log', base=10)
plt.xlabel("Dataset size (number of passwords) — log scale")
plt.ylabel("Throughput (hashes / s)")
plt.title("Hashing throughput (hashes/s) vs dataset size")
plt.grid(True, which='both', axis='both', linestyle='--', linewidth=0.4)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "throughput_vs_size.png"), dpi=300)
plt.close()
print("Saved throughput_vs_size.png")

# 3) CPU: Avg and Peak bars grouped by algorithm for each dataset_size
# Pivot to multi-index table: index=dataset_size, columns=(algorithm, metric)
cpu_avg = df.pivot(index="dataset_size", columns="algorithm", values="avg_cpu_percent")
cpu_peak = df.pivot(index="dataset_size", columns="algorithm", values="peak_cpu_percent")
sizes = cpu_avg.index.tolist()
algorithms = cpu_avg.columns.tolist()

# Stacked grouped bar layout
width = 0.2  # bar width per algorithm
x = np.arange(len(sizes))
plt.figure(figsize=(12,6))
for i, algo in enumerate(algorithms):
    plt.bar(x + (i - len(algorithms)/2)*width + width/2,
            cpu_avg[algo].values,
            width=width,
            label=f"{algo} (avg)")
    plt.bar(x + (i - len(algorithms)/2)*width + width/2,
            cpu_peak[algo].values - cpu_avg[algo].values,
            bottom=cpu_avg[algo].values,
            width=width,
            alpha=0.4,
            label=f"{algo} (peak-avg)" if i==0 else "")  # only label once
plt.xticks(x, [str(int(s)) for s in sizes], rotation=45)
plt.xlabel("Dataset size")
plt.ylabel("CPU % (avg + extra to peak)")
plt.title("Average and peak CPU % by algorithm and dataset size")
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "cpu_avg_peak_bar.png"), dpi=300)
plt.close()
print("Saved cpu_avg_peak_bar.png")

# 4) Memory: Avg and Peak bars grouped by algorithm for each dataset_size
mem_avg = df.pivot(index="dataset_size", columns="algorithm", values="avg_memory_mb")
mem_peak = df.pivot(index="dataset_size", columns="algorithm", values="peak_memory_mb")

plt.figure(figsize=(12,6))
for i, algo in enumerate(algorithms):
    plt.bar(x + (i - len(algorithms)/2)*width + width/2,
            mem_avg[algo].values,
            width=width,
            label=f"{algo} (avg)")
    plt.bar(x + (i - len(algorithms)/2)*width + width/2,
            mem_peak[algo].values - mem_avg[algo].values,
            bottom=mem_avg[algo].values,
            width=width,
            alpha=0.4,
            label=f"{algo} (peak-avg)" if i==0 else "")
plt.xticks(x, [str(int(s)) for s in sizes], rotation=45)
plt.xlabel("Dataset size")
plt.ylabel("Memory (MB)")
plt.title("Average and peak memory (MB) by algorithm and dataset size")
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "memory_avg_peak_bar.png"), dpi=300)
plt.close()
print("Saved memory_avg_peak_bar.png")

print("All plots saved to:", OUT_DIR)
