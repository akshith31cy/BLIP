#!/usr/bin/env python3
"""
Plot hash-performance CSV for paper figures.

Expected CSV columns:
slice,slice_size,algo,repeat,n_hashes,elapsed_s,avg_s_per_hash,hashes_per_sec,
bcrypt_rounds,argon2_time_cost,cpu_before,cpu_after,mem_before_pct,mem_after_pct,
rss_before_mb,rss_after_mb
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# ---- Edit paths if needed ----
PROJECT = "/mnt/c/Users/Akshith/leakage_resilient_password_storage"
CSV_IN = os.path.join(PROJECT, "tests", "hash_performance_results_rockyou.csv")  # <- your CSV
OUT_DIR = os.path.join(PROJECT, "tests", "result_hashes")
os.makedirs(OUT_DIR, exist_ok=True)

# ---- Load ----
df = pd.read_csv(CSV_IN, encoding="utf-8", low_memory=False)

# normalize algorithm names (if necessary)
df['algo'] = df['algo'].str.lower()

# ensure numeric
numcols = ['slice_size','n_hashes','elapsed_s','avg_s_per_hash','hashes_per_sec',
           'cpu_before','cpu_after','rss_before_mb','rss_after_mb',
           'mem_before_pct','mem_after_pct']
for c in numcols:
    if c in df.columns:
        df[c] = pd.to_numeric(df[c], errors='coerce')

# ---- Aggregate: mean & std per algo x slice_size ----
agg = df.groupby(['algo','slice_size']).agg(
    n_runs = ('repeat','count'),
    mean_throughput = ('hashes_per_sec','mean'),
    std_throughput  = ('hashes_per_sec','std'),
    mean_avg_s      = ('avg_s_per_hash','mean'),
    std_avg_s       = ('avg_s_per_hash','std'),
    mean_elapsed_s  = ('elapsed_s','mean'),
    std_elapsed_s   = ('elapsed_s','std'),
    mean_cpu_before = ('cpu_before','mean') if 'cpu_before' in df.columns else ('repeat','count'),
    mean_cpu_after  = ('cpu_after','mean') if 'cpu_after' in df.columns else ('repeat','count'),
    mean_rss_before = ('rss_before_mb','mean') if 'rss_before_mb' in df.columns else ('repeat','count'),
    mean_rss_after  = ('rss_after_mb','mean') if 'rss_after_mb' in df.columns else ('repeat','count')
).reset_index()

# save aggregated data for tables
agg.to_csv(os.path.join(OUT_DIR, "hash_performance_aggregated.csv"), index=False)
print("Saved aggregated CSV →", os.path.join(OUT_DIR, "hash_performance_aggregated.csv"))

# helper: ordered unique sizes
sizes = sorted(df['slice_size'].unique())
algos = sorted(df['algo'].unique())

# ---- Plot 1: Throughput vs dataset size (mean) ----
plt.figure(figsize=(9,5))
for algo, g in agg.groupby('algo'):
    plt.plot(g['slice_size'], g['mean_throughput'], marker='o', label=algo.upper())
plt.xscale('log')
plt.xlabel('Dataset size (number of passwords, log scale)')
plt.ylabel('Throughput (hashes / second)')
plt.title('Hashing throughput vs dataset size')
plt.grid(True, which='both', linestyle='--', linewidth=0.4)
plt.legend()
plt.tight_layout()
out1 = os.path.join(OUT_DIR, 'throughput_vs_size.png')
plt.savefig(out1, dpi=300)
plt.close()
print("Saved", out1)

# ---- Plot 2: Avg seconds per hash vs dataset size ----
plt.figure(figsize=(9,5))
for algo, g in agg.groupby('algo'):
    plt.plot(g['slice_size'], g['mean_avg_s'], marker='o', label=algo.upper())
plt.xscale('log')
plt.xlabel('Dataset size (number of passwords, log scale)')
plt.ylabel('Average seconds per hash')
plt.title('Average time per hash vs dataset size')
plt.grid(True, which='both', linestyle='--', linewidth=0.4)
plt.legend()
plt.tight_layout()
out2 = os.path.join(OUT_DIR, 'avg_time_per_hash_vs_size.png')
plt.savefig(out2, dpi=300)
plt.close()
print("Saved", out2)

# ---- Plot 3: Throughput with error bars (std) ----
plt.figure(figsize=(9,5))
for algo, g in agg.groupby('algo'):
    plt.errorbar(g['slice_size'], g['mean_throughput'],
                 yerr=g['std_throughput'].fillna(0),
                 marker='o', capsize=3, label=algo.upper())
plt.xscale('log')
plt.xlabel('Dataset size (log scale)')
plt.ylabel('Throughput (hashes / second)')
plt.title('Throughput (mean ± std) vs dataset size')
plt.grid(True, which='both', linestyle='--', linewidth=0.4)
plt.legend()
plt.tight_layout()
out3 = os.path.join(OUT_DIR, 'throughput_errorbars.png')
plt.savefig(out3, dpi=300)
plt.close()
print("Saved", out3)

# ---- Plot 4: CPU before/after grouped bars ----
# prepare pivot tables for means
cpu_before = agg.pivot(index='slice_size', columns='algo', values='mean_cpu_before').reindex(sizes)
cpu_after  = agg.pivot(index='slice_size', columns='algo', values='mean_cpu_after').reindex(sizes)

x = np.arange(len(sizes))
width = 0.18
plt.figure(figsize=(12,6))
for i, algo in enumerate(algos):
    before_vals = cpu_before[algo].values if algo in cpu_before.columns else np.zeros(len(sizes))
    after_vals = cpu_after[algo].values if algo in cpu_after.columns else np.zeros(len(sizes))
    # plot before
    plt.bar(x + (i-len(algos)/2)*width + width/2, before_vals, width=width, label=f"{algo.upper()} (cpu before)")
    # stacked part: after - before (may be small)
    plt.bar(x + (i-len(algos)/2)*width + width/2, after_vals - before_vals, bottom=before_vals, width=width, alpha=0.45)
plt.xticks(x, [str(int(s)) for s in sizes], rotation=45)
plt.xlabel('Dataset size')
plt.ylabel('CPU % (mean before, stacked to after)')
plt.title('CPU (mean before / after) by algorithm and dataset size')
plt.legend(ncol=2)
plt.tight_layout()
out4 = os.path.join(OUT_DIR, 'cpu_before_after.png')
plt.savefig(out4, dpi=300)
plt.close()
print("Saved", out4)

# ---- Plot 5: RSS before/after grouped bars (MB) ----
rss_before = agg.pivot(index='slice_size', columns='algo', values='mean_rss_before').reindex(sizes)
rss_after  = agg.pivot(index='slice_size', columns='algo', values='mean_rss_after').reindex(sizes)

plt.figure(figsize=(12,6))
for i, algo in enumerate(algos):
    before_vals = rss_before[algo].values if algo in rss_before.columns else np.zeros(len(sizes))
    after_vals = rss_after[algo].values if algo in rss_after.columns else np.zeros(len(sizes))
    plt.bar(x + (i-len(algos)/2)*width + width/2, before_vals, width=width, label=f"{algo.upper()} (rss before MB)")
    plt.bar(x + (i-len(algos)/2)*width + width/2, after_vals - before_vals, bottom=before_vals, width=width, alpha=0.45)
plt.xticks(x, [str(int(s)) for s in sizes], rotation=45)
plt.xlabel('Dataset size')
plt.ylabel('RSS (MB, mean) before -> after')
plt.title('Process RSS (MB) before/after by algorithm and dataset size')
plt.legend(ncol=2)
plt.tight_layout()
out5 = os.path.join(OUT_DIR, 'rss_before_after.png')
plt.savefig(out5, dpi=300)
plt.close()
print("Saved", out5)

# ---- Plot 6: hashes_per_sec distribution boxplot per algorithm (all sizes combined) ----
plt.figure(figsize=(8,5))
groups = [g['hashes_per_sec'].dropna().values for _, g in df.groupby('algo')]
labels = [k.upper() for k,_ in df.groupby('algo')]
plt.boxplot(groups, labels=labels, showfliers=True)
plt.ylabel('Hashes / sec')
plt.title('Hashes/sec distribution by algorithm (all slice sizes)')
plt.tight_layout()
out6 = os.path.join(OUT_DIR, 'hashes_per_sec_boxplot.png')
plt.savefig(out6, dpi=300)
plt.close()
print("Saved", out6)

print("All plots saved in:", OUT_DIR)
