#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import os

CSV = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs/john_attack_summary_longer_bcrypt.csv"
OUT = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/plots"

df = pd.read_csv(CSV)

# Convert slice name -> number
df["slice_size"] = df["slice"].str.extract(r"(\d+)").astype(int)

algos = df["algorithm"].unique()
attacks = df["attack"].unique()

# 1. TIME vs SLICE SIZE
for algo in algos:
    for attack in attacks:
        subset = df[(df["algorithm"] == algo) & (df["attack"] == attack)]

        if subset.empty:
            continue

        plt.figure(figsize=(10,6))
        plt.title(f"{algo.upper()} – Time vs Wordlist Size ({attack})")
        plt.xlabel("Slice size")
        plt.ylabel("Elapsed time (s)")

        plt.plot(subset["slice_size"], subset["elapsed_s"], marker='o')

        plt.grid(True)
        outpath = os.path.join(OUT, f"{algo}_{attack}_time_vs_size.png")
        plt.savefig(outpath)
        plt.close()

# 2. CRACKED COUNT vs SIZE
plt.figure(figsize=(10,6))
plt.title("Cracked Count vs Slice Size")
plt.xlabel("Slice size")
plt.ylabel("Cracked Count")

plt.plot(df["slice_size"], df["cracked_count"], marker='o')
plt.grid(True)

plt.savefig(os.path.join(OUT, "cracked_count_vs_size.png"))
plt.close()

# 3. BOX PLOT (time distribution)
plt.figure(figsize=(10,6))
plt.title("Time Distribution Across Runs")
plt.xlabel("Slice size")
plt.ylabel("Time (s)")

data = []
labels = []

for s in sorted(df["slice_size"].unique()):
    data.append(df[df["slice_size"] == s]["elapsed_s"])
    labels.append(str(s))

plt.boxplot(data, labels=labels)
plt.grid(True)

plt.savefig(os.path.join(OUT, "time_distribution_boxplot.png"))
plt.close()

print("Plots saved to:", OUT)
