import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("tests/hash_performance_results.csv")

# Total Time Graph
plt.figure(figsize=(10,6))
for algo in df["algorithm"].unique():
    subset = df[df["algorithm"] == algo]
    plt.plot(subset["count"], subset["total_time_s"], marker="o", label=algo)

plt.xlabel("Number of Passwords")
plt.ylabel("Total Time (s)")
plt.title("Hashing Performance Comparison")
plt.legend()
plt.grid(True)
plt.savefig("tests/graphs/hash_total_time.png")
plt.show()

# Avg Time Graph
plt.figure(figsize=(10,6))
for algo in df["algorithm"].unique():
    subset = df[df["algorithm"] == algo]
    plt.plot(subset["count"], subset["avg_ms"], marker="o", label=algo)

plt.xlabel("Number of Passwords")
plt.ylabel("Avg Time per Password (ms)")
plt.title("Avg Hashing Time per Password")
plt.legend()
plt.grid(True)
plt.savefig("tests/graphs/hash_avg_time.png")
plt.show()
