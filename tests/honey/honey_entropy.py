# tests/honey/honey_entropy.py

import pandas as pd
from math import log2
import matplotlib.pyplot as plt

FILE = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs/honey_fake_outputs.csv"
OUT_PLOT = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs/honey_entropy_dist.png"

df = pd.read_csv(FILE)

def entropy(s):
    if not isinstance(s, str) or len(s) == 0:
        return 0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c/length) * log2(c/length) for c in freq.values())

df["entropy"] = df["fake_output"].astype(str).apply(entropy)

print("=== Entropy Statistics ===")
print(df["entropy"].describe())

# Plot
plt.figure(figsize=(10, 6))
plt.hist(df["entropy"], bins=25, edgecolor='black')

plt.title("Entropy Distribution of Honey Encryption Fake Outputs", fontsize=14)
plt.xlabel("Entropy (bits)", fontsize=12)
plt.ylabel("Frequency", fontsize=12)

plt.grid(alpha=0.3, linestyle="--")

plt.tight_layout()
plt.savefig(OUT_PLOT, dpi=300)
plt.close()

print(f"Saved entropy distribution plot → {OUT_PLOT}")
