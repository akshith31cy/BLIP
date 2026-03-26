# tests/plot_attack_results.py
import os
import pandas as pd
import matplotlib
# Use non-interactive backend so this works in WSL/no-X environments
matplotlib.use("Agg")
import matplotlib.pyplot as plt

LOG_DIR = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs"
SUMMARY = os.path.join(LOG_DIR, "john_attack_summary.csv")

if not os.path.exists(SUMMARY):
    raise SystemExit(f"Summary CSV not found: {SUMMARY}")

df = pd.read_csv(SUMMARY)

# convert slice name to numeric size (first number found in filename)
df['slice_size'] = df['slice'].str.extract(r'(\d+)').astype(int)

# compute total hashes for each algorithm (counts lines in export file)
def total_hashes_for_alg(alg):
    mapping = {
        'bcrypt': '/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_exports/bcrypt_hashes.txt',
        'argon2i': '/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_exports/argon2_hashes.txt'
    }
    path = mapping.get(alg)
    if path and os.path.exists(path):
        return sum(1 for _ in open(path, 'r', encoding='utf-8', errors='ignore'))
    return 0

# compute and guard against division by zero
df['total_hashes'] = df['algorithm'].apply(total_hashes_for_alg)
df['cracked_percent'] = df.apply(
    lambda r: (r['cracked_count'] / r['total_hashes'] * 100) if r['total_hashes'] > 0 else 0.0,
    axis=1
)

# Ensure output directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Plot cracked percent vs wordlist size
for attack in sorted(df['attack'].unique()):
    plt.figure(figsize=(8, 5))
    subset = df[df['attack'] == attack]
    for algo in sorted(subset['algorithm'].unique()):
        s = subset[subset['algorithm'] == algo].sort_values('slice_size')
        plt.plot(s['slice_size'], s['cracked_percent'], marker='o', label=algo)
    plt.xlabel("Wordlist Size (passwords)")
    plt.ylabel("Cracked %")
    plt.xscale('log')  # optional: log scale helps visualization across sizes
    plt.title(f"Cracked % vs Wordlist Size — {attack}")
    plt.legend()
    plt.grid(True, which='both', ls='--', lw=0.5)
    plt.tight_layout()
    out = os.path.join(LOG_DIR, f"cracked_percent_{attack.replace(' ', '_')}.png")
    plt.savefig(out)
    print("Saved:", out)
    plt.close()

# Plot elapsed time vs slice size
for attack in sorted(df['attack'].unique()):
    plt.figure(figsize=(8, 5))
    subset = df[df['attack'] == attack]
    for algo in sorted(subset['algorithm'].unique()):
        s = subset[subset['algorithm'] == algo].sort_values('slice_size')
        plt.plot(s['slice_size'], s['elapsed_s'], marker='o', label=algo)
    plt.xlabel("Wordlist Size (passwords)")
    plt.ylabel("Elapsed Time (s)")
    plt.xscale('log')  # optional
    plt.title(f"Elapsed Time vs Wordlist Size — {attack}")
    plt.legend()
    plt.grid(True, which='both', ls='--', lw=0.5)
    plt.tight_layout()
    out2 = os.path.join(LOG_DIR, f"elapsed_time_{attack.replace(' ', '_')}.png")
    plt.savefig(out2)
    print("Saved:", out2)
    plt.close()
