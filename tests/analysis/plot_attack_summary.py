#!/usr/bin/env python3
import os
import pandas as pd
import matplotlib.pyplot as plt

IN = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs/john_attack_summary_tuned.csv"
OUTDIR = "results/plots"
os.makedirs(OUTDIR, exist_ok=True)

df = pd.read_csv(IN)
# Convert elapsed to numeric
df['elapsed_s'] = pd.to_numeric(df['elapsed_s'], errors='coerce')
df['cracked_count'] = pd.to_numeric(df['cracked_count'], errors='coerce')

# 1) Bar: cracked_count by algorithm + attack (sum across repeats & slices)
agg = df.groupby(['algorithm','attack'])['cracked_count'].sum().unstack(fill_value=0)
plt.figure(figsize=(8,4))
agg.plot(kind='bar', legend=True)
plt.ylabel('Total cracked (sum over slices & repeats)')
plt.title('Total cracked passwords by algorithm and attack')
plt.tight_layout()
plt.savefig(os.path.join(OUTDIR, 'cracked_by_alg_attack.png'))
plt.close()

# 2) Boxplot: elapsed time per algorithm (distribution across runs)
plt.figure(figsize=(8,4))
df.boxplot(column='elapsed_s', by='algorithm')
plt.ylabel('Elapsed time (s)')
plt.title('Elapsed time distribution by algorithm')
plt.suptitle('')
plt.tight_layout()
plt.savefig(os.path.join(OUTDIR, 'elapsed_box_by_alg.png'))
plt.close()

# 3) Line/scale: median elapsed vs slice size per algorithm & attack
# convert slice name to number (extract digits)
def slice_num(s):
    import re
    m = re.search(r'(\d+)', s)
    return int(m.group(1)) if m else 0
df['slice_n'] = df['slice'].apply(slice_num)
med = df.groupby(['algorithm','attack','slice_n'])['elapsed_s'].median().reset_index()
for (alg,atk), g in med.groupby(['algorithm','attack']):
    plt.plot(g['slice_n'], g['elapsed_s'], marker='o', label=f"{alg}-{atk}")
plt.xscale('log')
plt.xlabel('Slice size (log scale)')
plt.ylabel('Median elapsed (s)')
plt.title('Median elapsed time vs slice size')
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(OUTDIR, 'median_elapsed_vs_slice.png'))
plt.close()

print("Saved plots to", OUTDIR)
