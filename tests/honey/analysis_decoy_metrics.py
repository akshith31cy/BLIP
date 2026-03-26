#!/usr/bin/env python3
import pandas as pd, numpy as np, os
from Levenshtein import distance as lev_distance
from math import log2
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
from scipy.stats import entropy as scipy_entropy
from sklearn.feature_extraction.text import CountVectorizer
from tqdm import tqdm
import json

# Paths
PROJECT = "/mnt/c/Users/Akshith/leakage_resilient_password_storage"
IN = os.path.join(PROJECT, "tests", "john_logs", "honey_fake_outputs.csv")
OUTDIR = os.path.join(PROJECT, "tests", "honey", "outputs")
os.makedirs(OUTDIR, exist_ok=True)

# Read file: expected columns: wrong_key, fake_output
df = pd.read_csv(IN, encoding="utf-8", low_memory=False)
# If your CSV also has the real key / real output, adjust accordingly.
# For these metrics we need: fake_output (string). If you have original real plaintext list, supply it.

# helper: entropy (shannon) per string
def shannon_entropy(s):
    if not isinstance(s, str) or len(s) == 0:
        return 0.0
    c = Counter(s)
    L = len(s)
    return -sum((v/L) * log2(v/L) for v in c.values())

# basic metrics: entropy, length
df["fake_output_str"] = df["fake_output"].astype(str)
df["entropy"] = df["fake_output_str"].apply(shannon_entropy)
df["length"] = df["fake_output_str"].str.len()

# Save basic summary
summary = df[["fake_output_str","length","entropy"]].describe()
summary.to_csv(os.path.join(OUTDIR,"decoy_basic_summary.csv"))

# 1) Length histogram
plt.figure(figsize=(8,4))
sns.histplot(df["length"], bins=20, kde=True)
plt.title("Decoy Length Distribution")
plt.xlabel("Length (chars)")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(os.path.join(OUTDIR,"length_hist.png"), dpi=300)
plt.close()

# 2) Entropy histogram (you had this, but we save again nicely)
plt.figure(figsize=(8,4))
sns.histplot(df["entropy"], bins=25, kde=True)
plt.title("Decoy Entropy (bits)")
plt.xlabel("Entropy (bits)")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(os.path.join(OUTDIR,"entropy_hist.png"), dpi=300)
plt.close()

# 3) Edit distance to a *representative real password set*
# If you have the real password(s) you're protecting, compare decoys to those.
# For now: compute pairwise edit distance among decoys (distribution)
N = min(2000, len(df))
sample_decoys = df["fake_output_str"].sample(N, random_state=42).tolist()

edit_dists = []
for i in tqdm(range(len(sample_decoys)), desc="edit-dist calc"):
    for j in range(i+1, len(sample_decoys)):
        d = lev_distance(sample_decoys[i], sample_decoys[j])
        # normalized by max length for comparability
        maxlen = max(len(sample_decoys[i]), len(sample_decoys[j]), 1)
        edit_dists.append(d / maxlen)

# Save and plot edit-distance distribution
pd.Series(edit_dists).to_csv(os.path.join(OUTDIR,"pairwise_editdist_normalized.csv"), index=False)
plt.figure(figsize=(8,4))
sns.histplot(edit_dists, bins=40, kde=True)
plt.title("Pairwise Normalized Edit Distance (decoys sample)")
plt.xlabel("Normalized Levenshtein distance")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(os.path.join(OUTDIR,"editdist_hist.png"), dpi=300)
plt.close()

# 4) Jaccard similarity on character n-grams (use char-3-grams)
def char_ngrams(s, n=3):
    s = s if isinstance(s,str) else ""
    return {s[i:i+n] for i in range(max(0,len(s)-n+1))}

def jaccard(a,b):
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    uni = len(a | b)
    return inter / uni if uni>0 else 0.0

# compute jaccard for pairwise sample (smaller sample)
sample2 = df["fake_output_str"].sample(min(1000,len(df)), random_state=1).tolist()
jaccs=[]
for i in range(len(sample2)):
    for j in range(i+1, len(sample2)):
        jaccs.append(jaccard(char_ngrams(sample2[i],3), char_ngrams(sample2[j],3)))
# save & plot
pd.Series(jaccs).to_csv(os.path.join(OUTDIR,"pairwise_jaccard_3gram.csv"), index=False)
plt.figure(figsize=(8,4))
sns.histplot(jaccs, bins=40, kde=True)
plt.title("Pairwise Jaccard (char 3-grams) among decoys")
plt.xlabel("Jaccard similarity")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(os.path.join(OUTDIR,"jaccard_hist.png"), dpi=300)
plt.close()

# 5) Character frequency and KL divergence vs a reference (if you have real passwords)
# Build char distribution of decoys
all_chars = "".join(df["fake_output_str"].astype(str).tolist())
decoy_counts = Counter(all_chars)
decoy_total = sum(decoy_counts.values())

decoy_freq = {c: decoy_counts[c]/decoy_total for c in decoy_counts}

# If you have real password corpus (e.g., small list of true passwords), place path here:
REAL_PW_PATH = os.path.join(PROJECT,"data","real_passwords_sample.txt")  # optional
if os.path.exists(REAL_PW_PATH):
    reals = open(REAL_PW_PATH, "r", encoding="utf-8").read().splitlines()
    all_chars_real = "".join(reals)
    real_counts = Counter(all_chars_real)
    real_total = sum(real_counts.values())
    real_freq = {c: real_counts[c]/real_total for c in real_counts}
    # build aligned vectors
    chars = sorted(set(list(decoy_freq.keys()) + list(real_freq.keys())))
    p = np.array([decoy_freq.get(c,1e-9) for c in chars])
    q = np.array([real_freq.get(c,1e-9) for c in chars])
    kl = scipy_entropy(p, q, base=2)  # KL(decoy || real)
    with open(os.path.join(OUTDIR,"kl_charfreq.txt"), "w") as f:
        f.write(f"KL(decoy || real) in bits: {kl}\n")
    # bar plot of top char freqs
    dfc = pd.DataFrame({"char": chars, "decoy": p, "real": q})
    dfc = dfc.sort_values("decoy", ascending=False).head(40).set_index("char")
    dfc.plot.bar(figsize=(12,4))
    plt.title("Top character frequency: decoy vs real")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTDIR,"kl_charfreq.png"), dpi=300)
    plt.close()
else:
    # save decoy char freq to CSV for paper
    pd.DataFrame.from_dict(decoy_freq, orient="index", columns=["freq"]).sort_values("freq", ascending=False).to_csv(os.path.join(OUTDIR,"decoy_charfreq.csv"))

# 6) Save combined per-decoy metrics to CSV
df_out = df[["fake_output_str","length","entropy"]].copy().rename(columns={"fake_output_str":"decoy"})
df_out.to_csv(os.path.join(OUTDIR,"decoy_metrics.csv"), index=False)

print("All decoy metrics & plots saved to:", OUTDIR)
