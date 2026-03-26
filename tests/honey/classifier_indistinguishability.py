#!/usr/bin/env python3
import os, pandas as pd, numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, accuracy_score, roc_curve
import matplotlib.pyplot as plt
from tqdm import tqdm

PROJECT = "/mnt/c/Users/Akshith/leakage_resilient_password_storage"
DECOY_CSV = os.path.join(PROJECT, "tests", "john_logs", "honey_fake_outputs.csv")
OUTDIR = os.path.join(PROJECT, "tests", "honey", "outputs")
os.makedirs(OUTDIR, exist_ok=True)

df = pd.read_csv(DECOY_CSV)
df['decoy'] = df['fake_output'].astype(str)

# If you have a file with real passwords (the true ones), load them.
REALS_PATH = os.path.join(PROJECT, "tests", "honey", "real_passwords_sample.txt")
if os.path.exists(REALS_PATH):
    reals = open(REALS_PATH,"r",encoding="utf-8").read().splitlines()
else:
    # If not available, create synthetic 'real' set from decoys + small variations (this weakens the test).
    reals = df['decoy'].sample(min(1000,len(df)), random_state=1).tolist()

# Build labelled dataset
decoys = df['decoy'].sample(min(2000, len(df)), random_state=3).tolist()
n = min(len(reals), len(decoys))
X = decoys[:n] + reals[:n]
y = [0]*n + [1]*n   # 0 = decoy, 1 = real

# vectorize using character n-grams TF-IDF (captures patterns)
vec = TfidfVectorizer(analyzer='char_wb', ngram_range=(3,5), max_features=5000)
Xv = vec.fit_transform(X)

Xtr, Xte, ytr, yte = train_test_split(Xv, y, test_size=0.3, random_state=42, stratify=y)

clf = LogisticRegression(max_iter=1000, solver="liblinear")
clf.fit(Xtr, ytr)
yp = clf.predict(Xte)
ypr = clf.predict_proba(Xte)[:,1]

acc = accuracy_score(yte, yp)
auc = roc_auc_score(yte, ypr)

print("Classifier accuracy:", acc)
print("Classifier AUC:", auc)

# Save metrics
with open(os.path.join(OUTDIR,"classifier_results.txt"), "w") as f:
    f.write(f"accuracy={acc}\nauc={auc}\n")

# plot ROC
from sklearn.metrics import roc_curve
fpr, tpr, _ = roc_curve(yte, ypr)
plt.figure(figsize=(6,5))
plt.plot(fpr, tpr, label=f"AUC = {auc:.3f}")
plt.plot([0,1],[0,1], linestyle='--', color='gray')
plt.xlabel("False positive rate")
plt.ylabel("True positive rate")
plt.title("ROC: Real vs Decoy classifier")
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(OUTDIR,"roc_curve.png"), dpi=300)
plt.close()

print("Saved classifier results & ROC to:", OUTDIR)
