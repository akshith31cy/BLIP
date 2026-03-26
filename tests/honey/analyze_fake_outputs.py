import pandas as pd
import matplotlib.pyplot as plt

FILE = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs/honey_fake_outputs.csv"
df = pd.read_csv(FILE)

print("Total outputs:", len(df))
print("Unique outputs:", df["fake_output"].nunique())
print("Duplication rate:", 1 - df["fake_output"].nunique()/len(df))

# Length distribution
df["len"] = df["fake_output"].astype(str).apply(len)

plt.hist(df["len"], bins=20)
plt.title("Honey Encryption Fake Output Length Distribution")
plt.xlabel("Length")
plt.ylabel("Frequency")
plt.savefig("/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs/honey_fake_length_dist.png")

print("Saved length distribution plot.")
