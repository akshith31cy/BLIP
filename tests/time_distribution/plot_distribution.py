import pandas as pd
import matplotlib.pyplot as plt

csv_path = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/time_distribution/bcrypt_time_distribution.csv"
df = pd.read_csv(csv_path)

# Convert timestamp to seconds
df["crack_time"] = pd.to_datetime(df["crack_time"])
df = df.sort_values("crack_time")
df["t_secs"] = (df["crack_time"] - df["crack_time"].min()).dt.total_seconds()

# Histogram
plt.figure(figsize=(8,5))
plt.hist(df["t_secs"], bins=20)
plt.title("Time-to-Crack Distribution (bcrypt)")
plt.xlabel("Seconds Since Attack Start")
plt.ylabel("Number of Cracked Passwords")
plt.grid(True)
plt.tight_layout()
plt.show()

# CDF
plt.figure(figsize=(8,5))
plt.plot(df["t_secs"], df.index / len(df))
plt.title("CDF of Time-to-Crack (bcrypt)")
plt.xlabel("Seconds")
plt.ylabel("Cumulative Fraction Cracked")
plt.grid(True)
plt.tight_layout()
plt.show()
