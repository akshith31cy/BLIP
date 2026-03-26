import time
import hashlib
import bcrypt
import pandas as pd
from argon2 import PasswordHasher

# Load the password file
password_file_path = "data/common-passwords.txt"

with open(password_file_path, "r", encoding="utf-8", errors="ignore") as f:
    all_passwords = [line.strip() for line in f.readlines() if line.strip()]

# Split samples for safety
sample_sha = all_passwords[:1000]      # Fastest, so 1000 is okay
sample_bcrypt = all_passwords[:500]    # bcrypt is slower
sample_argon2 = all_passwords[:100]    # argon2 is slowest

print(f"✅ Loaded {len(all_passwords)} passwords for testing")
print(f"Testing: SHA256 (1000), bcrypt (500), Argon2 (100)\n")

# ========================
# Define hashing functions
# ========================

def hash_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_bcrypt(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Use lower cost temporarily for testing
ph = PasswordHasher(time_cost=2, memory_cost=51200, parallelism=2)

def hash_argon2(password):
    return ph.hash(password)

# ========================
# Benchmark functions
# ========================

def benchmark(algorithm_name, hash_func, password_list):
    print(f"⏱️ Hashing with {algorithm_name}...")
    start = time.time()
    for pwd in password_list:
        hash_func(pwd)
    end = time.time()
    elapsed = round(end - start, 2)
    print(f"{algorithm_name} Time: {elapsed} seconds for {len(password_list)} passwords\n")
    return elapsed

# ========================
# Run Tests
# ========================

sha_time = benchmark("SHA256", hash_sha256, sample_sha)
bcrypt_time = benchmark("bcrypt", hash_bcrypt, sample_bcrypt)
argon2_time = benchmark("Argon2", hash_argon2, sample_argon2)

# ========================
# Save to CSV
# ========================

df = pd.DataFrame({
    "Algorithm": ["SHA256", "bcrypt", "Argon2"],
    "Time (s)": [sha_time, bcrypt_time, argon2_time],
    "Passwords_Tested": [len(sample_sha), len(sample_bcrypt), len(sample_argon2)]
})

df.to_csv("tests/hash_benchmark_results.csv", index=False)
print("📊 Results saved to tests/hash_benchmark_results.csv")
