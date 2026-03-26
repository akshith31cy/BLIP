#!/usr/bin/env python3
import os

ROCKYOU_PATH = "/mnt/c/Users/Akshith/wordlists/rockyou.txt"  # update if needed
OUT_DIR = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/data_rockyou"

SIZES = [
    10000,
    50000,
    100000,
    200000,
    500000,
    1000000
]

os.makedirs(OUT_DIR, exist_ok=True)

def create_slice(n):
    out_file = os.path.join(OUT_DIR, f"rockyou_top_{n}.txt")
    print(f"⏳ Creating slice {n} → {out_file}")

    with open(ROCKYOU_PATH, "r", encoding="latin-1") as src:
        lines = []
        for i, line in enumerate(src):
            if i >= n:
                break
            lines.append(line)

    with open(out_file, "w", encoding="utf-8") as out:
        out.writelines(lines)

    print(f"✔ Done: {out_file}")

for size in SIZES:
    create_slice(size)

print("\n🎉 All slices created in:", OUT_DIR)
