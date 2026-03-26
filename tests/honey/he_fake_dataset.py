from honey import encrypt, decrypt, DTE
import random, string, json, csv

REAL_KEY = "Password123!"
PLAINTEXT = {"secret": "MyUltraSecretValue"}

cipher = encrypt(REAL_KEY, DTE.encode(json.dumps(PLAINTEXT)))

def random_key():
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(8))

OUT = "/mnt/c/Users/Akshith/leakage_resilient_password_storage/tests/john_logs/honey_fake_outputs.csv"

rows=[]
for i in range(500):  # 500 sample wrong decryptions
    wk = random_key()
    dec = DTE.decode(decrypt(wk, cipher))
    rows.append([wk, dec])

with open(OUT, "w", newline="", encoding="utf-8") as f:
    w=csv.writer(f)
    w.writerow(["wrong_key","fake_output"])
    w.writerows(rows)

print("Saved:", OUT)
