from honey import encrypt, decrypt, DTE
import json

REAL_KEY = "Password123!"
WRONG_KEYS = ["123456", "letmein", "qwerty", "abcdef", "zzzzzzz"]

plaintext = {
    "username": "akshith@example.com",
    "password": "Password123!"
}

# Encode + encrypt
cipher = encrypt(REAL_KEY, DTE.encode(json.dumps(plaintext)))

print("Ciphertext:", cipher)

# Decrypt with correct key
real = json.loads(DTE.decode(decrypt(REAL_KEY, cipher)))
print("Real Decryption:", real)

# Decrypt using wrong keys
for wk in WRONG_KEYS:
    fake = None
    try:
        fake = json.loads(DTE.decode(decrypt(wk, cipher)))
    except Exception:
        fake = "Invalid JSON but syntactically valid string"
    print(f"Wrong Key = {wk} → Fake Output:", fake)
