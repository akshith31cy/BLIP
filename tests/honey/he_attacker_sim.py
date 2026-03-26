from honey import encrypt, decrypt, DTE
import json

REAL_KEY = "Password123!"
plaintext = {"secret":"MyUltraSecret"}
cipher = encrypt(REAL_KEY, DTE.encode(json.dumps(plaintext)))

print("Cipher:", cipher)

print("\nAttacker Simulation:")
for guess in open("/tmp/attacker_guess_list.txt"):
    g = guess.strip()
    try:
        out = DTE.decode(decrypt(g, cipher))
    except Exception:
        out = "Invalid format but syntactically valid"
    print(f"Guess: {g} → Output: {out}")
