from honey_encryption.honey_encryptor import honey_encrypt, honey_decrypt

real_password = "MySecurePassword123!"
decoy_count = 100
guess_attempts = 10

encrypted = honey_encrypt(real_password, decoy_count=decoy_count)
print("🔐 Honey Encryption Test")
print(f"Real password: {real_password}")
print(f"Generated {decoy_count} decoys.")
print(f"Real password is hidden at index: {encrypted['key_index']}\n")

print("🕵️ Simulated Attacker Guesses:")
for i in range(guess_attempts):
    guess_index = i
    result = honey_decrypt(encrypted, guess_index)
    verdict = "✅ REAL" if result == real_password else "❌ FAKE"
    print(f"Guess {guess_index:>3}: {result}  →  {verdict}")
