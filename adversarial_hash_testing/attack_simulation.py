import time
from hash_algorithms import hash_sha256, hash_bcrypt, hash_argon2

# List of common passwords (simulate a dictionary attack)
password_list = [
    "123456", "password", "admin", "qwerty", "abc123",
    "letmein", "123123", "iloveyou", "000000", "123456789"
]

target_password = "qwerty"  # Let's assume this is the real password

print("Simulating attack on password:", target_password)

def simulate_attack(hash_func, name):
    print(f"\nTesting {name}...")
    start = time.time()
    hashed_target = hash_func(target_password)

    success = False
    for guess in password_list:
        hashed_guess = hash_func(guess)
        if hashed_guess == hashed_target:
            success = True
            break
    end = time.time()
    print(f"{name} - {'Cracked' if success else 'Not Cracked'} in {end - start:.4f} seconds")

simulate_attack(hash_sha256, "SHA-256")
simulate_attack(hash_bcrypt, "bcrypt")
simulate_attack(hash_argon2, "Argon2")
