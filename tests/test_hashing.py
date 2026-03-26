import time
import bcrypt
import hashlib
from argon2 import PasswordHasher

password = "testpass"

def time_hash_sha256():
    start = time.time()
    for _ in range(10):
        hashlib.sha256(password.encode()).hexdigest()
    return time.time() - start

def time_hash_bcrypt():
    start = time.time()
    for _ in range(10):
        bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return time.time() - start

def time_hash_argon2():
    ph = PasswordHasher()
    start = time.time()
    for _ in range(10):
        ph.hash(password)
    return time.time() - start

print("SHA256 time (10x):", round(time_hash_sha256(), 4), "s")
print("bcrypt time (10x):", round(time_hash_bcrypt(), 4), "s")
print("Argon2 time (10x):", round(time_hash_argon2(), 4), "s")
