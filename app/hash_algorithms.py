# app/hash_algorithms.py
from argon2 import PasswordHasher, exceptions

# Argon2i default settings; tune time/memory as desired
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=1)

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(hash_str: str, password: str) -> bool:
    try:
        return ph.verify(hash_str, password)
    except exceptions.VerifyMismatchError:
        return False
    except exceptions.VerificationError:
        return False
