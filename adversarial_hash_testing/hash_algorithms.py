import bcrypt
import hashlib
from argon2 import PasswordHasher

def hash_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_bcrypt(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def hash_argon2(password):
    ph = PasswordHasher()
    return ph.hash(password)
