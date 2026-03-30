# adversarial_hash_testing/hash_algorithms.py
#
# FIX (Issue 5 & 6):
#   OLD: hash_bcrypt() and hash_argon2() generated a NEW salt on every call.
#        This made == comparison always False — attacks silently "failed" for the wrong reason.
#   NEW: Hashing functions only produce a hash for storing.
#        Verification uses the correct library-level verify calls (checkpw / ph.verify).
#        These functions are for HASHING ONLY. Use verify_sha256 / verify_bcrypt / verify_argon2
#        for attack simulation.

import bcrypt
import hashlib
import argon2
from argon2 import PasswordHasher

# ── One shared PasswordHasher instance (Argon2id explicitly) ──────────────────
# FIX (Issue 7): explicitly use Argon2id — default in older argon2-cffi was Argon2i.
ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=1,
    type=argon2.Type.ID   # <-- explicit Argon2id
)


# ── Hash functions (for storing new hashes) ───────────────────────────────────

def hash_sha256(password: str) -> str:
    """SHA-256 — deterministic, no salt. For benchmarking only."""
    return hashlib.sha256(password.encode()).hexdigest()


def hash_bcrypt(password: str) -> bytes:
    """bcrypt with cost=12. Returns bytes. Store with .decode() if needed."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))


def hash_argon2(password: str) -> str:
    """Argon2id hash. Returns the full MCF string including salt."""
    return ph.hash(password)


# ── Verify functions (for ATTACK SIMULATION — correct usage) ──────────────────

def verify_sha256(stored_hash: str, guess: str) -> bool:
    """SHA-256 is deterministic — direct string comparison is correct here."""
    return hashlib.sha256(guess.encode()).hexdigest() == stored_hash


def verify_bcrypt(stored_hash, guess: str) -> bool:
    """
    FIX: Use bcrypt.checkpw() — NOT hash(guess) == stored_hash.
    bcrypt embeds the salt in the stored_hash string; checkpw extracts it automatically.
    """
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode()
    try:
        return bcrypt.checkpw(guess.encode(), stored_hash)
    except Exception:
        return False


def verify_argon2(stored_hash: str, guess: str) -> bool:
    """
    FIX: Use ph.verify() — NOT ph.hash(guess) == stored_hash.
    Argon2 embeds the salt in the MCF string; ph.verify() extracts it automatically.
    """
    try:
        return ph.verify(stored_hash, guess)
    except argon2.exceptions.VerifyMismatchError:
        return False
    except argon2.exceptions.VerificationError:
        return False
    except Exception:
        return False