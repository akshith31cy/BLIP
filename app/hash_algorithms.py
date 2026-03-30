# app/hash_algorithms.py
#
# FIX (Issue 7):
#   OLD: PasswordHasher() with no type argument — defaults to Argon2i in older
#        argon2-cffi versions. Argon2i is weaker against GPU attacks.
#   NEW: Explicitly set type=argon2.Type.ID to guarantee Argon2id regardless
#        of library version. Argon2id is the NIST/OWASP recommended variant
#        for credential storage (hybrid: resists both side-channel and GPU attacks).

import argon2
from argon2 import PasswordHasher, exceptions

# ── Explicit Argon2id — never rely on defaults ─────────────────────────────────
# OWASP 2024 minimum: m=19456, t=2, p=1
# We use m=65536 (64MB) — more conservative, still within interactive budget.
ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=1,
    type=argon2.Type.ID     # <-- Argon2id explicitly
)


def hash_password(password: str) -> str:
    """Hash a plaintext password with Argon2id. Returns full MCF string."""
    return ph.hash(password)


def verify_password(hash_str: str, password: str) -> bool:
    """
    Verify a plaintext password against a stored Argon2id hash.
    Extracts the embedded salt from hash_str automatically — do NOT
    compare hash strings with ==.
    """
    try:
        return ph.verify(hash_str, password)
    except exceptions.VerifyMismatchError:
        return False
    except exceptions.VerificationError:
        return False
    except Exception:
        return False