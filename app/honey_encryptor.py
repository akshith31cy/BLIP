# app/honey_encryptor.py
#
# FIX (Issue 3 — honey_index plaintext storage):
#   OLD: generate_decoys() returned (hashes, real_index).
#        real_index was stored in the database. An attacker who dumps the DB
#        immediately knows which hash is real — the honey pool is useless.
#   NEW: The index is DERIVED from the password at login time using HMAC.
#        The database stores only a random `honey_salt` (16 bytes, hex-encoded).
#        honey_index is NEVER stored.
#
# FIX (Issue 3 — mutation-based decoys leak structure):
#   OLD: mutate_password() produced decoys by reversing, appending suffixes,
#        or leet-substituting the REAL password. Cracking any decoy partially
#        reveals the real password's structure.
#   NEW: Decoys are sampled independently from the RockYou frequency list.
#        If no wordlist is available, they fall back to a realistic synthetic
#        generator (length/charset distributions from empirical data).
#        Decoys have NO structural relationship to the real password.
#
# API contract (backward-compatible with main.py):
#   generate_decoys(password, count=9)
#     → returns (honey_hashes: list[str], honey_salt: str)
#       honey_hashes: list of count+1 Argon2id hashes in random order
#       honey_salt:   hex-encoded 16-byte random salt — store this in DB
#
#   derive_honey_index(password: str, honey_salt: str, pool_size: int) → int
#     → deterministically recovers which index is real given the password

import os
import hmac
import hashlib
import random
import string
from pathlib import Path
from .hash_algorithms import hash_password

# ── Wordlist paths (try project-relative, fall back to synthetic) ──────────────
_WORDLIST_CANDIDATES = [
    Path(__file__).parent.parent / "data" / "sample_10000.txt",
    Path(__file__).parent.parent / "data" / "sample_5000.txt",
    Path(__file__).parent.parent / "data" / "common-passwords.txt",
    Path(__file__).parent.parent / "data_rockyou" / "rockyou_top_10000.txt",
]

def _load_wordlist() -> list[str]:
    for path in _WORDLIST_CANDIDATES:
        if path.exists():
            words = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            words = [w.strip() for w in words if 6 <= len(w.strip()) <= 20]
            if len(words) >= 100:
                return words
    return []   # triggers synthetic fallback

_WORDLIST: list[str] = _load_wordlist()


# ── Synthetic password generator (fallback when no wordlist) ──────────────────
_CHARSETS = [
    string.ascii_lowercase,
    string.ascii_lowercase + string.digits,
    string.ascii_lowercase + string.ascii_uppercase + string.digits,
    string.ascii_lowercase + string.digits + "!@#$",
]

def _synthetic_password() -> str:
    """
    Generate a realistic-looking password using length/charset distributions
    derived from empirical breach data.
    Lengths: 6-12 chars, skewed toward 8-10.
    """
    length = random.choices(
        range(6, 13),
        weights=[5, 12, 20, 20, 18, 15, 10],
        k=1
    )[0]
    charset = random.choice(_CHARSETS)
    return ''.join(random.choices(charset, k=length))


# ── HMAC-based index derivation ────────────────────────────────────────────────

def derive_honey_index(password: str, honey_salt: str, pool_size: int) -> int:
    """
    Deterministically derive which pool index holds the real hash,
    given the correct plaintext password and the stored salt.

    This is a one-way function:
      - Correct password + salt → correct index
      - Wrong password + salt   → different (wrong) index
      - Attacker with salt only → cannot derive index without the password

    honey_salt: hex-encoded 16-byte random value stored in the database.
    """
    salt_bytes = bytes.fromhex(honey_salt)
    digest = hmac.new(salt_bytes, password.encode("utf-8"), hashlib.sha256).digest()
    # Use first 4 bytes as an unsigned int, then modulo pool size
    return int.from_bytes(digest[:4], "big") % pool_size


# ── Decoy password sampler ─────────────────────────────────────────────────────

def _sample_decoy(real_pw: str, used: set[str]) -> str:
    """
    Draw one decoy password that:
      1. Has no structural relationship to real_pw
      2. Is not the same as real_pw
      3. Has not been used already in this pool
    Tries wordlist first (more realistic), falls back to synthetic.
    """
    # Try wordlist
    if _WORDLIST:
        for _ in range(200):
            candidate = random.choice(_WORDLIST)
            if candidate != real_pw and candidate not in used:
                return candidate

    # Fallback: synthetic
    for _ in range(500):
        candidate = _synthetic_password()
        if candidate != real_pw and candidate not in used:
            return candidate

    # Last resort — shouldn't reach here
    return _synthetic_password() + str(random.randint(10, 99))


# ── Main API ───────────────────────────────────────────────────────────────────

def generate_decoys(real_pw: str, count: int = 9) -> tuple[list[str], str]:
    """
    Build a honey pool:
      - `count` decoy passwords (sampled independently — no relation to real_pw)
      - 1 real password
      - Shuffled into random order
      - All hashed with Argon2id

    Returns:
        honey_hashes: list of (count+1) Argon2id hash strings
        honey_salt:   hex-encoded 16-byte random salt
                      → store this in the database, NOT the index

    The real password's position is derived at login via derive_honey_index().
    """
    if count < 3:
        count = 3

    # 1. Generate a random salt for this user's honey pool
    honey_salt = os.urandom(16).hex()

    # 2. Determine where the real hash goes (using HMAC derivation)
    pool_size = count + 1
    real_idx = derive_honey_index(real_pw, honey_salt, pool_size)

    # 3. Sample decoy plaintexts — independent of real_pw
    used: set[str] = {real_pw}
    decoy_plaintexts: list[str] = []
    while len(decoy_plaintexts) < count:
        decoy = _sample_decoy(real_pw, used)
        used.add(decoy)
        decoy_plaintexts.append(decoy)

    # 4. Build the plaintext pool in slot order
    #    Slot real_idx = real password; all others = decoys
    pool_plain: list[str] = []
    decoy_iter = iter(decoy_plaintexts)
    for i in range(pool_size):
        if i == real_idx:
            pool_plain.append(real_pw)
        else:
            pool_plain.append(next(decoy_iter))

    # 5. Hash all slots
    honey_hashes = [hash_password(p) for p in pool_plain]

    return honey_hashes, honey_salt