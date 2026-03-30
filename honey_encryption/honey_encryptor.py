# honey_encryption/honey_encryptor.py
#
# FIX (Issue 8 — plaintext password in returned dict):
#   OLD: encrypted dict contained ['encrypted'][real_index] = real_data (plaintext).
#        If serialised to disk or logged, the real password was exposed in cleartext.
#        key_index was also stored alongside — immediately revealing the real slot.
#   NEW: This module is redesigned as a RESEARCH/DEMO module only.
#        It demonstrates the conceptual honey encryption mechanism WITHOUT
#        storing plaintext. Passwords are hashed before storage.
#        key_index is NEVER stored in the returned structure.
#
# NOTE: The production system in app/honey_encryptor.py uses HMAC-based
#       index derivation. This module exists for standalone research demos.

import os
import hmac
import hashlib
import random
from faker import Faker

faker = Faker()


def honey_encrypt(real_password: str, decoy_count: int = 9) -> dict:
    """
    Research demonstration of honey encryption concept.

    Stores:
      - hashed versions of all passwords (real + decoys)
      - a random honey_salt for HMAC index derivation
      - NEVER the real_index, NEVER any plaintext

    To retrieve the real hash at 'decryption' time, the correct password
    must be provided to honey_decrypt().

    Args:
        real_password: The actual user password (plaintext — discarded after hashing)
        decoy_count:   Number of decoy slots (default 9 → 10 total)

    Returns:
        dict with:
          'hashed_pool': list of hashed strings (real + decoys, shuffled)
          'honey_salt':  hex salt for HMAC derivation (safe to store)
          NOTE: 'key_index' is NOT returned
    """
    pool_size  = decoy_count + 1
    honey_salt = os.urandom(16).hex()

    # Derive real index from password (not stored)
    salt_bytes = bytes.fromhex(honey_salt)
    digest     = hmac.new(salt_bytes, real_password.encode(), hashlib.sha256).digest()
    real_index = int.from_bytes(digest[:4], "big") % pool_size

    # Generate decoy plaintexts (independent — no relation to real_password)
    decoy_pool: list[str] = []
    seen = {real_password}
    while len(decoy_pool) < decoy_count:
        candidate = faker.password(length=random.randint(8, 14))
        if candidate not in seen:
            seen.add(candidate)
            decoy_pool.append(candidate)

    # Build the pool: real password goes in real_index, decoys fill the rest
    pool_plain: list[str] = []
    decoy_iter = iter(decoy_pool)
    for i in range(pool_size):
        if i == real_index:
            pool_plain.append(real_password)
        else:
            pool_plain.append(next(decoy_iter))

    # Hash everything — never store plaintext
    import hashlib as _hl
    hashed_pool = [_hl.sha256(p.encode()).hexdigest() for p in pool_plain]
    # NOTE: In production use Argon2id (app/honey_encryptor.py).
    # SHA256 is used here for demo speed only.

    return {
        "hashed_pool": hashed_pool,
        "honey_salt":  honey_salt,
        "pool_size":   pool_size,
        # key_index intentionally omitted
    }


def honey_decrypt(encrypted_data: dict, password_guess: str) -> dict:
    """
    Attempt to identify the real hash slot using a password guess.

    Args:
        encrypted_data: dict from honey_encrypt()
        password_guess: plaintext candidate password

    Returns:
        dict with:
          'candidate_index': index this password maps to
          'candidate_hash':  hash at that index
          'matched':         True if the hash of the guess matches the slot
                             (attacker cannot know this without knowing real_index)
    """
    honey_salt = encrypted_data["honey_salt"]
    pool_size  = encrypted_data["pool_size"]
    hashed_pool = encrypted_data["hashed_pool"]

    salt_bytes      = bytes.fromhex(honey_salt)
    digest          = hmac.new(salt_bytes, password_guess.encode(), hashlib.sha256).digest()
    candidate_index = int.from_bytes(digest[:4], "big") % pool_size

    import hashlib as _hl
    guess_hash      = _hl.sha256(password_guess.encode()).hexdigest()
    slot_hash       = hashed_pool[candidate_index]

    return {
        "candidate_index": candidate_index,
        "candidate_hash":  slot_hash,
        "matched":         guess_hash == slot_hash,
    }