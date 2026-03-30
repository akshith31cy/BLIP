# adversarial_hash_testing/attack_simulation.py
#
# FIX (Issue 5):
#   OLD: simulate_attack() hashed the guess and compared with ==.
#        For bcrypt and Argon2 this ALWAYS returns False because each hash()
#        call generates a new random salt — two hashes of the same password never match.
#   NEW: Uses verify_bcrypt() and verify_argon2() which correctly extract the
#        embedded salt from the stored hash and re-derive for comparison.
#        SHA-256 still uses direct comparison (it is deterministic by design).
#
# FIX (Issue 5 cont.): External JtR is the authoritative attacker.
#   This module is now a PYTHON FALLBACK simulator for unit-test-level checks.
#   For real adversarial testing use: tests/john_runner.py

import time
from pathlib import Path
from hash_algorithms import (
    hash_sha256, hash_bcrypt, hash_argon2,
    verify_sha256, verify_bcrypt, verify_argon2
)

# ── Configuration ──────────────────────────────────────────────────────────────

TARGET_PASSWORD = "qwerty"          # the "real" password we are testing against
WORDLIST = [
    "123456", "password", "admin", "qwerty", "abc123",
    "letmein", "123123", "iloveyou", "000000", "123456789"
]


# ── Core simulation ────────────────────────────────────────────────────────────

def simulate_attack(
    stored_hash,
    verify_func,
    algorithm_name: str,
    wordlist: list[str],
) -> dict:
    """
    Simulate a dictionary attack against a single stored hash.

    Args:
        stored_hash:     The hash as it would appear in a leaked database.
        verify_func:     The correct verify function (verify_sha256 / verify_bcrypt / verify_argon2).
        algorithm_name:  Label for reporting.
        wordlist:        List of candidate passwords to try.

    Returns:
        dict with: algorithm, cracked (bool), cracked_with (str|None),
                   attempts, elapsed_s, hashes_per_second
    """
    start = time.perf_counter()
    cracked = False
    cracked_with = None
    attempts = 0

    for guess in wordlist:
        attempts += 1
        if verify_func(stored_hash, guess):
            cracked = True
            cracked_with = guess
            break

    elapsed = time.perf_counter() - start
    hps = attempts / elapsed if elapsed > 0 else 0

    return {
        "algorithm":       algorithm_name,
        "cracked":         cracked,
        "cracked_with":    cracked_with,
        "attempts":        attempts,
        "elapsed_s":       round(elapsed, 4),
        "hashes_per_sec":  round(hps, 2),
    }


def simulate_honey_pool_attack(
    honey_hashes: list[str],
    real_index: int,          # only used to EVALUATE success — NOT stored
    verify_func,
    algorithm_name: str,
    wordlist: list[str],
) -> dict:
    """
    Simulate an attacker who has the full honey pool (all 10 hashes)
    and tries the wordlist against each hash in sequence.

    Key insight: attacker cannot distinguish real from decoy — they must try all.
    Measures:
      - total hashes attempted before a crack
      - whether the crack was a decoy or real
      - how many decoys were cracked before the real one
    """
    start = time.perf_counter()
    total_attempts = 0
    decoys_cracked = 0
    real_cracked = False
    results = []

    for pool_idx, stored_hash in enumerate(honey_hashes):
        is_real = (pool_idx == real_index)
        for guess in wordlist:
            total_attempts += 1
            if verify_func(stored_hash, guess):
                if is_real:
                    real_cracked = True
                    results.append({
                        "pool_index": pool_idx,
                        "is_real": True,
                        "cracked_with": guess,
                    })
                else:
                    decoys_cracked += 1
                    results.append({
                        "pool_index": pool_idx,
                        "is_real": False,
                        "cracked_with": guess,
                    })
                break  # next hash in pool

    elapsed = time.perf_counter() - start
    return {
        "algorithm":       algorithm_name,
        "pool_size":       len(honey_hashes),
        "real_cracked":    real_cracked,
        "decoys_cracked":  decoys_cracked,
        "total_attempts":  total_attempts,
        "elapsed_s":       round(elapsed, 4),
        "crack_details":   results,
    }


# ── Runner ─────────────────────────────────────────────────────────────────────

def run_all(target_password: str = TARGET_PASSWORD, wordlist: list[str] = WORDLIST):
    print(f"\n{'='*60}")
    print(f"  LEAP Adversarial Attack Simulation")
    print(f"  Target password: {target_password!r}")
    print(f"  Wordlist size:   {len(wordlist)} entries")
    print(f"{'='*60}\n")

    configs = [
        ("SHA-256",  hash_sha256(target_password),         verify_sha256),
        ("bcrypt",   hash_bcrypt(target_password),          verify_bcrypt),
        ("Argon2id", hash_argon2(target_password),          verify_argon2),
    ]

    for algo, stored, verifier in configs:
        result = simulate_attack(stored, verifier, algo, wordlist)
        status = "CRACKED" if result["cracked"] else "NOT CRACKED"
        print(f"[{algo:>10}]  {status:14}  "
              f"attempts={result['attempts']:>3}  "
              f"time={result['elapsed_s']:.4f}s  "
              f"H/s={result['hashes_per_sec']:.1f}")
        if result["cracked"]:
            print(f"             cracked with: {result['cracked_with']!r}")
    print()


if __name__ == "__main__":
    run_all()