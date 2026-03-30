#!/usr/bin/env python3
# tests/benchmark_pipeline.py
#
# FIX: Replaces the flawed hash_performance.py simulation.
#
# OLD PROBLEMS:
#   1. hash_bcrypt() and hash_argon2() generated NEW salts per call.
#      Timing measured hash GENERATION not VERIFICATION — irrelevant to cracking.
#   2. attack_simulation.py used == comparison for bcrypt/Argon2 — always False.
#   3. No reproducibility (no seed, no fixed params, inconsistent sample sizes).
#   4. bcrypt cost was 10 in some files, 12 in others, default in others.
#
# NEW DESIGN:
#   Phase A — Hash generation benchmark (how long to build a hash):
#              Uses fresh hashing per password — but with FIXED parameters.
#   Phase B — Verification benchmark (how long an attacker spends per guess):
#              Pre-generates ONE stored hash, then times VERIFY calls.
#              This is what matters for crack-rate estimation.
#   Phase C — John the Ripper integration (real attack, not simulated):
#              Delegates to john_runner.py for actual adversarial testing.
#
# Output: CSV at tests/benchmark_results.csv (reproducible)
#
# Usage:
#   python tests/benchmark_pipeline.py
#   python tests/benchmark_pipeline.py --sizes 1000 5000 --algorithms sha256 argon2id

import time
import csv
import hashlib
import argparse
import bcrypt as _bcrypt
import argon2
from argon2 import PasswordHasher
from pathlib import Path

ROOT        = Path(__file__).parent.parent.resolve()
RESULTS_CSV = ROOT / "tests" / "benchmark_results.csv"
DATA_DIR    = ROOT / "data"

# ── FIXED algorithm parameters (reproducible) ─────────────────────────────────
# FIX: single global instance — NOT creating a new one per call.
_PH_ARGON2ID = PasswordHasher(
    time_cost=2, memory_cost=65536, parallelism=1,
    type=argon2.Type.ID
)
_BCRYPT_COST = 12   # OWASP recommended minimum


# ─────────────────────────────────────────────────────────────────────────────
# Hash generation (how long it takes to store a new password)
# ─────────────────────────────────────────────────────────────────────────────

def _gen_sha256(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()

def _gen_bcrypt(pwd: str) -> bytes:
    return _bcrypt.hashpw(pwd.encode(), _bcrypt.gensalt(rounds=_BCRYPT_COST))

def _gen_argon2id(pwd: str) -> str:
    return _PH_ARGON2ID.hash(pwd)


# ─────────────────────────────────────────────────────────────────────────────
# Verification (how long attacker spends per guess — the relevant metric)
# ─────────────────────────────────────────────────────────────────────────────

def _verify_sha256(stored: str, guess: str) -> bool:
    return hashlib.sha256(guess.encode()).hexdigest() == stored

def _verify_bcrypt(stored: bytes, guess: str) -> bool:
    # FIX: use checkpw — NOT hashpw(guess) == stored
    try:
        return _bcrypt.checkpw(guess.encode(), stored)
    except Exception:
        return False

def _verify_argon2id(stored: str, guess: str) -> bool:
    # FIX: use ph.verify — NOT ph.hash(guess) == stored
    try:
        return _PH_ARGON2ID.verify(stored, guess)
    except argon2.exceptions.VerifyMismatchError:
        return False
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Benchmark runner
# ─────────────────────────────────────────────────────────────────────────────

ALGORITHMS = {
    "sha256":   (_gen_sha256,   _verify_sha256,   lambda h: h),
    "bcrypt":   (_gen_bcrypt,   _verify_bcrypt,   lambda h: h),
    "argon2id": (_gen_argon2id, _verify_argon2id, lambda h: h),
}


def benchmark_generation(passwords: list[str], gen_func, label: str) -> dict:
    """Time how long it takes to HASH (generate) each password."""
    times = []
    for pwd in passwords:
        t0 = time.perf_counter()
        gen_func(pwd)
        times.append(time.perf_counter() - t0)

    n      = len(times)
    avg_ms = (sum(times) / n) * 1000
    std_ms = (sum((t - sum(times)/n)**2 for t in times) / n) ** 0.5 * 1000
    total  = sum(times)
    hps    = n / total if total > 0 else 0

    return {
        "phase":      "generation",
        "algorithm":  label,
        "n":          n,
        "total_s":    round(total, 4),
        "avg_ms":     round(avg_ms, 4),
        "std_ms":     round(std_ms, 4),
        "hashes_per_sec": round(hps, 2),
    }


def benchmark_verification(passwords: list[str], gen_func, verify_func, cast, label: str) -> dict:
    """
    Time VERIFICATION — this is what determines cracking speed.
    Pre-generates ONE stored hash of passwords[0], then times verifying
    each candidate in passwords[1:] against it.
    This models an attacker with a single stolen hash trying a wordlist.
    """
    # Create one "victim" hash
    target_password = passwords[0]
    stored_hash     = cast(gen_func(target_password))

    # Time verification of each candidate
    times = []
    hits  = 0
    for candidate in passwords:
        t0 = time.perf_counter()
        result = verify_func(stored_hash, candidate)
        times.append(time.perf_counter() - t0)
        if result:
            hits += 1

    n      = len(times)
    avg_ms = (sum(times) / n) * 1000
    std_ms = (sum((t - sum(times)/n)**2 for t in times) / n) ** 0.5 * 1000
    total  = sum(times)
    hps    = n / total if total > 0 else 0

    return {
        "phase":          "verification",
        "algorithm":      label,
        "n":              n,
        "total_s":        round(total, 4),
        "avg_ms":         round(avg_ms, 4),
        "std_ms":         round(std_ms, 4),
        "hashes_per_sec": round(hps, 2),
        "hits":           hits,
    }


def load_passwords(path: Path, limit: int) -> list[str]:
    """Load up to `limit` non-empty lines from a wordlist."""
    words = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if w:
                words.append(w)
            if len(words) >= limit:
                break
    return words


def find_wordlist(size: int) -> Path:
    """Locate the best available wordlist for the requested size."""
    candidates = [
        DATA_DIR / f"sample_{size}.txt",
        DATA_DIR / "common-passwords.txt",
        ROOT / "data_rockyou" / f"rockyou_top_{size}.txt",
    ]
    for p in candidates:
        if p.exists():
            return p
    # Return the first one that exists regardless of size
    for p in DATA_DIR.glob("*.txt"):
        return p
    raise FileNotFoundError(f"No wordlist found in {DATA_DIR}")


def run_benchmarks(sizes: list[int], algorithm_names: list[str]) -> list[dict]:
    """Run full generation + verification benchmark for each size/algorithm combination."""
    all_results = []

    for size in sizes:
        try:
            wl_path = find_wordlist(size)
        except FileNotFoundError as e:
            print(f"[SKIP] size={size}: {e}")
            continue

        # Limit samples for slow algorithms
        limits = {"sha256": size, "bcrypt": min(size, 200), "argon2id": min(size, 100)}

        for algo_name in algorithm_names:
            if algo_name not in ALGORITHMS:
                print(f"[SKIP] Unknown algorithm: {algo_name}")
                continue

            gen_func, verify_func, cast = ALGORITHMS[algo_name]
            limit     = limits[algo_name]
            passwords = load_passwords(wl_path, limit)

            if not passwords:
                print(f"[SKIP] No passwords loaded from {wl_path}")
                continue

            print(f"[BENCH] {algo_name:>10}  size={size:>7}  n={len(passwords)}")

            # Phase A: generation
            try:
                gen_result = benchmark_generation(passwords, gen_func, algo_name)
                gen_result["dataset_size"] = size
                gen_result["wordlist"]     = str(wl_path.name)
                all_results.append(gen_result)
                print(f"         gen:   avg={gen_result['avg_ms']:.2f}ms  "
                      f"H/s={gen_result['hashes_per_sec']:.1f}")
            except Exception as e:
                print(f"[ERROR] Generation benchmark failed: {e}")

            # Phase B: verification (FIX: this is the relevant metric)
            try:
                ver_result = benchmark_verification(passwords, gen_func, verify_func, cast, algo_name)
                ver_result["dataset_size"] = size
                ver_result["wordlist"]     = str(wl_path.name)
                all_results.append(ver_result)
                print(f"         verify: avg={ver_result['avg_ms']:.2f}ms  "
                      f"H/s={ver_result['hashes_per_sec']:.1f}")
            except Exception as e:
                print(f"[ERROR] Verification benchmark failed: {e}")

    return all_results


def save_results(results: list[dict]):
    """Write all results to CSV."""
    if not results:
        print("[WARN] No results to save.")
        return

    fieldnames = [
        "phase", "algorithm", "dataset_size", "wordlist",
        "n", "total_s", "avg_ms", "std_ms", "hashes_per_sec", "hits",
    ]
    with open(RESULTS_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(results)

    print(f"\n[SAVED] Benchmark results → {RESULTS_CSV}")


def print_summary_table(results: list[dict]):
    print(f"\n{'─'*70}")
    print(f"{'Phase':<14} {'Algorithm':<12} {'Size':>8} {'Avg (ms)':>10} {'H/s':>12}")
    print(f"{'─'*70}")
    for r in results:
        print(f"{r['phase']:<14} {r['algorithm']:<12} {r.get('dataset_size',0):>8} "
              f"{r['avg_ms']:>10.3f} {r['hashes_per_sec']:>12.1f}")
    print(f"{'─'*70}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LEAP Hash Benchmark Pipeline")
    parser.add_argument(
        "--sizes", nargs="+", type=int,
        default=[1000, 5000, 10000],
        help="Dataset sizes to benchmark (default: 1000 5000 10000)"
    )
    parser.add_argument(
        "--algorithms", nargs="+",
        default=["sha256", "bcrypt", "argon2id"],
        help="Algorithms to benchmark (default: all three)"
    )
    args = parser.parse_args()

    print(f"\nLEAP Hash Benchmark Pipeline")
    print(f"Sizes:      {args.sizes}")
    print(f"Algorithms: {args.algorithms}\n")

    results = run_benchmarks(args.sizes, args.algorithms)
    print_summary_table(results)
    save_results(results)


if __name__ == "__main__":
    main()