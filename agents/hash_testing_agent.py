# agents/hash_testing_agent.py
#
# IMPROVEMENT: Integrates John the Ripper as the authoritative attack backend.
#   - If JtR is available, delegates actual cracking to john_runner.py
#   - Falls back to Python-based scoring when JtR is not installed
#   - Reports include real crack counts from JtR (not estimates)
#   - Detects weak configs from live attack evidence, not just heuristics

import time
import json
import math
import re
import os
import sys
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# ── JtR binary detection ───────────────────────────────────────────────────────
_JTR_CANDIDATES = [
    "john",
    os.path.expanduser("~/john-jumbo/run/john"),
    "/usr/sbin/john",
    "/usr/bin/john",
]

def _find_john() -> str | None:
    for c in _JTR_CANDIDATES:
        try:
            r = subprocess.run([c, "--list=formats"], capture_output=True, timeout=5)
            if r.returncode == 0:
                return c
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None

JOHN_BIN = _find_john()

# ── Crack-rate table (GPU RTX 3090 reference) ──────────────────────────────────
CRACK_RATES_HPS = {
    "argon2id": 800,
    "argon2i":  1000,
    "bcrypt":   30_000,
    "sha256":   10_000_000_000,
    "md5":      100_000_000_000,
    "unknown":  1_000_000_000,
}

SECURITY_LEVELS = [
    (25,   "critical",  "Algorithm too weak — trivially crackable"),
    (45,   "weak",      "Weak configuration — parameters below threshold"),
    (65,   "moderate",  "Acceptable but hardening is recommended"),
    (80,   "strong",    "Good configuration"),
    (None, "excellent", "Excellent — honey pool + strong memory-hard KDF"),
]


class HashTestingAgent:
    """
    Runs on every register/login event.
    Uses JtR for real attack validation when available;
    falls back to algorithmic scoring otherwise.
    """

    def __init__(self, wordlist_path: str | None = None):
        self.wordlist = wordlist_path or self._find_wordlist()
        self.john_bin = JOHN_BIN

    def run(
        self,
        username:    str,
        real_hash:   str,
        honey_hashes: list[str],
        honey_index: int,
        trigger:     str = "register",
        extra:       dict | None = None,
    ) -> dict:
        started = time.perf_counter()

        algo   = self._detect_algo(real_hash)
        params = self._parse_params(real_hash, algo)
        pool   = len(honey_hashes)

        # ── Live JtR attack (if available) ────────────────────────────────
        jtr_result = None
        if self.john_bin and self.wordlist:
            jtr_result = self._run_jtr_probe(honey_hashes, algo)

        # ── Scoring ───────────────────────────────────────────────────────
        strength    = self._score_strength(algo, params, pool, jtr_result)
        crack_est   = self._estimate_crack_time(algo, params)
        probe_stats = self._honey_probe_stats(pool)
        entropy     = self._entropy_bits(algo)

        elapsed = round(time.perf_counter() - started, 4)

        report = {
            "report_id":        self._gen_id(username),
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "trigger":          trigger,
            "username":         username,
            "algorithm":        algo,
            "algorithm_params": params,
            "honey_pool_size":  pool,

            "security_score":   strength["score"],
            "security_level":   strength["level"],
            "level_reason":     strength["reason"],

            "estimated_crack_seconds": crack_est["seconds"],
            "estimated_crack_human":   crack_est["human"],
            "crack_rate_hps":          crack_est["rate_hps"],

            "entropy_bits":     entropy,
            "dictionary_probe": probe_stats,
            "jtr_probe":        jtr_result,   # None if JtR not available

            "recommendations":  self._recommendations(algo, params, strength, pool, jtr_result),
            "agent_runtime_s":  elapsed,
            "extra":            extra or {},
        }

        self._save(report)
        return report

    # ── JtR live probe ─────────────────────────────────────────────────────

    def _run_jtr_probe(self, honey_hashes: list[str], algo: str) -> dict | None:
        """
        Write a tiny temp hash file (just the honey pool for this user)
        and run JtR for a short probe (max 30 seconds).
        Returns structured results.
        """
        fmt_map = {"argon2id": "argon2id", "argon2i": "argon2i",
                   "bcrypt": "bcrypt", "sha256": "raw-sha256"}
        fmt = fmt_map.get(algo)
        if not fmt:
            return None

        # Filter hashes matching the format
        prefix_map = {"argon2id": "$argon2id", "argon2i": "$argon2i",
                      "bcrypt": "$2", "sha256": ""}
        prefix = prefix_map.get(algo, "")

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="leap_probe_"
            ) as tf:
                for i, h in enumerate(honey_hashes):
                    if not prefix or h.startswith(prefix):
                        tf.write(f"probe_slot{i}:{h}\n")
                tmp_path = tf.name

            if os.path.getsize(tmp_path) == 0:
                os.unlink(tmp_path)
                return None

            # Run JtR — short probe only (30s max)
            t0  = time.perf_counter()
            cmd = [
                self.john_bin,
                f"--wordlist={self.wordlist}",
                f"--format={fmt}",
                "--max-run-time=30",
                tmp_path,
            ]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=35
            )
            elapsed = time.perf_counter() - t0

            # Run --show
            show = subprocess.run(
                [self.john_bin, "--show", f"--format={fmt}", tmp_path],
                capture_output=True, text=True
            )

            # Parse cracked count
            cracked_lines = [
                l for l in show.stdout.splitlines()
                if ":" in l and "password" not in l.lower()
            ]

            os.unlink(tmp_path)
            return {
                "format":       fmt,
                "elapsed_s":    round(elapsed, 2),
                "cracked":      len(cracked_lines),
                "total_hashes": len(honey_hashes),
                "crack_rate":   round(len(cracked_lines)/len(honey_hashes)*100, 1),
                "cracked_slots": [l.split(":")[0] for l in cracked_lines],
            }

        except subprocess.TimeoutExpired:
            return {"format": fmt, "error": "JtR probe timed out (>35s)"}
        except Exception as e:
            return {"format": fmt, "error": str(e)}

    # ── Detection & parsing ────────────────────────────────────────────────

    def _detect_algo(self, h: str) -> str:
        h2 = h.lower()
        if h2.startswith("$argon2id"): return "argon2id"
        if h2.startswith("$argon2i"):  return "argon2i"
        if h2.startswith("$argon2"):   return "argon2i"
        if h2.startswith("$2b$") or h2.startswith("$2a$"): return "bcrypt"
        if re.fullmatch(r"[0-9a-f]{64}", h2): return "sha256"
        if re.fullmatch(r"[0-9a-f]{32}", h2): return "md5"
        return "unknown"

    def _parse_params(self, h: str, algo: str) -> dict:
        if algo in ("argon2i", "argon2id"):
            return {
                "memory_kb":   int(m.group(1)) if (m := re.search(r"m=(\d+)", h)) else 65536,
                "time_cost":   int(m.group(1)) if (m := re.search(r"t=(\d+)", h)) else 2,
                "parallelism": int(m.group(1)) if (m := re.search(r"p=(\d+)", h)) else 1,
            }
        if algo == "bcrypt":
            m = re.search(r"\$2[ab]\$(\d+)\$", h)
            return {"rounds": int(m.group(1)) if m else 12}
        return {}

    # ── Scoring ────────────────────────────────────────────────────────────

    def _score_strength(self, algo, params, pool, jtr=None) -> dict:
        # Base: algorithm
        base = {"argon2id":50,"argon2i":45,"bcrypt":35,"sha256":10,"md5":0,"unknown":0}
        score = base.get(algo, 0)

        # Params
        if algo in ("argon2i","argon2id"):
            score += min(15, int(math.log2(max(params.get("memory_kb",1024),1024))-9))
            score += min(15, params.get("time_cost",2)*4)
        elif algo == "bcrypt":
            score += min(30, (params.get("rounds",12)-10)*5)

        # Honey pool
        score += min(20, (pool-1)*2)

        # JtR penalty: if live attack cracked anything, reduce score
        if jtr and jtr.get("cracked", 0) > 0:
            crack_rate = jtr.get("crack_rate", 0)
            score = max(0, score - int(crack_rate * 0.5))

        score = max(0, min(100, score))

        for threshold, level, reason in SECURITY_LEVELS:
            if threshold is None or score <= threshold:
                return {"score": score, "level": level, "reason": reason}

    def _estimate_crack_time(self, algo, params) -> dict:
        rate = CRACK_RATES_HPS.get(algo, CRACK_RATES_HPS["unknown"])
        if algo in ("argon2i","argon2id"):
            mem = params.get("memory_kb",65536)
            tc  = params.get("time_cost",2)
            rate = max(100, rate // max(1, (mem//65536)*tc))
        elif algo == "bcrypt":
            rate = max(100, rate // max(1, 2**(params.get("rounds",12)-12)))
        keyspace = 62**8
        secs     = keyspace / rate
        return {"seconds": secs, "human": self._human(secs), "rate_hps": rate}

    def _honey_probe_stats(self, pool: int) -> dict:
        p_decoy  = (pool-1)/pool
        confusion = round(math.log2(pool), 2)
        return {
            "pool_size":            pool,
            "decoy_count":          pool-1,
            "p_decoy_first":        round(p_decoy, 3),
            "expected_attempts":    pool,
            "honey_confusion_gain": confusion,
            "simulation_note":      (
                f"Attacker faces {pool} indistinguishable hashes. "
                f"Adds ~{confusion} bits of confusion."
            ),
        }

    def _entropy_bits(self, algo) -> float:
        return {"argon2id":256,"argon2i":256,"bcrypt":184,"sha256":256,"md5":128}.get(algo,128)

    # ── Recommendations ────────────────────────────────────────────────────

    def _recommendations(self, algo, params, strength, pool, jtr=None) -> list[dict]:
        recs = []
        lvl  = strength["level"]

        if algo in ("md5","sha256","unknown"):
            recs.append({"priority":"critical","action":"upgrade_algorithm",
                         "detail":"Switch to Argon2id immediately."})
        elif algo == "bcrypt":
            recs.append({"priority":"medium","action":"consider_argon2id",
                         "detail":"Argon2id preferred for new deployments."})

        if algo in ("argon2i","argon2id"):
            if params.get("memory_kb",0) < 65536:
                recs.append({"priority":"high","action":"increase_memory_cost",
                             "detail":f"memory={params.get('memory_kb')}KB. Recommend ≥65536KB."})
            if params.get("time_cost",0) < 2:
                recs.append({"priority":"high","action":"increase_time_cost",
                             "detail":f"time_cost={params.get('time_cost')}. Recommend ≥2."})

        if pool < 10:
            recs.append({"priority":"medium","action":"increase_honey_pool",
                         "detail":f"Pool={pool}. Recommend ≥10."})

        if jtr and jtr.get("cracked",0) > 0:
            recs.append({"priority":"critical","action":"trigger_rehash",
                         "detail":f"JtR cracked {jtr['cracked']}/{jtr['total_hashes']} hashes. Rehash required."})
        elif lvl in ("critical","weak"):
            recs.append({"priority":"high","action":"trigger_rehash",
                         "detail":"Score below threshold. Schedule rehash."})

        return recs

    # ── Util ───────────────────────────────────────────────────────────────

    def _find_wordlist(self) -> str | None:
        root = Path(__file__).parent.parent
        for p in [
            root/"data"/"sample_1000.txt",
            root/"data"/"common-passwords.txt",
            root/"data_rockyou"/"rockyou_top_10000.txt",
        ]:
            if p.exists():
                return str(p)
        return None

    def _human(self, s: float) -> str:
        if s < 1:        return "< 1 second"
        if s < 60:       return f"{int(s)} seconds"
        if s < 3600:     return f"{s/60:.1f} minutes"
        if s < 86400:    return f"{s/3600:.1f} hours"
        if s < 31536000: return f"{s/86400:.1f} days"
        y = s/31536000
        return f"{y:,.0f} years" if y < 1e6 else f"{y:.2e} years"

    def _gen_id(self, username) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        return f"rpt_{username[:8]}_{ts}"

    def _save(self, report: dict):
        (REPORTS_DIR / f"{report['report_id']}.json").write_text(json.dumps(report, indent=2))
        with open(REPORTS_DIR / "all_reports.jsonl", "a") as f:
            f.write(json.dumps(report) + "\n")