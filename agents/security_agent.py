# agents/security_agent.py
"""
Security Posture Improvement Agent — LEAP Security System
-----------------------------------------------------------
Reads reports from the Hash Testing Agent, applies security
improvements, logs all changes, and never breaks existing users.
Rule-based — no paid APIs required.
"""

import json
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

REPORTS_DIR  = Path(__file__).parent.parent / "reports"
CHANGES_LOG  = REPORTS_DIR / "security_changes.jsonl"
REPORTS_DIR.mkdir(exist_ok=True)

logger = logging.getLogger("security_agent")

# ── Security Config (current live settings) ───────────────────────────────────

DEFAULT_CONFIG = {
    "algorithm":    "argon2id",
    "memory_kb":    65536,
    "time_cost":    2,
    "parallelism":  1,
    "honey_count":  9,         # decoys per user
    "min_password_length": 8,
    "require_digit":        True,
    "require_upper":        False,
    "version":      1,
}

CONFIG_PATH = REPORTS_DIR / "security_config.json"


def load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return DEFAULT_CONFIG.copy()


def save_config(cfg: dict):
    cfg["updated_at"] = datetime.now(timezone.utc).isoformat()
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


# ── Agent ─────────────────────────────────────────────────────────────────────

class SecurityAgent:
    """
    Reads the latest test report and applies graduated improvements:
      critical  → force algorithm upgrade + rehash flag
      weak      → increase parameters
      moderate  → suggest improvements, increase honey pool
      strong+   → no action
    """

    def __init__(self):
        self.config = load_config()

    # ── Public API ──────────────────────────────────────────────────────────

    def analyze_and_improve(self, report: dict) -> dict:
        """
        Main entry point. Takes a HashTestingAgent report dict.
        Returns a change summary dict.
        """
        level   = report.get("security_level", "unknown")
        score   = report.get("security_score", 0)
        recs    = report.get("recommendations", [])
        algo    = report.get("algorithm", "unknown")
        params  = report.get("algorithm_params", {})
        pool    = report.get("honey_pool_size", 9)

        changes_applied = []
        flags           = []

        # ── 1. Critical — algorithm is broken ───────────────────────────────
        if level == "critical" or algo in ("md5", "sha256", "unknown"):
            change = self._upgrade_algorithm("argon2id")
            if change:
                changes_applied.append(change)
                flags.append("rehash_required")

        # ── 2. Weak — tighten parameters ────────────────────────────────────
        elif level == "weak":
            if self.config["algorithm"] in ("argon2i", "argon2id"):
                # Bump memory by one step (×2)
                new_mem = min(self.config["memory_kb"] * 2, 262144)  # cap 256 MB
                if new_mem > self.config["memory_kb"]:
                    changes_applied.append(self._update_param("memory_kb", self.config["memory_kb"], new_mem))

                new_tc = min(self.config["time_cost"] + 1, 6)
                if new_tc > self.config["time_cost"]:
                    changes_applied.append(self._update_param("time_cost", self.config["time_cost"], new_tc))

            elif self.config["algorithm"] == "bcrypt":
                # Bump cost factor
                old_rounds = self.config.get("bcrypt_rounds", 12)
                new_rounds = min(old_rounds + 1, 15)
                if new_rounds > old_rounds:
                    changes_applied.append(self._update_param("bcrypt_rounds", old_rounds, new_rounds))

            flags.append("rehash_recommended")

        # ── 3. Moderate — expand honey pool if small ────────────────────────
        elif level == "moderate":
            if pool < 10:
                old_count = self.config["honey_count"]
                new_count = min(old_count + 2, 19)
                if new_count > old_count:
                    changes_applied.append(self._update_param("honey_count", old_count, new_count))

        # ── 4. Always check password policy from recs ───────────────────────
        for rec in recs:
            if rec["action"] == "enforce_password_policy":
                change = self._enforce_policy(rec.get("detail", ""))
                if change:
                    changes_applied.append(change)

        # ── Persist changes ─────────────────────────────────────────────────
        if changes_applied:
            save_config(self.config)

        summary = {
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "report_id":        report.get("report_id", "unknown"),
            "username":         report.get("username", "unknown"),
            "trigger_level":    level,
            "score_before":     score,
            "changes_applied":  changes_applied,
            "flags":            flags,
            "new_config":       self.config.copy(),
        }
        self._log_change(summary)
        return summary

    # ── Improvement actions ─────────────────────────────────────────────────

    def _upgrade_algorithm(self, target_algo: str) -> dict | None:
        if self.config["algorithm"] == target_algo:
            return None
        old = self.config["algorithm"]
        self.config["algorithm"] = target_algo
        # Reset to recommended defaults
        self.config["memory_kb"]   = 65536
        self.config["time_cost"]   = 2
        self.config["parallelism"] = 1
        return {
            "action":   "upgrade_algorithm",
            "from":     old,
            "to":       target_algo,
            "reason":   f"{old} is insufficiently secure. Upgraded to {target_algo}.",
        }

    def _update_param(self, key: str, old_val, new_val) -> dict:
        self.config[key] = new_val
        return {
            "action":   f"update_{key}",
            "from":     old_val,
            "to":       new_val,
            "reason":   f"Security posture improvement: {key} increased.",
        }

    def _enforce_policy(self, detail: str) -> dict | None:
        changed = False
        if "length" in detail.lower() and self.config["min_password_length"] < 12:
            self.config["min_password_length"] = 12
            changed = True
        if "upper" in detail.lower() and not self.config.get("require_upper"):
            self.config["require_upper"] = True
            changed = True
        if changed:
            return {
                "action": "enforce_password_policy",
                "detail": detail,
                "reason": "Weak password detected in testing. Policy hardened.",
            }
        return None

    # ── Utility ─────────────────────────────────────────────────────────────

    def _log_change(self, summary: dict):
        with open(CHANGES_LOG, "a") as f:
            f.write(json.dumps(summary) + "\n")

    def get_change_history(self, limit: int = 20) -> list[dict]:
        if not CHANGES_LOG.exists():
            return []
        lines = CHANGES_LOG.read_text().strip().split("\n")
        parsed = []
        for line in lines:
            try:
                parsed.append(json.loads(line))
            except Exception:
                continue
        return parsed[-limit:][::-1]  # newest first


# ── Standalone test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    agent = SecurityAgent()
    fake_report = {
        "report_id":      "rpt_testuser_001",
        "username":       "testuser",
        "algorithm":      "sha256",
        "algorithm_params": {},
        "security_level": "critical",
        "security_score": 10,
        "honey_pool_size": 5,
        "recommendations": [
            {"action": "upgrade_algorithm", "priority": "critical",
             "detail": "Switch to Argon2id"},
        ],
    }
    result = agent.analyze_and_improve(fake_report)
    print(json.dumps(result, indent=2))