# agents/report_generator.py
"""
Report Generation System — LEAP Security System
-------------------------------------------------
Reads agent outputs and produces structured JSON reports.
Also provides helper functions for the Flask API to query reports.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPORTS_DIR  = Path(__file__).parent.parent / "reports"
ALL_REPORTS  = REPORTS_DIR / "all_reports.jsonl"
CHANGES_LOG  = REPORTS_DIR / "security_changes.jsonl"
REPORTS_DIR.mkdir(exist_ok=True)


# ── Report Builder ────────────────────────────────────────────────────────────

class ReportGenerator:
    """
    Combines a HashTestingAgent report + SecurityAgent change summary
    into one consolidated security report stored as JSON.
    """

    def generate(
        self,
        test_report: dict,
        change_summary: dict,
    ) -> dict:
        """
        Merge test + change data into a single consolidated report.
        Saved to reports/<report_id>_full.json and appended to index.
        """
        full = {
            "report_id":     test_report["report_id"],
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "username":      test_report.get("username"),
            "trigger":       test_report.get("trigger"),

            # ── Test results ───────────────────────────────────────────────
            "hash_test": {
                "algorithm":        test_report.get("algorithm"),
                "algorithm_params": test_report.get("algorithm_params"),
                "security_score":   test_report.get("security_score"),
                "security_level":   test_report.get("security_level"),
                "level_reason":     test_report.get("level_reason"),
                "estimated_crack":  test_report.get("estimated_crack_human"),
                "entropy_bits":     test_report.get("entropy_bits"),
                "honey_pool_size":  test_report.get("honey_pool_size"),
                "dictionary_probe": test_report.get("dictionary_probe"),
            },

            # ── Security changes applied ───────────────────────────────────
            "security_changes": {
                "changes_applied": change_summary.get("changes_applied", []),
                "flags":           change_summary.get("flags", []),
                "new_config":      change_summary.get("new_config", {}),
            },

            # ── Recommendations ────────────────────────────────────────────
            "recommendations": test_report.get("recommendations", []),

            # ── Meta ───────────────────────────────────────────────────────
            "agent_runtime_s": test_report.get("agent_runtime_s"),
        }

        # Save individual report
        out_path = REPORTS_DIR / f"{full['report_id']}_full.json"
        with open(out_path, "w") as f:
            json.dump(full, f, indent=2)

        # Append to index file
        index_path = REPORTS_DIR / "report_index.jsonl"
        with open(index_path, "a") as f:
            f.write(json.dumps({
                "report_id":     full["report_id"],
                "generated_at":  full["generated_at"],
                "username":      full["username"],
                "trigger":       full["trigger"],
                "security_level": full["hash_test"]["security_level"],
                "security_score": full["hash_test"]["security_score"],
                "changes_count":  len(full["security_changes"]["changes_applied"]),
            }) + "\n")

        return full

    # ── Query helpers (used by Flask API) ─────────────────────────────────

    def get_latest_report(self, username: str | None = None) -> dict | None:
        """Return the most recent full report (optionally filtered by user)."""
        index_path = REPORTS_DIR / "report_index.jsonl"
        if not index_path.exists():
            return None

        lines  = index_path.read_text().strip().split("\n")
        entries = [json.loads(l) for l in lines if l.strip()]
        if username:
            entries = [e for e in entries if e.get("username") == username]
        if not entries:
            return None

        latest = entries[-1]
        full_path = REPORTS_DIR / f"{latest['report_id']}_full.json"
        if full_path.exists():
            with open(full_path) as f:
                return json.load(f)
        return latest

    def get_report_history(self, limit: int = 50, username: str | None = None) -> list[dict]:
        """Return a list of summary entries from the index (newest first)."""
        index_path = REPORTS_DIR / "report_index.jsonl"
        if not index_path.exists():
            return []
        lines   = [l for l in index_path.read_text().strip().split("\n") if l.strip()]
        entries = []
        for l in lines:
            try:
                entries.append(json.loads(l))
            except Exception:
                continue
        if username:
            entries = [e for e in entries if e.get("username") == username]
        return entries[-limit:][::-1]

    def get_system_summary(self) -> dict:
        """Aggregate stats across all reports — used by the dashboard."""
        history = self.get_report_history(limit=500)
        if not history:
            return {
                "total_reports": 0,
                "level_counts": {},
                "avg_score": 0,
                "total_changes": 0,
                "latest": None,
            }

        level_counts: dict[str, int] = {}
        total_score   = 0
        total_changes = 0

        for e in history:
            lvl = e.get("security_level", "unknown")
            level_counts[lvl] = level_counts.get(lvl, 0) + 1
            total_score  += e.get("security_score", 0)
            total_changes += e.get("changes_count", 0)

        return {
            "total_reports":  len(history),
            "level_counts":   level_counts,
            "avg_score":      round(total_score / len(history), 1),
            "total_changes":  total_changes,
            "latest":         history[0] if history else None,
        }

    def get_change_history(self, limit: int = 20) -> list[dict]:
        """Return recent security changes from security_changes.jsonl."""
        if not CHANGES_LOG.exists():
            return []
        lines = [l for l in CHANGES_LOG.read_text().strip().split("\n") if l.strip()]
        out = []
        for l in lines:
            try:
                out.append(json.loads(l))
            except Exception:
                continue
        return out[-limit:][::-1]