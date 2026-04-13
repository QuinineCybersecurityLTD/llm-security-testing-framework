"""
Comparison Reporter — Baseline Delta Comparison Module
Compares two test sessions to identify regressions, improvements, and net-new findings.
Outputs a structured delta report for CI/CD pipeline integration.
"""

import json
import sqlite3
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path

# ── Schema for delta_reports table ───────────────────────────────────────
DELTA_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS delta_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    baseline_id     TEXT NOT NULL,
    current_id      TEXT NOT NULL,
    generated_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    regressions     INTEGER DEFAULT 0,
    improvements    INTEGER DEFAULT 0,
    unchanged       INTEGER DEFAULT 0,
    net_new         INTEGER DEFAULT 0,
    delta_json      TEXT,
    FOREIGN KEY(baseline_id) REFERENCES test_sessions(test_id),
    FOREIGN KEY(current_id)  REFERENCES test_sessions(test_id)
);
"""


@dataclass
class DeltaResult:
    """Single attack comparison between baseline and current run."""
    attack_id: str
    category: str
    baseline_classification: Optional[str]
    current_classification: Optional[str]
    baseline_score: Optional[float]
    current_score: Optional[float]
    delta_type: str  # "regression", "improvement", "unchanged", "net_new"

    def to_dict(self) -> dict:
        return {
            "attack_id": self.attack_id,
            "category": self.category,
            "baseline": self.baseline_classification,
            "current": self.current_classification,
            "score_baseline": self.baseline_score,
            "score_current": self.current_score,
            "delta": self.delta_type,
        }


@dataclass
class DeltaReport:
    """Full delta comparison report between two sessions."""
    baseline_id: str
    current_id: str
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    deltas: List[DeltaResult] = field(default_factory=list)

    # ── Aggregate counts ─────────────────────────────────────────────
    @property
    def regressions(self) -> int:
        return sum(1 for d in self.deltas if d.delta_type == "regression")

    @property
    def improvements(self) -> int:
        return sum(1 for d in self.deltas if d.delta_type == "improvement")

    @property
    def unchanged(self) -> int:
        return sum(1 for d in self.deltas if d.delta_type == "unchanged")

    @property
    def net_new(self) -> int:
        return sum(1 for d in self.deltas if d.delta_type == "net_new")

    def to_dict(self) -> dict:
        return {
            "baseline_id": self.baseline_id,
            "current_id": self.current_id,
            "generated_at": self.generated_at,
            "summary": {
                "regressions": self.regressions,
                "improvements": self.improvements,
                "unchanged": self.unchanged,
                "net_new": self.net_new,
            },
            "deltas": [d.to_dict() for d in self.deltas],
        }


# ── Severity ordering for determining regression vs improvement ──────
_SEVERITY_ORDER = {
    "REFUSED": 0,
    "PARTIAL_COMPLIANCE": 1,
    "FULL_COMPLIANCE": 2,
}


class ComparisonReporter:
    """Compare two test sessions and produce a delta report."""

    def __init__(self, db_path: str = "security_metrics.db"):
        self.db_path = db_path

    # ── Internal helpers ─────────────────────────────────────────────
    def _fetch_results(self, test_id: str) -> Dict[str, dict]:
        """Fetch attack results keyed by attack_id."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT attack_id, category, classification, semantic_score "
                "FROM attack_results WHERE test_id = ?",
                (test_id,),
            ).fetchall()
        return {
            row["attack_id"]: {
                "category": row["category"],
                "classification": row["classification"],
                "score": row["semantic_score"],
            }
            for row in rows
        }

    @staticmethod
    def _classify_delta(
        baseline_cls: Optional[str], current_cls: Optional[str]
    ) -> str:
        if baseline_cls is None:
            return "net_new"
        if baseline_cls == current_cls:
            return "unchanged"
        b = _SEVERITY_ORDER.get(baseline_cls, 1)
        c = _SEVERITY_ORDER.get(current_cls, 1)
        return "regression" if c > b else "improvement"

    # ── Public API ───────────────────────────────────────────────────
    def compare(self, baseline_id: str, current_id: str) -> DeltaReport:
        """Compare two test sessions and return a DeltaReport."""
        baseline = self._fetch_results(baseline_id)
        current = self._fetch_results(current_id)

        all_attack_ids = set(baseline.keys()) | set(current.keys())
        report = DeltaReport(baseline_id=baseline_id, current_id=current_id)

        for aid in sorted(all_attack_ids):
            b = baseline.get(aid)
            c = current.get(aid)
            delta = DeltaResult(
                attack_id=aid,
                category=(c or b or {}).get("category", "UNKNOWN"),
                baseline_classification=b["classification"] if b else None,
                current_classification=c["classification"] if c else None,
                baseline_score=b["score"] if b else None,
                current_score=c["score"] if c else None,
                delta_type=self._classify_delta(
                    b["classification"] if b else None,
                    c["classification"] if c else None,
                ),
            )
            report.deltas.append(delta)

        return report

    def save_report(self, report: DeltaReport, output_dir: str = "./reports") -> str:
        """Save delta report as JSON and persist summary to SQLite."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"delta_{report.baseline_id}_vs_{report.current_id}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)

        # Persist to SQLite
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(DELTA_SCHEMA_SQL)
            conn.execute(
                "INSERT INTO delta_reports "
                "(baseline_id, current_id, regressions, improvements, unchanged, net_new, delta_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    report.baseline_id,
                    report.current_id,
                    report.regressions,
                    report.improvements,
                    report.unchanged,
                    report.net_new,
                    json.dumps(report.to_dict()),
                ),
            )
            conn.commit()

        return str(path)

    def print_summary(self, report: DeltaReport) -> None:
        """Print a human-readable summary."""
        print(f"\n{'='*60}")
        print("🔄 DELTA COMPARISON REPORT".center(60))
        print(f"{'='*60}")
        print(f"  Baseline : {report.baseline_id}")
        print(f"  Current  : {report.current_id}")
        print(f"  Generated: {report.generated_at}")
        print(f"\n  📊 Summary:")
        print(f"    🔴 Regressions  : {report.regressions}")
        print(f"    🟢 Improvements : {report.improvements}")
        print(f"    ⚪ Unchanged    : {report.unchanged}")
        print(f"    🆕 Net New      : {report.net_new}")

        if report.regressions > 0:
            print(f"\n  🚨 Regressions:")
            for d in report.deltas:
                if d.delta_type == "regression":
                    print(f"    • {d.attack_id} ({d.category}): "
                          f"{d.baseline_classification} → {d.current_classification}")
        print(f"{'='*60}\n")
