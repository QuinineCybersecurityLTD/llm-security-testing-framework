"""
Retest Module — Live Retest & Verification Runner
Re-executes specific failed attacks to verify remediation, with full CLI support.

CLI Usage:
    python retest.py --retest Q9-LLM-PI-001,Q9-LLM-JB-003 --config config_local.yaml
    python retest.py --retest-all-critical --config config_local.yaml
    python retest.py --retest Q9-LLM-PI-001 --output ./retest_reports
"""

import asyncio
import json
import sqlite3
import sys
import os
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path
from enum import Enum


@dataclass
class RetestResult:
    """Result of a single retest execution."""
    attack_id: str
    category: str
    original_classification: str
    retest_classification: str
    original_score: float
    retest_score: float
    is_fixed: bool
    remediation_verified: bool
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "attack_id": self.attack_id,
            "category": self.category,
            "original": self.original_classification,
            "retest": self.retest_classification,
            "original_score": self.original_score,
            "retest_score": self.retest_score,
            "is_fixed": self.is_fixed,
            "remediation_verified": self.remediation_verified,
            "timestamp": self.timestamp,
            "notes": self.notes,
        }


class RemediationStatus(Enum):
    FIXED = "fixed"
    PARTIALLY_FIXED = "partially_fixed"
    NOT_FIXED = "not_fixed"
    REGRESSED = "regressed"


@dataclass
class VerificationReport:
    """Full verification/retest report."""
    test_id: str
    model_id: str
    baseline_test_id: str
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    results: List[RetestResult] = field(default_factory=list)

    @property
    def fixed_count(self) -> int:
        return sum(1 for r in self.results if r.is_fixed)

    @property
    def not_fixed_count(self) -> int:
        return sum(1 for r in self.results if not r.is_fixed)

    @property
    def fix_rate(self) -> float:
        return (self.fixed_count / len(self.results) * 100) if self.results else 0.0

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "model_id": self.model_id,
            "baseline_test_id": self.baseline_test_id,
            "generated_at": self.generated_at,
            "summary": {
                "total_retested": len(self.results),
                "fixed": self.fixed_count,
                "not_fixed": self.not_fixed_count,
                "fix_rate": f"{self.fix_rate:.1f}%",
            },
            "results": [r.to_dict() for r in self.results],
        }


class RetestModule:
    """
    Re-execute specific attacks to verify remediation.
    
    This module integrates with the existing framework to:
    1. Load historical results from SQLite
    2. Re-run specific attacks against the model
    3. Compare before/after classifications
    4. Generate a verification report
    """

    def __init__(self, framework=None, db_path: str = "security_metrics.db"):
        self.framework = framework
        self.db_path = db_path

    def get_critical_failures(self, test_id: str) -> List[str]:
        """Get attack IDs that were FULL_COMPLIANCE with HIGH/CRITICAL threat."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT attack_id FROM attack_results "
                "WHERE test_id = ? AND classification = 'FULL_COMPLIANCE' "
                "AND threat_level IN ('high', 'critical', 'HIGH', 'CRITICAL')",
                (test_id,),
            ).fetchall()
        return [row[0] for row in rows]

    def get_all_failures(self, test_id: str) -> List[str]:
        """Get all attack IDs that were not REFUSED."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT attack_id FROM attack_results "
                "WHERE test_id = ? AND classification != 'REFUSED'",
                (test_id,),
            ).fetchall()
        return [row[0] for row in rows]

    def _get_baseline_result(self, test_id: str, attack_id: str) -> Optional[dict]:
        """Fetch baseline result for a specific attack."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT classification, semantic_score, category, threat_level "
                "FROM attack_results WHERE test_id = ? AND attack_id = ?",
                (test_id, attack_id),
            ).fetchone()
        if row:
            return dict(row)
        return None

    def _classify_remediation(
        self, original_cls: str, retest_cls: str
    ) -> RemediationStatus:
        """Determine remediation status from classification change."""
        severity = {"REFUSED": 0, "PARTIAL_COMPLIANCE": 1, "FULL_COMPLIANCE": 2}
        orig = severity.get(original_cls, 1)
        ret = severity.get(retest_cls, 1)

        if ret == 0:
            return RemediationStatus.FIXED
        elif ret < orig:
            return RemediationStatus.PARTIALLY_FIXED
        elif ret > orig:
            return RemediationStatus.REGRESSED
        else:
            return RemediationStatus.NOT_FIXED

    async def retest_attacks(
        self,
        attack_ids: List[str],
        model_id: str,
        baseline_test_id: str,
    ) -> VerificationReport:
        """
        Re-execute specific attacks and generate verification report.

        Args:
            attack_ids: List of attack IDs to retest
            model_id: Target model identifier
            baseline_test_id: Original test session ID for comparison
        """
        import uuid

        retest_id = f"retest-{uuid.uuid4().hex[:8]}"
        report = VerificationReport(
            test_id=retest_id,
            model_id=model_id,
            baseline_test_id=baseline_test_id,
        )

        if not self.framework:
            raise RuntimeError("Framework not initialised. Pass framework instance to RetestModule.")

        if not self.framework._initialized:
            await self.framework.initialize()

        print(f"\n{'='*60}")
        print("🔄 RETEST MODULE — Verification Run".center(60))
        print(f"{'='*60}")
        print(f"  Baseline:  {baseline_test_id}")
        print(f"  Retest ID: {retest_id}")
        print(f"  Attacks:   {len(attack_ids)}")
        print(f"  Model:     {model_id}\n")

        for i, aid in enumerate(attack_ids, 1):
            baseline = self._get_baseline_result(baseline_test_id, aid)
            original_cls = baseline["classification"] if baseline else "UNKNOWN"
            original_score = baseline.get("semantic_score", 0.0) if baseline else 0.0
            category = baseline.get("category", "UNKNOWN") if baseline else "UNKNOWN"

            print(f"  [{i}/{len(attack_ids)}] Retesting {aid}...", end=" ", flush=True)

            try:
                # Re-execute the attack through the framework
                attack = self.framework.attack_library.get_attack(aid)
                if not attack:
                    print(f"⚠ Attack not found in library, skipping")
                    continue

                attack_result, eval_result = await self.framework._execute_single_attack(
                    attack, model_id, retest_id, i, len(attack_ids)
                )

                retest_cls = eval_result.classification.value
                retest_score = float(eval_result.score) if eval_result.score else 0.0
                status = self._classify_remediation(original_cls, retest_cls)

                result = RetestResult(
                    attack_id=aid,
                    category=category,
                    original_classification=original_cls,
                    retest_classification=retest_cls,
                    original_score=original_score,
                    retest_score=retest_score,
                    is_fixed=(status == RemediationStatus.FIXED),
                    remediation_verified=(status in (RemediationStatus.FIXED, RemediationStatus.PARTIALLY_FIXED)),
                    notes=f"Status: {status.value}",
                )
                report.results.append(result)

            except Exception as e:
                print(f"✗ Error: {e}")
                result = RetestResult(
                    attack_id=aid,
                    category=category,
                    original_classification=original_cls,
                    retest_classification="ERROR",
                    original_score=original_score,
                    retest_score=0.0,
                    is_fixed=False,
                    remediation_verified=False,
                    notes=f"Retest error: {str(e)}",
                )
                report.results.append(result)

        return report

    def save_report(self, report: VerificationReport, output_dir: str = "./reports") -> str:
        """Save verification report as JSON."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"retest_{report.test_id}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        return str(path)

    def print_summary(self, report: VerificationReport) -> None:
        """Print verification summary."""
        print(f"\n{'='*60}")
        print("✅ RETEST VERIFICATION SUMMARY".center(60))
        print(f"{'='*60}")
        print(f"  Baseline: {report.baseline_test_id}")
        print(f"  Retest:   {report.test_id}")
        print(f"  Total:    {len(report.results)}")
        print(f"  Fixed:    {report.fixed_count} ({report.fix_rate:.1f}%)")
        print(f"  Not Fixed: {report.not_fixed_count}")

        for r in report.results:
            icon = "✓" if r.is_fixed else "✗"
            print(f"    {icon} {r.attack_id}: {r.original_classification} → {r.retest_classification} ({r.notes})")
        print(f"{'='*60}\n")


# ═══════════════════════════════════════════════════════════════════════
# CLI Interface
# ═══════════════════════════════════════════════════════════════════════

async def cli_main():
    """CLI entry point for retest module."""
    args = sys.argv[1:]
    config_path = None
    attack_ids = []
    retest_all_critical = False
    baseline_test_id = None
    model_id = None
    output_dir = "./reports"

    for i, arg in enumerate(args):
        if arg.startswith("--retest="):
            attack_ids = arg.split("=", 1)[1].split(",")
        elif arg == "--retest-all-critical":
            retest_all_critical = True
        elif arg.startswith("--config="):
            config_path = arg.split("=", 1)[1]
        elif arg.startswith("--baseline="):
            baseline_test_id = arg.split("=", 1)[1]
        elif arg.startswith("--model="):
            model_id = arg.split("=", 1)[1]
        elif arg.startswith("--output="):
            output_dir = arg.split("=", 1)[1]

    if not baseline_test_id:
        print("❌ --baseline=<test_id> is required")
        sys.exit(1)

    # Import and create framework
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from main import LLMSecurityTestFramework

    framework = LLMSecurityTestFramework(config_path=config_path)
    retest = RetestModule(framework=framework)

    if retest_all_critical:
        attack_ids = retest.get_critical_failures(baseline_test_id)
        if not attack_ids:
            print("ℹ No critical failures found in baseline. Nothing to retest.")
            return

    if not attack_ids:
        print("❌ No attack IDs specified. Use --retest=ID1,ID2 or --retest-all-critical")
        sys.exit(1)

    if not model_id:
        # Use first target from config
        targets = framework.config.get("targets", [])
        model_id = targets[0]["name"] if targets else None
        if not model_id:
            print("❌ No model specified and no targets in config")
            sys.exit(1)

    report = await retest.retest_attacks(attack_ids, model_id, baseline_test_id)
    path = retest.save_report(report, output_dir)
    retest.print_summary(report)
    print(f"📄 Report saved: {path}")


if __name__ == "__main__":
    asyncio.run(cli_main())
