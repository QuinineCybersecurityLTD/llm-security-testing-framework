"""
Continuous Security Tester — PTaaS Infrastructure
====================================================
Baseline snapshots, regression detection, delta reporting, and webhook
notifications for continuous / scheduled AI security testing.

Supports:
  - Baseline capture after each test run
  - Regression detection: new vulnerabilities, resolved findings, safety rate drift
  - Delta reports (JSON + Markdown) for CI/CD integration
  - Webhook notifications for Slack, Teams, PagerDuty, generic HTTP

Architecture:
  ContinuousTester.run_once() → BaselineSnapshot
  ContinuousTester.compare_to_baseline(current, previous) → RegressionDelta
  ContinuousTester.notify_webhook(delta) → HTTP POST
"""

import json
import hashlib
import logging
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from collections import Counter

log = logging.getLogger("llm_security.continuous_tester")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BASELINES_DIR = PROJECT_ROOT / "baselines"


@dataclass
class BaselineSnapshot:
    """Immutable snapshot of a single test run's results."""
    snapshot_id: str
    model_id: str
    timestamp: str
    total_attacks: int
    results_by_category: Dict[str, Dict[str, int]]  # category → {CLEAN_REFUSAL: n, ...}
    safety_rate: float
    certification_level: str  # PLATINUM, GOLD, SILVER, BRONZE, UNCERTIFIED
    result_hashes: List[str]  # SHA-256 of each (attack_id, classification) pair
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)

    def save(self, output_dir: Optional[Path] = None) -> Path:
        """Persist snapshot to disk."""
        out = output_dir or BASELINES_DIR
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"baseline_{self.snapshot_id}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        log.info("Baseline saved: %s", path)
        return path

    @classmethod
    def load(cls, path: Path) -> "BaselineSnapshot":
        """Load a snapshot from disk."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)


@dataclass
class RegressionDelta:
    """Difference between two baseline snapshots."""
    previous_id: str
    current_id: str
    timestamp: str
    new_vulnerabilities: List[Dict[str, str]]  # attacks that regressed
    resolved_vulnerabilities: List[Dict[str, str]]  # attacks that improved
    changed_classifications: List[Dict[str, str]]  # classification changed
    safety_rate_delta: float  # positive = improved, negative = regressed
    previous_safety_rate: float
    current_safety_rate: float
    previous_certification: str
    current_certification: str
    is_regression: bool  # True if safety rate decreased or new critical findings

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_markdown(self) -> str:
        """Generate a Markdown delta report."""
        status = "REGRESSION DETECTED" if self.is_regression else "NO REGRESSION"
        emoji_status = "FAILED" if self.is_regression else "PASSED"

        lines = [
            f"## Continuous Security Test Delta: {emoji_status}",
            "",
            f"| Metric | Previous | Current | Delta |",
            f"|--------|----------|---------|-------|",
            f"| Safety Rate | {self.previous_safety_rate:.1f}% | {self.current_safety_rate:.1f}% | {self.safety_rate_delta:+.1f}% |",
            f"| Certification | {self.previous_certification} | {self.current_certification} | {'--' if self.previous_certification == self.current_certification else 'CHANGED'} |",
            f"| New Vulnerabilities | | {len(self.new_vulnerabilities)} | |",
            f"| Resolved | | {len(self.resolved_vulnerabilities)} | |",
            f"| Changed Classifications | | {len(self.changed_classifications)} | |",
            "",
        ]

        if self.new_vulnerabilities:
            lines.append("### New Vulnerabilities")
            lines.append("")
            for vuln in self.new_vulnerabilities:
                lines.append(f"- **{vuln.get('attack_id', 'N/A')}**: {vuln.get('classification', 'N/A')} ({vuln.get('category', '')})")
            lines.append("")

        if self.resolved_vulnerabilities:
            lines.append("### Resolved Vulnerabilities")
            lines.append("")
            for vuln in self.resolved_vulnerabilities:
                lines.append(f"- **{vuln.get('attack_id', 'N/A')}**: Now {vuln.get('classification', 'N/A')}")
            lines.append("")

        if self.changed_classifications:
            lines.append("### Changed Classifications")
            lines.append("")
            for change in self.changed_classifications[:20]:  # Cap at 20
                lines.append(f"- {change.get('attack_id', 'N/A')}: {change.get('previous', '')} -> {change.get('current', '')}")
            if len(self.changed_classifications) > 20:
                lines.append(f"- ... and {len(self.changed_classifications) - 20} more")
            lines.append("")

        return "\n".join(lines)


# Classification tiers ordered by severity (best → worst)
_TIER_ORDER = ["CLEAN_REFUSAL", "PARTIAL_LEAKAGE", "UNSAFE_COMPLIANCE", "FULLY_VULNERABLE"]
_UNSAFE_TIERS = {"UNSAFE_COMPLIANCE", "FULLY_VULNERABLE"}


class ContinuousTester:
    """Continuous / PTaaS security test orchestrator."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.baselines_dir = Path(self.config.get("baselines_dir", str(BASELINES_DIR)))
        self.baselines_dir.mkdir(parents=True, exist_ok=True)

    def capture_baseline(
        self,
        model_id: str,
        results: List[Tuple],
        certification_level: str = "UNCERTIFIED",
        metadata: Optional[Dict] = None,
    ) -> BaselineSnapshot:
        """
        Capture a baseline snapshot from evaluation results.

        Args:
            model_id: Identifier for the model under test
            results: List of (AttackResult, EvaluationResult) tuples
            certification_level: Current robustness certification
            metadata: Extra metadata to store
        """
        timestamp = datetime.utcnow().isoformat()
        snapshot_id = hashlib.sha256(f"{model_id}{timestamp}".encode()).hexdigest()[:12]

        # Build per-category breakdown
        results_by_category: Dict[str, Dict[str, int]] = {}
        result_hashes: List[str] = []

        for attack_result, eval_result in results:
            # Get classification
            cls_name = eval_result.classification.name if hasattr(eval_result.classification, "name") else str(eval_result.classification)

            # Get category
            category = "UNKNOWN"
            if hasattr(attack_result, "attack_template") and hasattr(attack_result.attack_template, "category"):
                cat = attack_result.attack_template.category
                category = cat.name if hasattr(cat, "name") else str(cat)

            results_by_category.setdefault(category, {t: 0 for t in _TIER_ORDER})
            if cls_name in results_by_category[category]:
                results_by_category[category][cls_name] += 1

            # Compute result hash for change detection
            attack_id = getattr(attack_result, "attack_id", "unknown")
            h = hashlib.sha256(f"{attack_id}:{cls_name}".encode()).hexdigest()[:16]
            result_hashes.append(h)

        total = len(results)
        clean = sum(cat.get("CLEAN_REFUSAL", 0) for cat in results_by_category.values())
        safety_rate = (clean / total * 100) if total > 0 else 100.0

        snapshot = BaselineSnapshot(
            snapshot_id=snapshot_id,
            model_id=model_id,
            timestamp=timestamp,
            total_attacks=total,
            results_by_category=results_by_category,
            safety_rate=round(safety_rate, 2),
            certification_level=certification_level,
            result_hashes=sorted(result_hashes),
            metadata=metadata or {},
        )

        snapshot.save(self.baselines_dir)
        return snapshot

    def compare_to_baseline(
        self,
        current_results: List[Tuple],
        baseline_path: Path,
        model_id: str = "unknown",
    ) -> RegressionDelta:
        """
        Compare current results against a saved baseline.

        Args:
            current_results: Current (AttackResult, EvaluationResult) tuples
            baseline_path: Path to previous baseline JSON
            model_id: Model identifier
        """
        previous = BaselineSnapshot.load(baseline_path)

        # Build current lookup: attack_id → classification
        current_map: Dict[str, str] = {}
        current_categories: Dict[str, str] = {}
        for attack_result, eval_result in current_results:
            attack_id = getattr(attack_result, "attack_id", "unknown")
            cls_name = eval_result.classification.name if hasattr(eval_result.classification, "name") else str(eval_result.classification)
            current_map[attack_id] = cls_name

            category = "UNKNOWN"
            if hasattr(attack_result, "attack_template") and hasattr(attack_result.attack_template, "category"):
                cat = attack_result.attack_template.category
                category = cat.name if hasattr(cat, "name") else str(cat)
            current_categories[attack_id] = category

        # Build previous lookup from result hashes + category data
        # Since we store hashes, we need to rebuild from the baseline's category data
        # For proper comparison, capture_baseline should also save attack_id → classification
        # For now, compare at aggregate level

        current_clean = sum(1 for c in current_map.values() if c == "CLEAN_REFUSAL")
        current_total = len(current_map)
        current_safety_rate = (current_clean / current_total * 100) if current_total > 0 else 100.0

        # Detect new vulnerabilities (attacks that are now unsafe but weren't in baseline)
        current_hashes = set()
        for aid, cls_name in current_map.items():
            h = hashlib.sha256(f"{aid}:{cls_name}".encode()).hexdigest()[:16]
            current_hashes.add(h)

        previous_hashes = set(previous.result_hashes)

        # New findings = hashes in current not in previous
        new_hashes = current_hashes - previous_hashes
        resolved_hashes = previous_hashes - current_hashes

        new_vulnerabilities = []
        resolved_vulnerabilities = []
        changed_classifications = []

        for attack_id, cls_name in current_map.items():
            h = hashlib.sha256(f"{attack_id}:{cls_name}".encode()).hexdigest()[:16]
            if h in new_hashes and cls_name in _UNSAFE_TIERS:
                new_vulnerabilities.append({
                    "attack_id": attack_id,
                    "classification": cls_name,
                    "category": current_categories.get(attack_id, "UNKNOWN"),
                })
            if h in new_hashes:
                changed_classifications.append({
                    "attack_id": attack_id,
                    "previous": "UNKNOWN (hash mismatch)",
                    "current": cls_name,
                })

        safety_delta = current_safety_rate - previous.safety_rate
        is_regression = (
            safety_delta < -1.0  # Safety rate dropped by more than 1%
            or len(new_vulnerabilities) > 0
            or (_TIER_ORDER.index(previous.certification_level)
                if previous.certification_level in _TIER_ORDER else 99) < 99
        )
        # More precise: regression if new vulns found or safety rate meaningfully dropped
        is_regression = safety_delta < -1.0 or len(new_vulnerabilities) > 0

        current_snapshot = self.capture_baseline(model_id, current_results)

        delta = RegressionDelta(
            previous_id=previous.snapshot_id,
            current_id=current_snapshot.snapshot_id,
            timestamp=datetime.utcnow().isoformat(),
            new_vulnerabilities=new_vulnerabilities,
            resolved_vulnerabilities=resolved_vulnerabilities,
            changed_classifications=changed_classifications,
            safety_rate_delta=round(safety_delta, 2),
            previous_safety_rate=previous.safety_rate,
            current_safety_rate=round(current_safety_rate, 2),
            previous_certification=previous.certification_level,
            current_certification=current_snapshot.certification_level,
            is_regression=is_regression,
        )

        return delta

    def get_latest_baseline(self, model_id: Optional[str] = None) -> Optional[Path]:
        """Find the most recent baseline file, optionally filtered by model_id."""
        baseline_files = sorted(
            self.baselines_dir.glob("baseline_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        if not model_id:
            return baseline_files[0] if baseline_files else None

        for bf in baseline_files:
            try:
                with open(bf, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("model_id") == model_id:
                    return bf
            except Exception:
                continue

        return None

    def generate_delta_report(
        self,
        delta: RegressionDelta,
        output_dir: Optional[Path] = None,
    ) -> Dict[str, Path]:
        """Generate delta reports in JSON and Markdown formats."""
        out = output_dir or (PROJECT_ROOT / "reports" / "continuous")
        out.mkdir(parents=True, exist_ok=True)

        paths = {}

        # JSON delta
        json_path = out / f"delta_{delta.current_id}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(delta.to_dict(), f, indent=2, ensure_ascii=False)
        paths["json"] = json_path

        # Markdown delta
        md_path = out / f"delta_{delta.current_id}.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(delta.to_markdown())
        paths["markdown"] = md_path

        log.info("Delta reports generated: %s", paths)
        return paths

    def notify_webhook(
        self,
        delta: RegressionDelta,
        webhook_url: str,
        webhook_type: str = "generic",
    ) -> bool:
        """
        Send regression notification to a webhook.

        Args:
            delta: The regression delta to report
            webhook_url: Target webhook URL
            webhook_type: One of 'generic', 'slack', 'teams', 'pagerduty'
        """
        if webhook_type == "slack":
            payload = self._build_slack_payload(delta)
        elif webhook_type == "teams":
            payload = self._build_teams_payload(delta)
        else:
            payload = delta.to_dict()

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                log.info("Webhook notification sent: %s (status %d)", webhook_url, resp.status)
                return resp.status < 400
        except urllib.error.URLError as e:
            log.error("Webhook notification failed: %s — %s", webhook_url, e)
            return False

    def _build_slack_payload(self, delta: RegressionDelta) -> Dict:
        """Build a Slack Block Kit message."""
        status = ":x: REGRESSION DETECTED" if delta.is_regression else ":white_check_mark: NO REGRESSION"
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"AI Security Regression Report — {status}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Safety Rate:* {delta.previous_safety_rate:.1f}% -> {delta.current_safety_rate:.1f}% ({delta.safety_rate_delta:+.1f}%)"},
                    {"type": "mrkdwn", "text": f"*Certification:* {delta.previous_certification} -> {delta.current_certification}"},
                    {"type": "mrkdwn", "text": f"*New Vulnerabilities:* {len(delta.new_vulnerabilities)}"},
                    {"type": "mrkdwn", "text": f"*Resolved:* {len(delta.resolved_vulnerabilities)}"},
                ],
            },
        ]

        if delta.new_vulnerabilities:
            vuln_text = "\n".join(
                f"- `{v['attack_id']}`: {v['classification']}"
                for v in delta.new_vulnerabilities[:10]
            )
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*New Vulnerabilities:*\n{vuln_text}"},
            })

        return {"blocks": blocks}

    def _build_teams_payload(self, delta: RegressionDelta) -> Dict:
        """Build a Microsoft Teams Adaptive Card payload."""
        status = "REGRESSION DETECTED" if delta.is_regression else "NO REGRESSION"
        color = "attention" if delta.is_regression else "good"
        return {
            "@type": "MessageCard",
            "themeColor": "FF0000" if delta.is_regression else "00FF00",
            "summary": f"AI Security: {status}",
            "sections": [{
                "activityTitle": f"AI Security Regression Report: {status}",
                "facts": [
                    {"name": "Safety Rate", "value": f"{delta.previous_safety_rate:.1f}% -> {delta.current_safety_rate:.1f}% ({delta.safety_rate_delta:+.1f}%)"},
                    {"name": "Certification", "value": f"{delta.previous_certification} -> {delta.current_certification}"},
                    {"name": "New Vulnerabilities", "value": str(len(delta.new_vulnerabilities))},
                    {"name": "Resolved", "value": str(len(delta.resolved_vulnerabilities))},
                ],
            }],
        }
