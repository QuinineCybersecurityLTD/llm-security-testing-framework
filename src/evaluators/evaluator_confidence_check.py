"""
Evaluator Confidence Check — Day 4
Select 5 high-risk + 5 low-risk outputs, present for manual review,
and document false positives, false negatives, and misclassifications.

Usage:
    cd src
    python evaluator_confidence_check.py
    python evaluator_confidence_check.py --results-dir ../logs --output ../reports/confidence_check.json
"""

import sys, os
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    if sys.stdout.encoding != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding != "utf-8":
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


# ═══════════════════════════════════════════════════════════════════════
class EvaluatorConfidenceCheck:
    """
    Sample 5 high-risk + 5 low-risk outputs from evaluator results.
    Present each for manual review and document:
      • False Positives (flagged harmful but actually safe)
      • False Negatives (marked safe but actually harmful)
      • Misclassifications (wrong tier/severity)
    """

    def __init__(self, results_dir: str = None):
        self.results_dir = Path(results_dir or (PROJECT_ROOT / "logs"))

    def _load_results(self) -> List[Dict[str, Any]]:
        """Load latest evaluator results JSONL."""
        results = []

        jsonl_files = sorted(
            self.results_dir.glob("evaluator_results_*.jsonl"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        if not jsonl_files:
            # Try RAG run logs as fallback
            jsonl_files = sorted(
                self.results_dir.glob("rag_run_log_*.jsonl"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )

        if not jsonl_files:
            print("  ⚠ No evaluator results found.")
            return results

        latest = jsonl_files[0]
        print(f"  → Loading: {latest.name}")

        with open(latest, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        return results

    def _classify_risk(self, result: Dict) -> str:
        """Classify a result as high-risk or low-risk."""
        # Check multiple possible field names
        threat = (
            result.get("threat_level", "")
            or result.get("evaluator_classification", {}).get("threat_level", "")
        ).lower()

        classification = (
            result.get("classification", "")
            or result.get("four_tier", "")
            or result.get("evaluator_classification", {}).get("three_class", "")
        ).upper()

        if threat in ("critical", "high") or classification in (
            "FULL_COMPLIANCE", "FULLY_VULNERABLE", "UNSAFE_COMPLIANCE"
        ):
            return "HIGH"
        return "LOW"

    def sample(self, results: List[Dict] = None) -> Dict[str, List[Dict]]:
        """Sample 5 high-risk + 5 low-risk outputs."""
        if results is None:
            results = self._load_results()

        high_risk = [r for r in results if self._classify_risk(r) == "HIGH"]
        low_risk = [r for r in results if self._classify_risk(r) == "LOW"]

        # Sort high-risk by score (ascending = worst first)
        high_risk.sort(key=lambda r: r.get("score", r.get("evaluator_classification", {}).get("score", 50)))
        # Sort low-risk by score (descending = safest first)
        low_risk.sort(key=lambda r: r.get("score", r.get("evaluator_classification", {}).get("score", 50)), reverse=True)

        sampled_high = high_risk[:5]
        sampled_low = low_risk[:5]

        return {"high_risk": sampled_high, "low_risk": sampled_low}

    def display_for_review(self, samples: Dict[str, List[Dict]]) -> None:
        """Display sampled outputs for manual review."""

        print("\n" + "═" * 70)
        print("🔍  EVALUATOR CONFIDENCE CHECK".center(70))
        print("═" * 70)

        for risk_label, items in [("HIGH-RISK", samples["high_risk"]), ("LOW-RISK", samples["low_risk"])]:
            print(f"\n{'─' * 70}")
            print(f"  {risk_label} SAMPLES ({len(items)} selected)")
            print(f"{'─' * 70}")

            for idx, item in enumerate(items, 1):
                # Extract fields (handle both evaluator JSONL and RAG run log formats)
                attack_id = item.get("attack_id", item.get("attack_name", "???"))
                input_prompt = item.get("input_prompt", item.get("user_query", ""))[:300]
                model_output = item.get("model_response", item.get("model_output", ""))[:300]

                # Classification from either format
                if "evaluator_classification" in item:
                    ec = item["evaluator_classification"]
                    classification = ec.get("three_class", "???")
                    score = ec.get("score", "?")
                    threat = ec.get("threat_level", "?")
                    reasoning = ec.get("reasoning", "")[:200]
                else:
                    classification = item.get("classification", item.get("four_tier", "???"))
                    score = item.get("score", "?")
                    threat = item.get("threat_level", "?")
                    reasoning = item.get("reasoning", "")[:200]

                print(f"\n  [{idx}] {attack_id}")
                print(f"      Classification: {classification}")
                print(f"      Score: {score}/100 | Threat: {threat}")
                print(f"      Input:  {input_prompt[:150]}{'…' if len(input_prompt) > 150 else ''}")
                print(f"      Output: {model_output[:150]}{'…' if len(model_output) > 150 else ''}")
                if reasoning:
                    print(f"      Reason: {reasoning[:150]}{'…' if len(reasoning) > 150 else ''}")
                print(f"      ┌─ MANUAL REVIEW ───────────────────────────┐")
                print(f"      │  Verdict: [ ] TP  [ ] FP  [ ] FN  [ ] OK │")
                print(f"      │  Notes:                                   │")
                print(f"      └───────────────────────────────────────────┘")

        print(f"\n{'═' * 70}")

    def generate_report(
        self,
        samples: Dict[str, List[Dict]],
        manual_verdicts: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate the confidence check report.
        If manual_verdicts is None, generate a template for later filling.
        """
        report = {
            "report_type": "evaluator_confidence_check",
            "timestamp": datetime.now().isoformat(),
            "methodology": "Manual review of 5 highest-risk and 5 lowest-risk outputs",
            "samples": {
                "high_risk": [],
                "low_risk": [],
            },
            "summary": {
                "total_reviewed": len(samples["high_risk"]) + len(samples["low_risk"]),
                "false_positives": 0,
                "false_negatives": 0,
                "misclassifications": 0,
                "true_positives": 0,
                "true_negatives": 0,
                "notes": "Pending manual review — fill in the verdicts below.",
            },
        }

        for risk_label in ["high_risk", "low_risk"]:
            for idx, item in enumerate(samples[risk_label]):
                attack_id = item.get("attack_id", item.get("attack_name", f"sample-{idx}"))

                if "evaluator_classification" in item:
                    ec = item["evaluator_classification"]
                    auto_classification = ec.get("three_class", "???")
                    auto_score = ec.get("score", None)
                    auto_threat = ec.get("threat_level", "?")
                else:
                    auto_classification = item.get("classification", item.get("four_tier", "???"))
                    auto_score = item.get("score", None)
                    auto_threat = item.get("threat_level", "?")

                entry = {
                    "sample_index": idx + 1,
                    "attack_id": attack_id,
                    "risk_bucket": risk_label.upper().replace("_", "-"),
                    "auto_classification": auto_classification,
                    "auto_score": auto_score,
                    "auto_threat_level": auto_threat,
                    "input_excerpt": (item.get("input_prompt", item.get("user_query", "")))[:300],
                    "output_excerpt": (item.get("model_response", item.get("model_output", "")))[:300],
                    "manual_verdict": "PENDING",  # TP, FP, FN, TN, MISCLASSIFIED
                    "manual_notes": "",
                }
                report["samples"][risk_label].append(entry)

        # If verdicts are provided, compute summary
        if manual_verdicts:
            fp = fn = mis = tp = tn = 0
            all_verdicts = manual_verdicts.get("high_risk", []) + manual_verdicts.get("low_risk", [])
            for v in all_verdicts:
                v_upper = v.upper()
                if v_upper == "FP":
                    fp += 1
                elif v_upper == "FN":
                    fn += 1
                elif v_upper in ("MIS", "MISCLASSIFIED"):
                    mis += 1
                elif v_upper == "TP":
                    tp += 1
                elif v_upper == "TN":
                    tn += 1
            report["summary"].update({
                "false_positives": fp,
                "false_negatives": fn,
                "misclassifications": mis,
                "true_positives": tp,
                "true_negatives": tn,
                "notes": f"Reviewed {len(all_verdicts)} samples. FP={fp}, FN={fn}, Mis={mis}.",
            })

        return report

    def save_report(self, report: Dict, output_path: str = None) -> str:
        """Save confidence check report as JSON."""
        if output_path is None:
            output_path = str(PROJECT_ROOT / "reports" / "confidence_check_report.json")

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"\n  ✓ Confidence check report saved: {output_path}")
        return output_path


# ═══════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="Evaluator Confidence Check")
    parser.add_argument("--results-dir", type=str, default=None)
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()

    checker = EvaluatorConfidenceCheck(results_dir=args.results_dir)

    # 1. Load and sample
    results = checker._load_results()
    if not results:
        print("\n❌ No evaluator results found. Run tests first.")
        return

    samples = checker.sample(results)
    print(f"\n  Sampled {len(samples['high_risk'])} high-risk + {len(samples['low_risk'])} low-risk outputs")

    # 2. Display for review
    checker.display_for_review(samples)

    # 3. Generate template report (pending manual verdicts)
    report = checker.generate_report(samples)
    checker.save_report(report, args.output)

    print("\n📋 Next steps:")
    print("   1. Open the confidence check report JSON")
    print("   2. For each sample, set 'manual_verdict' to: TP, FP, FN, TN, or MISCLASSIFIED")
    print("   3. Add notes explaining your reasoning")
    print("   4. Re-run with --update to compute summary statistics")


if __name__ == "__main__":
    main()
