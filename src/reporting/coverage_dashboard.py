"""
Coverage Dashboard — Day 4
Structured table showing testing maturity: threats defined vs executed,
category coverage, model coverage (hosted vs local), and RAG coverage.

Usage:
    cd src
    python coverage_dashboard.py
    python coverage_dashboard.py --attacks-dir ../attacks --results-dir ../logs
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
import yaml
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import Counter, defaultdict


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


# ═══════════════════════════════════════════════════════════════════════
class CoverageDashboard:
    """
    Compute and display testing maturity metrics:
      • Total threats defined vs executed
      • Category coverage
      • Model coverage (Hosted vs Local)
      • RAG-specific coverage
    """

    def __init__(
        self,
        attacks_dir: str = None,
        results_dir: str = None,
    ):
        self.attacks_dir = Path(attacks_dir or (PROJECT_ROOT / "attacks"))
        self.results_dir = Path(results_dir or (PROJECT_ROOT / "logs"))

    # ── Load all defined attacks ── ───────────────────────────────────
    def _load_defined_attacks(self) -> List[Dict[str, Any]]:
        """Load all attack definitions from YAML files."""
        attacks = []
        if not self.attacks_dir.exists():
            print(f"  ⚠ Attacks directory not found: {self.attacks_dir}")
            return attacks

        for yaml_file in self.attacks_dir.glob("*.yaml"):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}

                # Handle various YAML schemas
                attack_list = data.get("attacks", [])
                if isinstance(attack_list, list):
                    for atk in attack_list:
                        if isinstance(atk, dict):
                            atk["_source_file"] = yaml_file.name
                            attacks.append(atk)
            except Exception as e:
                print(f"  ⚠ Error loading {yaml_file.name}: {e}")

        return attacks

    # ── Load latest executed results ──────────────────────────────────
    def _load_latest_results(self) -> List[Dict[str, Any]]:
        """Load results from the most recent evaluator JSONL file."""
        results = []
        if not self.results_dir.exists():
            print(f"  ⚠ Results directory not found: {self.results_dir}")
            return results

        # Find latest evaluator results file
        jsonl_files = sorted(
            self.results_dir.glob("evaluator_results_*.jsonl"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        # Also check RAG run logs
        rag_logs = sorted(
            self.results_dir.glob("rag_run_log_*.jsonl"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        # Load evaluator results
        if jsonl_files:
            latest = jsonl_files[0]
            try:
                with open(latest, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            results.append(json.loads(line))
            except Exception as e:
                print(f"  ⚠ Error loading {latest.name}: {e}")

        # If no evaluator results, try JSON reports
        if not results:
            json_reports = sorted(
                self.results_dir.parent.joinpath("reports").glob("report_*.json")
                if (self.results_dir.parent / "reports").exists()
                else [],
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if json_reports:
                try:
                    with open(json_reports[0], "r", encoding="utf-8") as f:
                        data = json.load(f)
                    results = data.get("results", [])
                except Exception as e:
                    print(f"  ⚠ Error loading JSON report: {e}")

        return results

    # ── Compute coverage metrics ──────────────────────────────────────
    def compute(self) -> Dict[str, Any]:
        """Compute all coverage metrics."""
        defined_attacks = self._load_defined_attacks()
        executed_results = self._load_latest_results()

        # ── Total threats defined vs executed ──
        defined_ids = {a.get("id", a.get("name", "")) for a in defined_attacks}
        executed_ids = {r.get("attack_id", r.get("test_id", "")) for r in executed_results}

        # ── Category coverage ──
        defined_categories = Counter()
        for a in defined_attacks:
            cat = a.get("category", "UNKNOWN")
            defined_categories[cat] += 1

        executed_categories = Counter()
        for r in executed_results:
            cat = r.get("attack_category", r.get("category", "UNKNOWN"))
            executed_categories[cat] += 1

        category_coverage = []
        all_cats = set(list(defined_categories.keys()) + list(executed_categories.keys()))
        for cat in sorted(all_cats):
            defined_count = defined_categories.get(cat, 0)
            executed_count = executed_categories.get(cat, 0)
            pct = (executed_count / defined_count * 100) if defined_count > 0 else 0
            category_coverage.append({
                "category": cat,
                "defined": defined_count,
                "executed": executed_count,
                "coverage_pct": round(pct, 1),
            })

        # ── Model coverage (Hosted vs Local) ──
        model_types = Counter()
        model_names = set()
        for r in executed_results:
            model_id = r.get("model_id", r.get("model_name", r.get("model_identifier", "unknown")))
            model_names.add(model_id)
            # Classify: if path or "gguf" or "local" → local, else hosted
            model_id_lower = str(model_id).lower()
            if any(x in model_id_lower for x in ["gguf", "local", "llama", ".bin", "mistral"]):
                model_types["Local"] += 1
            else:
                model_types["Hosted"] += 1

        model_coverage = {
            "total_models_tested": len(model_names),
            "model_names": list(model_names),
            "local_tests": model_types.get("Local", 0),
            "hosted_tests": model_types.get("Hosted", 0),
        }

        # ── RAG coverage ──
        rag_defined = sum(1 for a in defined_attacks if a.get("_source_file", "").startswith("rag"))
        rag_tags = sum(1 for a in defined_attacks if "rag" in str(a.get("tags", [])).lower())
        rag_total_defined = max(rag_defined, rag_tags)

        rag_executed = 0
        rag_log_files = sorted(
            self.results_dir.glob("rag_run_log_*.jsonl"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if rag_log_files:
            try:
                with open(rag_log_files[0], "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            rag_executed += 1
            except Exception:
                pass

        rag_coverage_pct = (rag_executed / rag_total_defined * 100) if rag_total_defined > 0 else 0

        rag_coverage = {
            "total_defined": rag_total_defined,
            "total_executed": rag_executed,
            "coverage_pct": round(rag_coverage_pct, 1),
        }

        # ── Overall ──
        overall_coverage_pct = (
            len(executed_ids) / len(defined_ids) * 100
        ) if defined_ids else 0

        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_threats_defined": len(defined_ids),
                "total_threats_executed": len(executed_ids),
                "overall_coverage_pct": round(overall_coverage_pct, 1),
            },
            "category_coverage": category_coverage,
            "model_coverage": model_coverage,
            "rag_coverage": rag_coverage,
        }

    # ── Display console table ─────────────────────────────────────────
    def display(self, data: Optional[Dict] = None) -> Dict[str, Any]:
        """Print a formatted coverage dashboard and return data."""
        if data is None:
            data = self.compute()

        summary = data["summary"]

        print("\n" + "═" * 70)
        print("📊  COVERAGE DASHBOARD".center(70))
        print("═" * 70)

        # Overall
        print(f"\n  Total Threats Defined  : {summary['total_threats_defined']}")
        print(f"  Total Threats Executed : {summary['total_threats_executed']}")
        print(f"  Overall Coverage      : {summary['overall_coverage_pct']}%")

        # Category coverage
        print(f"\n{'─' * 70}")
        print(f"  {'Category':<35} {'Defined':>8} {'Executed':>9} {'Coverage':>9}")
        print(f"{'─' * 70}")
        for row in data["category_coverage"]:
            bar = "█" * int(row["coverage_pct"] / 10)
            print(f"  {row['category']:<35} {row['defined']:>8} {row['executed']:>9} {row['coverage_pct']:>8.1f}%  {bar}")

        # Model coverage
        mc = data["model_coverage"]
        print(f"\n{'─' * 70}")
        print(f"  Model Coverage")
        print(f"{'─' * 70}")
        print(f"  Total Models Tested : {mc['total_models_tested']}")
        print(f"  Local Tests         : {mc['local_tests']}")
        print(f"  Hosted Tests        : {mc['hosted_tests']}")
        if mc['model_names']:
            print(f"  Models              : {', '.join(mc['model_names'])}")

        # RAG coverage
        rc = data["rag_coverage"]
        print(f"\n{'─' * 70}")
        print(f"  RAG Coverage")
        print(f"{'─' * 70}")
        print(f"  RAG Attacks Defined  : {rc['total_defined']}")
        print(f"  RAG Attacks Executed : {rc['total_executed']}")
        print(f"  RAG Coverage         : {rc['coverage_pct']}%")

        print(f"\n{'═' * 70}\n")

        return data

    # ── Save to JSON ──────────────────────────────────────────────────
    def save(self, data: Dict, output_path: str = None) -> str:
        """Save dashboard data as JSON."""
        if output_path is None:
            output_path = str(PROJECT_ROOT / "reports" / "coverage_dashboard.json")

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"  ✓ Coverage dashboard saved: {output_path}")
        return output_path

    # ── Generate HTML snippet for embedding in report ─────────────────
    def generate_html_section(self, data: Optional[Dict] = None) -> str:
        """Return an HTML snippet for the coverage dashboard (for report embedding)."""
        if data is None:
            data = self.compute()

        s = data["summary"]
        mc = data["model_coverage"]
        rc = data["rag_coverage"]

        rows_html = ""
        for row in data["category_coverage"]:
            pct = row["coverage_pct"]
            color_class = "color-green" if pct >= 70 else "color-amber" if pct >= 40 else "color-red"
            rows_html += f"""
            <tr>
              <td>{row['category']}</td>
              <td>{row['defined']}</td>
              <td>{row['executed']}</td>
              <td class="{color_class}">{pct:.1f}%</td>
            </tr>"""

        html = f"""
<div class="section">
  <div class="section-title">📊 Coverage Dashboard — Testing Maturity</div>
  <div class="callout blue mb-20">
    ℹ️ We measure maturity, not assume it. This dashboard tracks defined vs executed threats.
  </div>

  <div class="kpi-row">
    <div class="kpi-card">
      <div class="kpi-value">{s['total_threats_defined']}</div>
      <div class="kpi-label">Threats Defined</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value">{s['total_threats_executed']}</div>
      <div class="kpi-label">Threats Executed</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value">{s['overall_coverage_pct']}%</div>
      <div class="kpi-label">Overall Coverage</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value">{mc['total_models_tested']}</div>
      <div class="kpi-label">Models Tested</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value">{rc['coverage_pct']}%</div>
      <div class="kpi-label">RAG Coverage</div>
    </div>
  </div>

  <div class="table-wrap">
    <table>
      <thead><tr>
        <th>Category</th><th>Defined</th><th>Executed</th><th>Coverage</th>
      </tr></thead>
      <tbody>{rows_html}
      </tbody>
    </table>
  </div>

  <div class="callout {'green' if rc['coverage_pct'] >= 70 else 'yellow' if rc['coverage_pct'] >= 40 else 'red'} mt-20">
    RAG: {rc['total_executed']}/{rc['total_defined']} attacks executed ({rc['coverage_pct']}%) ·
    Local: {mc['local_tests']} tests · Hosted: {mc['hosted_tests']} tests
  </div>
</div>"""
        return html


# ═══════════════════════════════════════════════════════════════════════
# CLI entry point
# ═══════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="Coverage Dashboard")
    parser.add_argument("--attacks-dir", type=str, default=None, help="Path to attacks YAML directory")
    parser.add_argument("--results-dir", type=str, default=None, help="Path to results/logs directory")
    parser.add_argument("--save", action="store_true", help="Save dashboard as JSON")
    parser.add_argument("--output", type=str, default=None, help="Output JSON path")
    args = parser.parse_args()

    dashboard = CoverageDashboard(
        attacks_dir=args.attacks_dir,
        results_dir=args.results_dir,
    )

    data = dashboard.display()

    if args.save or args.output:
        dashboard.save(data, args.output)


if __name__ == "__main__":
    main()
