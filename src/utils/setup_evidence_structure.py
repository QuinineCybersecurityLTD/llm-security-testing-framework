"""
Evidence Structure Setup — Day 4
Standardise the project folder structure for production-grade output.

Creates:
    /runs       — timestamped run folders (one per test session)
    /evidence   — screenshots, recordings, manual evidence
    /logs       — telemetry, evaluator JSONL, raw outputs
    /testpacks  — attack YAMLs and test suites
    /reports    — HTML, JSON reports

Usage:
    cd src
    python setup_evidence_structure.py
    python setup_evidence_structure.py --project-root ..
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

import shutil
import argparse
from pathlib import Path
from datetime import datetime


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Standard directories
STANDARD_DIRS = [
    "runs",
    "evidence",
    "logs",
    "testpacks",
    "reports",
]

# Files to migrate from old locations
MIGRATION_MAP = {
    # old_glob_pattern → new_directory
    "logs/evaluator_results_*.jsonl":  "logs",
    "logs/evaluator_results_*.csv":    "logs",
    "logs/raw_outputs_*.txt":          "logs",
    "logs/rag_run_log_*.jsonl":        "logs",
    "reports/report_*.html":           "reports",
    "reports/report_*.json":           "reports",
    "reports/coverage_dashboard.json": "reports",
    "reports/confidence_check_report.json": "reports",
    "attacks/*.yaml":                  "testpacks",
    "config/test_suites.yaml":         "testpacks",
}


def setup_structure(project_root: Path = PROJECT_ROOT, migrate: bool = False) -> None:
    """Create standardised evidence structure."""

    print("\n" + "═" * 60)
    print("🗂️  EVIDENCE STRUCTURE SETUP".center(60))
    print("═" * 60)

    # 1. Create directories
    for dirname in STANDARD_DIRS:
        dirpath = project_root / dirname
        dirpath.mkdir(parents=True, exist_ok=True)
        marker = "✓" if dirpath.exists() else "✗"
        print(f"  {marker} /{dirname}/")

    # 2. Create README.md in each directory
    readme_contents = {
        "runs": "# Runs\n\nTimestamped run folders. Each test session creates a subfolder here.\n\nStructure:\n```\nruns/\n  2026-02-25_170000_<test_id>/\n    rag_run_log.jsonl\n    evaluator_results.jsonl\n    raw_outputs.txt\n    report.html\n    report.json\n```\n",
        "evidence": "# Evidence\n\nManual evidence: screenshots, recordings, analyst notes.\nUsed during audits and compliance reviews.\n",
        "logs": "# Logs\n\nTelemetry, evaluator JSONL, raw model outputs.\nAll automated logs from test sessions.\n",
        "testpacks": "# Test Packs\n\nAttack YAML files and test suite definitions.\nVersioned attack libraries ready for execution.\n",
        "reports": "# Reports\n\nGenerated HTML and JSON reports.\nCoverage dashboards and confidence check reports.\n",
    }

    for dirname, content in readme_contents.items():
        readme_path = project_root / dirname / "README.md"
        if not readme_path.exists():
            readme_path.write_text(content, encoding="utf-8")
            print(f"    → Created {dirname}/README.md")

    # 3. Create .gitkeep in evidence (usually empty initially)
    gitkeep = project_root / "evidence" / ".gitkeep"
    if not gitkeep.exists():
        gitkeep.touch()

    # 4. Migrate existing files if requested
    if migrate:
        print(f"\n  Migrating existing files …")
        migrated = 0
        for pattern, dest_dir in MIGRATION_MAP.items():
            src_files = list(project_root.glob(pattern))
            for src in src_files:
                dest = project_root / dest_dir / src.name
                if src.resolve() == dest.resolve():
                    continue  # Already in the right place
                if not dest.exists():
                    try:
                        shutil.copy2(str(src), str(dest))
                        print(f"    → Copied {src.name} → /{dest_dir}/")
                        migrated += 1
                    except Exception as e:
                        print(f"    ⚠ Failed to copy {src.name}: {e}")

        if migrated == 0:
            print("    No files needed migration.")
        else:
            print(f"    ✓ Migrated {migrated} files.")

    # 5. Create a run template
    template_dir = project_root / "runs" / "_template"
    template_dir.mkdir(parents=True, exist_ok=True)
    template_readme = template_dir / "README.md"
    if not template_readme.exists():
        template_readme.write_text(
            "# Run Template\n\n"
            "Copy this folder to create a new run:\n"
            "```\n"
            "runs/YYYY-MM-DD_HHMMSS_<test_id>/\n"
            "```\n\n"
            "Expected contents:\n"
            "- `rag_run_log.jsonl` — RAG-specific 7-field log\n"
            "- `evaluator_results.jsonl` — Full evaluator output\n"
            "- `raw_outputs.txt` — Raw model I/O\n"
            "- `report.html` — HTML report\n"
            "- `report.json` — JSON report\n"
            "- `coverage_dashboard.json` — Coverage metrics\n"
            "- `confidence_check_report.json` — Manual review\n",
            encoding="utf-8",
        )

    print(f"\n{'═' * 60}")
    print("✅ Evidence structure ready!")
    print(f"{'═' * 60}\n")


def create_run_folder(test_id: str, project_root: Path = PROJECT_ROOT) -> Path:
    """Create a timestamped run folder for a specific test session."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    run_dir = project_root / "runs" / f"{timestamp}_{test_id[:8]}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


# ═══════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="Setup Evidence Structure")
    parser.add_argument("--project-root", type=str, default=None)
    parser.add_argument("--migrate", action="store_true", help="Copy existing files to new structure")
    args = parser.parse_args()

    root = Path(args.project_root) if args.project_root else PROJECT_ROOT
    setup_structure(root, migrate=args.migrate)


if __name__ == "__main__":
    main()
