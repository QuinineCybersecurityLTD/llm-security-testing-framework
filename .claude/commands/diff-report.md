---
description: Generate a delta comparison report between two test runs
---

Generate a regression/improvement comparison between two test result JSON files using `src/comparison_reporter.py`.

Ask the user for:
1. Baseline results file (older run) — e.g., `reports/results_baseline.json`
2. Current results file (newer run) — e.g., `reports/results_latest.json`

Then:
1. Verify both files exist and have matching `target_model` fields (warn if different)
2. Run `python src/comparison_reporter.py --baseline [file1] --current [file2] --output reports/`
3. Summarise the delta:
   - Overall risk score change (up/down/same)
   - New vulnerabilities introduced (regressions)
   - Fixed vulnerabilities (improvements)
   - Category-level changes per OWASP LLM Top 10
4. Flag any regressions as HIGH priority
5. Output the path to the generated comparison report
