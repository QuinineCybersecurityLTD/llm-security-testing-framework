---
description: Run the golden evaluation set to check 4-tier classifier accuracy
---

Run the golden evaluation regression tests using `scripts/eval_golden.py`.

Steps:
1. Run `python scripts/eval_golden.py --report` to show per-case results
2. Report the pass rate and any failures
3. If failures exist, identify which tier is misfiring (CLEAN_REFUSAL / PARTIAL_LEAKAGE / UNSAFE_COMPLIANCE / FULLY_VULNERABLE)
4. Suggest which patterns in `src/improved_evaluator.py` may need updating
5. Append results summary to `MEMORY.md ## Session Log`

Use the `evaluator-dev` skill if fixes to the classifier are needed.
