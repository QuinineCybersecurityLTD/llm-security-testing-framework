# Run Template

Copy this folder to create a new run:
```
runs/YYYY-MM-DD_HHMMSS_<test_id>/
```

Expected contents:
- `rag_run_log.jsonl` — RAG-specific 7-field log
- `evaluator_results.jsonl` — Full evaluator output
- `raw_outputs.txt` — Raw model I/O
- `report.html` — HTML report
- `report.json` — JSON report
- `coverage_dashboard.json` — Coverage metrics
- `confidence_check_report.json` — Manual review
