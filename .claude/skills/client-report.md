---
name: client-report
description: Generate and modify client-facing reports, compliance mappings, and HTML dashboards for the LLM security testing framework. Use this skill when working on reporter.py, narrative_generator.py, comparison_reporter.py, or coverage_dashboard.py. Also trigger when the user mentions "report", "HTML report", "JSON report", "compliance", "client deliverable", "dashboard", "OWASP mapping", "ISO 42001", "NIST AI RMF", "EU AI Act", "risk register", "executive summary", "board-ready", or "narrative".
---

# Client Report Skill — Quinine Cybersecurity Framework

You are working on the reporting system that produces client-facing deliverables from security test results.

## Report Types

### 1. HTML Dashboard Report (`reporter.py`)
The primary deliverable. Must include:
- Executive summary with overall risk score
- 4-tier classification breakdown (pie chart / bar chart)
- Per-category results (OWASP LLM Top 10)
- Individual attack results with expandable details
- Risk register with remediation recommendations
- Compliance mapping table

### 2. JSON Machine-Readable Report (`reporter.py`)
For SIEM/GRC tool ingestion. Must be:
- Consistent schema across all test runs
- Include all data from HTML report in structured form
- Include metadata: framework version, timestamp, config used, model tested

### 3. Narrative Red Team Report (`narrative_generator.py`)
Board-ready document following: Discovery → Fingerprint → Exploit → Exfiltrate narrative arc.

### 4. Delta Comparison Report (`comparison_reporter.py`)
Shows regression/improvement between two test runs.

### 5. Coverage Dashboard (`coverage_dashboard.py`)
Testing maturity metrics: which categories tested, at what depth, gaps.

## Compliance Mapping Requirements

Every finding must map to ALL applicable frameworks:

| Framework | Required Fields |
|-----------|----------------|
| **OWASP LLM Top 10** | Category ID (LLM-01 through LLM-10), risk level |
| **ISO 42001** | Control reference, compliance status |
| **NIST AI RMF** | Function (Govern, Map, Measure, Manage), category |
| **EU AI Act** | Risk classification (Minimal, Limited, High, Unacceptable) |

## Risk Register Format

Each entry in the risk register must include:
```
Risk ID: RR-LLM-{NN} or RR-RAG-{NN}
Category: OWASP category
Severity: CRITICAL | HIGH | MEDIUM | LOW
Likelihood: Based on attack success rate
Impact: Business impact description
Remediation: Specific, actionable fix
Status: OPEN | MITIGATED | ACCEPTED
```

## HTML Report Quality Rules

1. **Self-contained** — all CSS/JS inline, no external dependencies
2. **Print-friendly** — must render correctly when printed to PDF
3. **Professional styling** — no default browser styles, use a clean design system
4. **Interactive** — expandable sections, sortable tables, filterable views
5. **Accessible** — proper heading hierarchy, alt text, color contrast
6. **Logo-ready** — placeholder for client logo in header

## JSON Report Schema Rules

1. **Consistent types** — scores are always integers, timestamps are ISO 8601
2. **No null values** — use empty strings, empty arrays, or 0 instead
3. **Sorted keys** — for deterministic output and easy diffing
4. **Version field** — include `schema_version` for forward compatibility

## Client Presentation Tips

When generating reports that will go directly to clients:
- Lead with the risk score and executive summary
- Use traffic light colors: red (FULLY_VULNERABLE), orange (UNSAFE_COMPLIANCE), yellow (PARTIAL_LEAKAGE), green (CLEAN_REFUSAL)
- Include a "What This Means" section in plain English for each finding
- Always include remediation steps — findings without fixes frustrate clients
- Include a methodology section explaining the testing approach

## File Locations
- Main reporter: `src/reporter.py` (V2, 4-tier, risk register)
- Legacy reporter: `src/reporterv1.py` (V1, kept for backward compatibility)
- Narrative generator: `src/narrative_generator.py`
- Comparison reporter: `src/comparison_reporter.py`
- Coverage dashboard: `src/coverage_dashboard.py`
