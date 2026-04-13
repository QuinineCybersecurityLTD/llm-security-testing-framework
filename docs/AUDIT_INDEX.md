# Quinine LLM Security Framework — Deep Audit & Upgrade Specification
## Master Index

**Prepared:** 2026-02-23  
**Author:** AI Red Team Architect  
**Classification:** CONFIDENTIAL — Internal Use Only

---

### Document Structure

This audit is split across 5 detailed specification files:

| # | File | Coverage | Key Deliverables |
|---|------|----------|-----------------|
| 1 | [audit_part1_gap_analysis.md](file:///c:/Users/acer/Desktop/Intership@quinine/Official%20Work-week%204/llm-security-testing-framework/docs/audit_part1_gap_analysis.md) | **GAP ANALYSIS (1A–1F)** | 31 YAML attack entries |
| 2 | [audit_part2_rag_methodology.md](file:///c:/Users/acer/Desktop/Intership@quinine/Official%20Work-week%204/llm-security-testing-framework/docs/audit_part2_rag_methodology.md) | **RAG METHODOLOGY (2A–2E)** | Oracle methodology, dense embedding code, 8 YAML entries |
| 3 | [audit_part3_api_pipeline_security.md](file:///c:/Users/acer/Desktop/Intership@quinine/Official%20Work-week%204/llm-security-testing-framework/docs/audit_part3_api_pipeline_security.md) | **API & PIPELINE SECURITY (3A–3E)** | 22 YAML attack entries |
| 4 | [audit_part4_quick_wins.md](file:///c:/Users/acer/Desktop/Intership@quinine/Official%20Work-week%204/llm-security-testing-framework/docs/audit_part4_quick_wins.md) | **QUICK WINS (4A–4E)** | 3 module specs, threat model template |
| 5 | [audit_part5_evaluator_and_positioning.md](file:///c:/Users/acer/Desktop/Intership@quinine/Official%20Work-week%204/llm-security-testing-framework/docs/audit_part5_evaluator_and_positioning.md) | **EVALUATOR UPGRADES (5A–5C) + POSITIONING** | Scoring rubric, compliance mappings, 400-word positioning |

---

### Summary Statistics

| Metric | Count |
|--------|-------|
| Total new YAML attack entries | **61** |
| New OWASP attack entries (owasp_attacks.yaml schema) | 45 |
| New RAG attack entries (rag_attacks.yaml schema) | 8 |
| New dense-retrieval-specific attacks | 6 |
| New reranker-specific attacks | 2 |
| New module specifications with code | 4 |
| Evaluator blind spots identified | 5 |
| Compliance framework mappings | 2 (UK GDPR + FCA) |
| Malicious document templates | 3 |
| Client threat model template | 1 |

### New Attack Categories Added

| Category | YAML IDs | Count | OWASP Mapping |
|----------|----------|-------|---------------|
| Indirect Prompt Injection | IPI-001 to IPI-005 | 5 | LLM01 |
| System Prompt Extraction (Depth) | SPE-001 to SPE-006 | 6 | LLM06 |
| Encoding/Obfuscation Bypass | ENC-001 to ENC-008 | 8 | LLM01 |
| Model Fingerprinting | ME-001 to ME-005 | 5 | LLM10 |
| Downstream Output Injection | IOH-004 to IOH-007 | 4 | LLM02 |
| Multimodal Injection | MMI-001 to MMI-003 | 3 | LLM01 |
| API Auth/IDOR/JWT | API-001 to API-005 | 5 | LLM06/LLM08 |
| SSRF via LLM | SSRF-001 to SSRF-004 | 4 | LLM08 |
| Cost/Sponge Attacks | RA-002 to RA-006 | 5 | LLM04 |
| Plugin/Tool Security | PLG-001 to PLG-005 | 5 | LLM07 |
| Output Format Injection | OFI-001 to OFI-003 | 3 | LLM02 |
| Dense Vector Retrieval | DVR-001 to DVR-006 | 6 | LLM06 |
| Cross-Encoder/Reranker | RERANK-001 to RERANK-002 | 2 | LLM06 |
