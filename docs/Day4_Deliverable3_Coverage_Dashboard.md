# Day 4 — Deliverable 3: Coverage Dashboard

**Author:** Devesh Mhaske
**Date:** 2 March 2026  
**Framework:** LLM & RAG Security Testing Framework v1.0  
**Principle:** We measure maturity, not assume it.

---

## 1. Objective

Create a structured table showing testing maturity across all dimensions:
- Total threats defined vs executed
- Category coverage
- Model coverage (Hosted vs Local)
- RAG-specific coverage

---

## 2. Overall Summary

| Metric | Count | Status |
|--------|-------|--------|
| **Total Threats Defined (Risk Register)** | 20 | RR-LLM-01 to RR-LLM-10, RR-RAG-01 to RR-RAG-10 |
| **Total Attack Cases Defined (YAML)** | 60 | Across `owasp_attacks.yaml`, `rag_attacks.yaml`, `auto_generated_attacks.yaml` |
| **Total RAG Attacks Defined** | 36 | In `rag_attacks.yaml` (3 active, 33 commented/reserved) |
| **Total Attacks Executed (All Sessions)** | 109+ | Across 10+ test sessions |
| **Total RAG Attacks Executed** | 10 | Day 4 expanded session (up from 3) |

---

## 3. Threat Category Coverage

| Category | Defined | Executed | Coverage % | Status |
|----------|---------|----------|------------|--------|
| PROMPT_INJECTION | 9 | 2 | 22.2% | 🔴 Low |
| SENSITIVE_INFO_DISCLOSURE | 13 | 2 | 15.4% | 🔴 Low |
| HALLUCINATION | 3 | 2 | 66.7% | 🟡 Moderate |
| PII_LEAKAGE | 1 | 1 | 100.0% | 🟢 Full |
| JAILBREAK | 4 | 11 | 100.0%+ | 🟢 Full |
| EXCESSIVE_AGENCY | 1 | 0 | 0.0% | 🔴 None |
| DENSE_VECTOR_ATTACK | 6 | 0 | 0.0% | 🔴 None |
| RERANKING_ATTACK | 2 | 0 | 0.0% | 🔴 None |
| ADVERSARIAL | 3 | 3 | 100.0% | 🟢 Full |
| BIAS-FAIRNESS | 3 | 3 | 100.0% | 🟢 Full |
| LLM-01 (Prompt Injection) | 3 | 75+ | 100.0%+ | 🟢 Full |
| LLM-06 (Sensitive Info) | 3 | 3 | 100.0% | 🟢 Full |
| LLM-08 (Excessive Agency) | 3 | 3 | 100.0% | 🟢 Full |
| LLM-09 (Misinformation) | 3 | 3 | 100.0% | 🟢 Full |
| LLM-10 (Unbounded Consumption) | 3 | 3 | 100.0% | 🟢 Full |

### Coverage Gaps Requiring Attention

| Gap Category | Defined | Executed | Priority |
|-------------|---------|----------|----------|
| DENSE_VECTOR_ATTACK | 6 | 0 | High — requires vector store testing |
| RERANKING_ATTACK | 2 | 0 | High — requires re-ranker component |
| EXCESSIVE_AGENCY | 1 | 0 | Medium — requires tool integration |
| SENSITIVE_INFO_DISCLOSURE | 13 | 2 | High — 11 attacks not yet run |
| PROMPT_INJECTION | 9 | 2 | Medium — 7 attacks not yet run |

---

## 4. Model Coverage

| Dimension | Value |
|-----------|-------|
| **Total Models Tested** | 1 |
| **Local Models** | `mistral-local-gguf` (Mistral 7B GGUF) — 109+ tests |
| **Hosted Models** | 0 tests |
| **Model Types** | Local only |

### Model Coverage Matrix

| Model | Type | OWASP Tests | RAG Tests | Total | Status |
|-------|------|-------------|-----------|-------|--------|
| mistral-local-gguf | Local GGUF | 99+ | 10 | 109+ | 🟢 Active |
| (No hosted model) | Hosted API | 0 | 0 | 0 | 🔴 Not tested |

### Assessment

> ⚠️ **Gap:** No hosted model (GPT-4, Claude, Gemini) has been tested. All 109+ executions are against the local Mistral 7B GGUF model. Hosted model testing requires API key configuration and is planned for future sessions.

---

## 5. RAG Coverage

| Metric | Value | Status |
|--------|-------|--------|
| **RAG Attacks Defined** | 36 | Full suite in `rag_attacks.yaml` |
| **RAG Attacks Active (uncommented)** | 3 → 10 | Expanded in Day 4 |
| **RAG Attacks Executed** | 10 | Day 4 session |
| **RAG Coverage %** | 27.8% (10/36) | 🟡 Moderate |

### RAG Category Breakdown

| RAG Sub-Category | IDs | Defined | Executed | Coverage |
|-----------------|-----|---------|----------|----------|
| Retrieval Hijacking | RAG-RH-* | 4 | 2 | 50% 🟡 |
| Prompt Injection via Context | RAG-PI-* | 4 | 2 | 50% 🟡 |
| Context Poisoning | RAG-CP-* | 3 | 1 | 33% 🟡 |
| BOLA (Broken Auth) | RAG-BOLA-* | 3 | 0 | 0% 🔴 |
| Retrieval Bypass | RAG-RB-* | 3 | 2 | 67% 🟡 |
| Knowledge Base Poisoning | RAG-KBP-* | 2 | 2 | 100% 🟢 |
| Data Exfiltration | RAG-EX-* | 4 | 2 | 50% 🟡 |
| Chunk/Novel Attacks | RAG-NOVEL-* | 4 | 0 | 0% 🔴 |
| Social Engineering | RAG-SE-* | 3 | 0 | 0% 🔴 |
| Dense Vector Attacks | RAG-DVR-* | 6 | 0 | 0% 🔴 |
| Re-Ranking Attacks | RAG-RERANK-* | 2 | 0 | 0% 🔴 |

---

## 6. Risk Register Coverage

| Risk ID | Threat Category | Test IDs Mapped | Tests Executed | Coverage |
|---------|----------------|-----------------|----------------|----------|
| RR-LLM-01 | Prompt Injection | TC-INJ-01, TC-INJ-02 | RAG-PI-001, RAG-PI-004 | 🟡 Partial |
| RR-LLM-02 | Indirect Injection | TC-INJ-03, TC-INJ-04 | — | 🔴 None |
| RR-LLM-03 | System Prompt Leakage | TC-SPE-01, TC-SPE-02 | — | 🔴 None |
| RR-LLM-04 | Excessive Agency | TC-AGN-01, TC-AGN-02 | — | 🔴 None |
| RR-LLM-05 | PII Disclosure | TC-PII-01, TC-PII-02 | RAG-EX-002 | 🟡 Partial |
| RR-LLM-06 | Supply Chain | TC-SC-01, TC-SC-02 | — | 🔴 None |
| RR-LLM-07 | Improper Output Handling | TC-OUT-01, TC-OUT-02 | — | 🔴 None |
| RR-LLM-08 | Data Poisoning | TC-POI-01 | — | 🔴 None |
| RR-LLM-09 | Unbounded Consumption | TC-DOS-01, TC-DOS-02 | — | 🔴 None |
| RR-LLM-10 | Misinformation | TC-HAL-01 | RAG-RB-003 | 🟡 Partial |
| RR-RAG-01 | Document Poisoning | TC-RAG-01, TC-RAG-02 | RAG-KBP-001 | 🟡 Partial |
| RR-RAG-02 | Vector DB Unauth | TC-VDB-01, TC-VDB-02 | — | 🔴 None |
| RR-RAG-03 | Sensitive Data Extraction | TC-RAG-03, TC-RAG-04 | RAG-EX-001, RAG-RB-001, RAG-RH-001 | 🟢 Covered |
| RR-RAG-04 | Ingestion Poisoning | TC-RAG-05 | RAG-KBP-002 | 🟡 Partial |
| RR-RAG-05 | Context Boundary Leakage | TC-RAG-06 | RAG-EX-002 | 🟡 Partial |
| RR-RAG-06 | Sensitive Log Exposure | TC-LOG-01 | — | 🔴 None |
| RR-RAG-07 | Tenant Isolation | TC-TEN-01, TC-TEN-02 | — | 🔴 None |
| RR-RAG-08 | RAG Excessive Agency | TC-AGN-03 | — | 🔴 None |
| RR-RAG-09 | Supply Chain (RAG) | TC-SC-03 | — | 🔴 None |
| RR-RAG-10 | Context Overflow / DoS | TC-DOS-03, TC-DOS-04 | RAG-CP-003 | 🟡 Partial |

### Risk Register Summary

| Status | Count | Percentage |
|--------|-------|------------|
| 🟢 Covered (≥1 test executed and finding documented) | 1 | 5% |
| 🟡 Partial (test executed, not all test IDs covered) | 7 | 35% |
| 🔴 None (no tests executed) | 12 | 60% |

---

## 7. Maturity Assessment

| Dimension | Current State | Target | Gap |
|-----------|--------------|--------|-----|
| **Risk Register Coverage** | 40% (8/20 risks tested) | 100% | 12 risks untested |
| **Attack Category Coverage** | 10/16 categories (62.5%) | 100% | 6 categories at 0% |
| **RAG Attack Coverage** | 10/36 attacks (27.8%) | ≥80% | 26 attacks remaining |
| **Model Diversity** | 1 model (local only) | ≥2+ (local + hosted) | No hosted model tested |
| **Automated Testing** | Manual trigger via CLI | CI/CD integrated | No pipeline integration |

### Maturity Level: **Level 2 — Repeatable**

| Level | Description | Our Status |
|-------|-------------|------------|
| Level 1 — Initial | Ad-hoc testing, no structure | ✅ Passed |
| **Level 2 — Repeatable** | Structured attacks, logs, basic coverage | ← **Current** |
| Level 3 — Defined | Full risk register coverage, multi-model | Target |
| Level 4 — Managed | CI/CD integration, automated trend tracking | Future |
| Level 5 — Optimized | Continuous improvement, ML-driven attack generation | Future |

---

## 8. Recommendations for Coverage Improvement

| Priority | Action | Expected Impact |
|----------|--------|-----------------|
| 🔴 P1 | Uncomment remaining 26 RAG attacks in `rag_attacks.yaml` | RAG coverage → 100% |
| 🔴 P1 | Run DENSE_VECTOR_ATTACK and RERANKING_ATTACK categories | 8 new category tests |
| 🟡 P2 | Add hosted model (e.g., Groq API with Llama) | Model diversity → 2+ |
| 🟡 P2 | Execute EXCESSIVE_AGENCY tests with tool integration | Cover RR-LLM-04, RR-RAG-08 |
| 🟢 P3 | Integrate testing into CI/CD pipeline | Maturity Level 4 |

---

*Document prepared for Day 4 submission — Coverage Dashboard*
