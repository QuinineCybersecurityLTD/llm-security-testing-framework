# Framework Memory

> Agent: read this at session start, append findings at session end.
> Keep entries concise. Archive old entries to `docs/memory_archive.md` when this file exceeds 150 lines.

---

## Known Issues

- `.benchmarks/` and `testpacks/` directories exist but are empty placeholders — need golden eval set
- `mypy` runs with `continue-on-error: true` in CI — type errors do not block merges
- `disallow_untyped_defs = false` in mypy config — strictest type checking disabled
- Only 2 test files exist (`tests/`) covering ~2 of 30+ `src/` modules
- No pre-commit hooks configured (`.pre-commit-config.yaml` absent)
- `src/test_core.py` is not in `tests/` and is not discovered by pytest
- No `pytest-cov` threshold enforced in CI despite being in dev deps
- `demo_hardening.py` contains real-format API key strings for demo purposes — review before sharing

## Decisions

- `knowledge_base/API_keys.txt` is INTENTIONAL test data for RAG leakage testing, not a security oversight
- `chat_with_rag.py` is a dev utility only, not part of the production framework
- 4-tier classification (CLEAN_REFUSAL / PARTIAL_LEAKAGE / UNSAFE_COMPLIANCE / FULLY_VULNERABLE) is the core differentiator — never simplify to binary pass/fail
- Attack IDs follow `Q9-{SCOPE}-{TYPE}-{NNN}` format — always check existing YAML for next unused NNN

## Session Log

### 2026-03-16 (Session 1 — Initial setup)
- Installed 4 skills: `security-audit`, `attack-creator`, `evaluator-dev`, `client-report`
- Set `ECC_HOOK_PROFILE=strict` in `~/.bashrc`
- Harness audit score: 34/70

### 2026-03-16 (Session 2 — Golden tier push)
- Fixed: `api.txt` + `*.key`, `*.pem`, `secrets.yaml/json` added to `.gitignore`
- Created: `MEMORY.md`, `CLAUDE.md` updated with agent instructions + skills index
- Created: `.claude/commands/` — `run-audit.md`, `new-attack.md`, `eval-golden.md`, `diff-report.md`
- Created: `.benchmarks/golden_eval.yaml` — 17 golden cases across all 4 tiers + tricky edge cases
- Created: `scripts/eval_golden.py` — standalone runner with pattern-matching fallback and CI mode
- Created: `.github/workflows/ci.yml` — proper GitHub Actions location with secret-scan → quality → golden-eval → smoke-test → docker pipeline
- Fixed: `pyproject.toml` mypy — added `no_implicit_optional`, `strict_equality`, `warn_unused_ignores`
- Created: `.pre-commit-config.yaml` — ruff, mypy, detect-secrets, file hygiene hooks
- Created: `.secrets.baseline` — detect-secrets baseline (excludes intentional test data)
- Created: `.env.example` — safe credential template for new contributors
- Created: 3 new skills — `harness-maintenance.md`, `cost-control.md`, `cross-harness-sync.md`
- Created: `.claude/agents/` — `security-researcher.md`, `report-generator.md`
- Created: `.cursor/rules/` — `project.mdc`, `conventions.mdc` for Cursor parity
- Estimated new harness score: ~62/70

### 2026-03-17 (Session 3 — HuggingFace API testing + attack audit)
- Fixed: HF adapter env var naming (HUGGINGFACE_API_KEY), .env auto-loading in main.py
- Fixed: HF model `meta-llama/Meta-Llama-3-8B-Instruct` works on router.huggingface.co/v1
- Ran 4-attack test: ALL attacks scored REFUSED 100/100 — attacks too naive
- Identified critical evaluator bug: hallucination attacks (fake citations) scored REFUSED 100/100

### 2026-03-18 (Session 4 — Attack corpus overhaul)
- Researched GARAK probes (GCG, TAP, encoding, atkgen, PAP), Promptfoo (tree-of-thought, composite, Likert, multilingual), and 14 state-of-art jailbreak techniques
- Created: `attacks/advanced_jailbreaks.yaml` — 30 attacks (crescendo, payload-splitting, many-shot, competing objectives, skeleton key, refusal suppression, Likert scale, AIM, hallucination)
- Created: `attacks/multilingual_attacks.yaml` — 30 attacks (Zulu, Scots Gaelic, Welsh, Swahili, Bengali, Hmong, Arabic, Chinese, Japanese, Korean, Russian, Hindi + code-switching, transliteration, translation-proxy, cross-lingual chains, RTL injection, Unicode homoglyphs)
- Created: `attacks/encoding_attacks.yaml` — 25 attacks (Base64, ROT13, leetspeak, Pig Latin, Morse, hex, binary, Caesar cipher, custom cipher, reverse text, zero-width chars, Unicode tags, token splitting, nested encoding, acrostic, math prompts)
- Updated: `src/attack_engine.py` — added 5 new AttackCategory enums (ENCODING_BYPASS, MULTILINGUAL, MANY_SHOT, MULTI_TURN_ATTACK, HALLUCINATION_ATTACK), expanded category mapping with 12+ new entries, fixed multi-turn YAML loading (turn_templates fallback)
- Fixed: `src/improved_evaluator.py` — added FIX-6 hallucination detection (HALLUCINATION_INDICATORS + HALLUCINATION_REFUSAL_PATTERNS), new CASE 0b in classify() catches fabricated citations/DOIs/statistics
- Total attacks: 240 (was ~156), 5 multi-turn, 13 categories

### 2026-03-20 (Session 5 — Client readiness audit + RAG redesign)
- Ran 3-agent parallel audit: core pipeline, adapters/configs, RAG/guards
- Overall score: ~85% production-ready
- FIX-1: Replaced hardcoded dev machine paths in 6 config files → `${GGUF_MODEL_PATH}` env var
- FIX-2: Converting 60+ print() → proper logging in main.py and rag_security_tester.py
- FIX-3: Fixed `./reports` and `./logs` relative paths → PROJECT_ROOT-based resolution
- FIX-4: Deleted stale root-level ci.yml duplicate
- FIX-5: Added llama-cpp-python to requirements.txt (commented, optional)
- FIX-6: Fixed reporter.py default paths to use PROJECT_ROOT
- MAJOR: Redesigned RAG testing for client engagements:
  - Created `src/client_rag_tester.py` — black-box testing of CLIENT's RAG via their API endpoint
  - Created `src/adapters/custom_rest_adapter.py` — universal adapter for any HTTP-based LLM/RAG
  - Created `config/config_client_template.yaml` — client LLM onboarding (9 format types)
  - Created `config/config_client_rag_template.yaml` — client RAG testing with 4 access modes
  - Registered CustomRESTAdapter in orchestrator
  - Updated .env.example with CLIENT_API_KEY, CLIENT_RAG_ENDPOINT, JUDGE_API_KEY, GGUF_MODEL_PATH
  - Added Client Engagement Workflow section to CLAUDE.md
- Key insight: `rag_security_tester.py` tests OUR RAG (benchmark), `client_rag_tester.py` tests CLIENT's RAG (deliverable)

## Next Steps

1. Run `pre-commit install` to activate hooks for local development
2. ~~Move/delete root-level `ci.yml`~~ DONE (Session 5)
3. Raise `pytest --cov-fail-under` from 60% to 80% once test coverage improves
4. Enable `disallow_untyped_defs = true` in `pyproject.toml` once all modules have type hints
5. Add `.opencode/instructions.md` and `.codex/instructions.md` for full cross-harness parity
6. Run full test suite against HuggingFace API with new 240-attack corpus
7. Consider adding TAP/PAIR automated attack generation to `automated_attack_generator.py`
8. Add transform pipeline (GARAK-style buffs) to multiply attacks × encodings × languages
9. Add tests for client_rag_tester.py, custom_rest_adapter.py, and evaluator
