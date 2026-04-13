---
name: security-audit
description: Audit LLM security testing framework code for production readiness, vulnerabilities, and client-facing quality. Use this skill whenever reviewing framework modules, checking for security issues, auditing code for production deployment, preparing for client demos, or when words like "audit", "production ready", "client ready", "review security", or "check vulnerabilities" appear. Also trigger when working on adapters/base.py, orchestrator.py, main.py, or any module that touches the attack pipeline.
---

# Security Audit Skill — Quinine Cybersecurity Framework

You are auditing an LLM security testing framework. This framework tests OTHER models for vulnerabilities — so the framework itself must be rock-solid.

## Audit Axes (Check All 5)

### 1. Security of the Framework Itself
- No hardcoded file paths (use `PROJECT_ROOT / Path`)
- No hardcoded API keys or secrets (use env vars)
- No unsafe deserialization of YAML/JSON attack files
- Jinja2 templates use `SandboxedEnvironment` (already in attack_engine.py)
- SQLite telemetry DB is not exposed to network
- Docker runs as non-root (`appuser`)

### 2. Reliability Under Production Load
- Circuit breaker is configured and tested
- Rate limiting works per-model, not just globally
- Async operations have proper timeout handling
- `total_attacks` counter is actually incremented (was a bug, verify fix)
- Error recovery doesn't swallow exceptions silently

### 3. Client-Facing Quality
- 
- Reports render correctly in HTML with no broken CSS/JS
- JSON reports follow a consistent schema
- Attack IDs follow `Q9-{SCOPE}-{TYPE}-{NNN}` format
- All OWASP mappings are valid (LLM-01 through LLM-10)
- Classification labels match the 4-tier system exactly

### 4. Code Quality
- No circular imports between modules
- Type hints are correct (use `typing` module, not builtins for generics in 3.9+)
- Async functions are properly awaited
- No blocking calls inside async functions
- Files under 800 lines (split if larger)

### 5. Infrastructure
- `requirements.txt` pins all versions
- `.gitignore` excludes: reports/, logs/, *.db, __pycache__, .env
- Dockerfile builds without errors
- Tests exist and pass

## Output Format

For each issue found, report:
```
[SEVERITY] CRITICAL | HIGH | MEDIUM | LOW
[FILE] path/to/file.py:line_number
[ISSUE] What's wrong
[FIX] How to fix it
[IMPACT] What happens if not fixed (client exposure, crash, data leak, etc.)
```

Sort by severity: CRITICAL first, then HIGH, MEDIUM, LOW.

## Known Fixed Issues (Don't Re-Flag)
- Hardcoded path in main.py → already fixed to use PROJECT_ROOT
- total_attacks counter → already fixed
- Type hint bug (builtin vs typing) → already fixed
- Missing .gitignore → already created
- Missing requirements.txt → already created
