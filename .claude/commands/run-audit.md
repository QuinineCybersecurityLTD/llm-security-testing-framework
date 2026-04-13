---
description: Run a security audit of the framework codebase using the security-audit skill
---

Run a full security audit of the LLM security testing framework.

Use the `security-audit` skill. Check all 5 axes:
1. Security of the framework itself (no hardcoded paths/keys, safe deserialization)
2. Reliability under production load (circuit breaker, rate limiting, counters)
3. Client-facing quality (HTML reports, JSON schema, attack IDs, OWASP mappings)
4. Code quality (circular imports, type hints, async correctness, file size)
5. Infrastructure (requirements.txt, .gitignore, Dockerfile, tests)

Report findings sorted by severity: CRITICAL → HIGH → MEDIUM → LOW.
Do not re-flag issues listed in `## Known Fixed Issues` in the security-audit skill.
After completing, append a summary to `MEMORY.md ## Session Log`.
