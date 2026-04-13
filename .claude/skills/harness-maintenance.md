---
name: harness-maintenance
description: Maintain the Claude Code agent harness for the LLM security testing framework. Use this skill when updating MEMORY.md, adding benchmark cases, modifying CI gates, managing session logs, or syncing harness files. Trigger on keywords: "update memory", "session log", "add benchmark", "golden eval", "CI gate", "harness", "pre-commit", "add test case", "update .gitignore", "fix CI", "harness audit".
---

# Harness Maintenance Skill — Quinine Cybersecurity Framework

You are maintaining the agent harness infrastructure. The harness is what makes the AI agent effective across sessions — treat it as production infrastructure.

## Harness File Map

```
.claude/
  skills/           ← Domain knowledge skills (auto-triggered by keywords)
  commands/         ← Slash command definitions (/run-audit, /new-attack, etc.)
  agents/           ← Sub-agent definitions for autonomous tasks
MEMORY.md           ← Cross-session persistent state (read at start, append at end)
CLAUDE.md           ← Static project context loaded every session
.benchmarks/
  golden_eval.yaml  ← 4-tier classification regression test set
scripts/
  eval_golden.py    ← Runner for golden eval set
.pre-commit-config.yaml  ← Pre-commit hooks (ruff, mypy, detect-secrets)
.github/workflows/ci.yml ← GitHub Actions CI (NOT root ci.yml — that's the old location)
.secrets.baseline   ← detect-secrets baseline (regenerate with: detect-secrets scan > .secrets.baseline)
```

## MEMORY.md Update Protocol

At the END of every significant session, append a new dated entry:

```markdown
### YYYY-MM-DD
- What was done
- Decisions made and why
- Issues discovered
- Update ## Next Steps if priorities changed
```

Never delete old entries — archive them to `docs/memory_archive.md` when the file exceeds 150 lines.

## Adding Golden Eval Cases

When adding a case to `.benchmarks/golden_eval.yaml`:
1. Assign the next unused ID in the relevant section: `GE-CR-NNN`, `GE-PL-NNN`, `GE-UC-NNN`, `GE-FV-NNN`, or `GE-TRICKY-NNN`
2. Use a real-format response (not a placeholder)
3. Include a `notes:` field explaining why this case is interesting/tricky
4. Verify the case is not a duplicate of an existing entry

Run after adding: `python scripts/eval_golden.py --report`

## CI Gate Rules

When modifying `.github/workflows/ci.yml`:
- Secret scanning (`secret-scan` job) MUST remain the first job — it gates everything else
- `pytest --cov-fail-under=60` is the minimum threshold — do not lower it
- Mypy MUST NOT have `continue-on-error: true` — type errors must block
- The `golden-eval` job must run after `quality` and before `docker`

## Pre-commit Setup for New Contributors

```bash
pip install pre-commit
pre-commit install
# To run manually on all files:
pre-commit run --all-files
```

## .secrets.baseline Regeneration

When you add new files with intentional test credentials (like knowledge_base/):
```bash
detect-secrets scan --exclude-files 'knowledge_base/.*' \
                    --exclude-files 'src/demo_hardening\.py' \
                    > .secrets.baseline
```
