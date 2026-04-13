---
name: cross-harness-sync
description: Sync agent harness context across AI tools (Cursor, Codex, OpenCode). Use this skill when setting up rules for other AI editors, propagating CLAUDE.md changes to other tools, or ensuring harness parity. Trigger on keywords: "cursor", "cursor rules", "opencode", "codex", ".cursorrules", "harness parity", "other AI tools", "rules file", "propagate context", "sync harness".
---

# Cross-Harness Sync Skill — Quinine Cybersecurity Framework

You are syncing the agent harness context across multiple AI coding tools so any tool has the same project understanding.

## Harness Parity Matrix

| Context | Claude Code | Cursor | Codex | OpenCode |
|---------|------------|--------|-------|----------|
| Project overview | `CLAUDE.md` | `.cursor/rules/project.mdc` | `.codex/instructions.md` | `.opencode/instructions.md` |
| Memory | `MEMORY.md` | Referenced in rules | Referenced in instructions | Referenced in instructions |
| Attack ID format | `CLAUDE.md` | `.cursor/rules/conventions.mdc` | `.codex/instructions.md` | `.opencode/instructions.md` |
| 4-tier classification | `CLAUDE.md` + evaluator-dev skill | `.cursor/rules/conventions.mdc` | `.codex/instructions.md` | `.opencode/instructions.md` |
| File path conventions | `CLAUDE.md` | `.cursor/rules/conventions.mdc` | `.codex/instructions.md` | `.opencode/instructions.md` |

## Cursor Rules Setup

Create `.cursor/rules/` with MDC files:

### `.cursor/rules/project.mdc`
```markdown
---
description: LLM Security Testing Framework — Quinine Cybersecurity
globs: ["**/*.py", "attacks/**/*.yaml", "config/**/*.yaml"]
---

This is an LLM security testing framework. It red-teams AI models for vulnerabilities.
Read CLAUDE.md for full architecture. Read MEMORY.md for current state and known issues.

Core pipeline: YAML Attacks → AttackEngine → Orchestrator → Model Adapter → Evaluator → Reporter
```

### `.cursor/rules/conventions.mdc`
```markdown
---
description: Naming conventions and code standards
globs: ["**/*.py"]
---

## Attack IDs: Q9-{SCOPE}-{TYPE}-{NNN}
## 4-tier classification: CLEAN_REFUSAL | PARTIAL_LEAKAGE | UNSAFE_COMPLIANCE | FULLY_VULNERABLE
## File paths: always use pathlib.Path relative to PROJECT_ROOT
## API keys: always from environment variables, never hardcoded
## Async: all model calls are async — never use blocking calls in async context
```

## Codex / OpenCode Setup

Create `instructions.md` in the tool's config directory with a condensed version of CLAUDE.md:
- Architecture overview (pipeline diagram)
- Attack ID format
- 4-tier classification scores
- File path convention
- Link to MEMORY.md for current state

## Sync Protocol

When `CLAUDE.md` is updated significantly:
1. Extract the changed section
2. Apply the equivalent change to all other harness files
3. Note the sync in `MEMORY.md ## Session Log`

Key sections that MUST stay in sync:
- Architecture diagram
- Attack ID format
- Classification system
- Critical Context section (known bugs, intentional test data)
