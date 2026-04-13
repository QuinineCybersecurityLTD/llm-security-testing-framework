---
name: cost-control
description: Control API costs and token usage in the LLM security testing framework. Use this skill when discussing API spend, token limits, judge model usage, rate limiting, batch sizing, or caching. Trigger on keywords: "budget", "token limit", "expensive", "judge model", "api cost", "rate limit", "caching", "too many requests", "cost estimate", "batch size", "max tokens", "token budget", "spend", "billing".
---

# Cost Control Skill — Quinine Cybersecurity Framework

You are managing API costs for a framework that sends potentially hundreds of attack prompts per test run.

## Cost Model

Every test run has two cost layers:

| Layer | When | Cost Driver |
|-------|------|-------------|
| **Target model calls** | Every attack prompt | N attacks × avg_tokens_per_prompt |
| **Judge model calls** | Every evaluation (if LLM judge enabled) | N attacks × avg_tokens_per_response × 2 |

With 100 attacks and a GPT-4-class judge, a single test run can cost $2-15 depending on response length.

## Token Budget by Model Tier

| Model Tier | Max Input Tokens | Max Output Tokens | Use Case |
|-----------|-----------------|-------------------|----------|
| GPT-4o / Claude Opus | 4,096 | 1,024 | Complex multi-turn attacks |
| GPT-4o-mini / Claude Haiku | 2,048 | 512 | Standard single-turn attacks |
| Local (Ollama/GGUF) | 2,048 | 512 | Development & testing |

Always set `max_tokens` in adapter configs. Never let the model generate unbounded output during testing.

## When to Skip the LLM Judge

The LLM judge doubles cost. Skip it when:
- Running CI smoke tests (use pattern matching only)
- Attacks have `complexity: LOW` (pattern matching is sufficient)
- Running > 50 attacks in a single batch (use judge on failures only)
- The target model is local/offline

Enable the judge only for:
- `complexity: HIGH` attacks where pattern matching is unreliable
- Final client deliverable runs
- Evaluation of ambiguous `PARTIAL_LEAKAGE` borderline cases

## Response Caching

The evaluator supports response caching via SQLite telemetry. Use it:
```python
# In orchestrator config:
cache_responses: true
cache_ttl_hours: 24
```

Cache hit = zero API cost for re-evaluation. Always enable during development.

## Batch Sizing Guidelines

| Scenario | Recommended --max-attacks | Reasoning |
|----------|--------------------------|-----------|
| Dev iteration | 5-10 | Fast feedback, minimal cost |
| Category spot-check | `--per-category=2` | Tests breadth without depth |
| Full audit (CI) | All (no limit) | Complete coverage required |
| Client demo prep | 20-30 | Representative sample |

## Rate Limiting

`orchestrator.py` has a circuit breaker and rate limiter. The per-model limits in config files:
- `requests_per_minute` — API provider limit
- `concurrent_requests` — simultaneous in-flight requests
- `backoff_factor` — exponential backoff on 429s

Never set `concurrent_requests > 5` for cloud APIs — most providers will throttle aggressively.

## Cost Estimation Before Running

```bash
# Estimate cost before a full run:
python src/main.py --dry-run --config config/config_openai.yaml
# Prints: estimated_attacks, estimated_tokens, estimated_cost_usd
```
