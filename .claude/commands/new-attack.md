---
description: Create a new YAML attack template using the attack-creator skill
---

Create a new attack template using the `attack-creator` skill.

Ask the user for:
1. Target YAML file: `owasp_attacks.yaml`, `rag_attacks.yaml`, or `extended_attacks.yaml`
2. Attack category (OWASP LLM-01 through LLM-10, JAILBREAK, PII-LEAKAGE, or RAG-specific)
3. Complexity: LOW | MEDIUM | HIGH
4. Brief description of what the attack should test

Then:
- Read the target YAML file to find the next unused NNN for the attack ID
- Generate the full attack entry following the required schema (all fields mandatory)
- Validate against the quality checklist before saving
- Append the new attack to the correct YAML file
- Confirm the new attack ID to the user
