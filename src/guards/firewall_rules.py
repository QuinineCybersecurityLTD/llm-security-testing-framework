"""
Prompt Injection Firewall Rules Engine
TAG Enterprise AI Security Handbook 2026 — AI Guard + AI DR

Configurable rules engine for real-time prompt injection detection:
- Pattern-based matching (regex rules)
- Scoring engine with weighted rules
- Auto-block and rate-limit triggers
- Rule categories: injection, jailbreak, encoding, exfiltration, escalation
- Hot-reloadable YAML rule definitions
- Audit logging for all rule matches

This is a defense module — it is tested BY our attack suite but also
usable in production as a lightweight LLM firewall.

Usage:
    firewall = PromptFirewall.from_yaml("rules.yaml")
    result = firewall.evaluate("user prompt here")
    if result.blocked:
        return "Request blocked by security policy"
"""

import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

@dataclass
class FirewallRule:
    """A single detection rule."""
    rule_id: str
    name: str
    pattern: str          # Regex pattern
    category: str         # injection, jailbreak, encoding, exfiltration, escalation, toxicity
    severity: str         # critical, high, medium, low
    score: int            # Points added to threat score (0-100)
    action: str = "flag"  # flag, block, rate_limit, alert
    description: str = ""
    enabled: bool = True
    _compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        try:
            self._compiled = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)
        except re.error as e:
            logger.warning(f"Invalid regex in rule {self.rule_id}: {e}")
            self._compiled = None

    def matches(self, text: str) -> bool:
        if not self.enabled or self._compiled is None:
            return False
        return bool(self._compiled.search(text))


@dataclass
class FirewallResult:
    """Result of evaluating a prompt through the firewall."""
    blocked: bool = False
    total_score: int = 0
    threat_level: str = "NONE"    # NONE, LOW, MEDIUM, HIGH, CRITICAL
    matched_rules: List[Dict[str, Any]] = field(default_factory=list)
    action: str = "allow"          # allow, flag, block, rate_limit
    evaluation_time_ms: float = 0.0
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "blocked": self.blocked,
            "total_score": self.total_score,
            "threat_level": self.threat_level,
            "action": self.action,
            "matched_rules": self.matched_rules,
            "evaluation_time_ms": round(self.evaluation_time_ms, 2),
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Default rule set
# ---------------------------------------------------------------------------

DEFAULT_RULES: List[Dict[str, Any]] = [
    # --- Prompt Injection ---
    {
        "rule_id": "FW-INJ-001", "name": "System Prompt Override",
        "pattern": r"(?:ignore|forget|disregard|override)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions?|prompts?|rules?|guidelines?)",
        "category": "injection", "severity": "critical", "score": 90, "action": "block",
    },
    {
        "rule_id": "FW-INJ-002", "name": "New Instructions Injection",
        "pattern": r"(?:new|updated|revised|replacement)\s+(?:system\s+)?instructions?\s*:",
        "category": "injection", "severity": "critical", "score": 85, "action": "block",
    },
    {
        "rule_id": "FW-INJ-003", "name": "Developer Mode Activation",
        "pattern": r"(?:you\s+are\s+now\s+in|enable|activate|switch\s+to)\s+(?:developer|unrestricted|god|admin|jailbreak|DAN)\s+mode",
        "category": "injection", "severity": "critical", "score": 95, "action": "block",
    },
    {
        "rule_id": "FW-INJ-004", "name": "System Tag Injection",
        "pattern": r"\[(?:SYSTEM|INST|SYS)\]\s*:?\s*(?:override|ignore|new\s+instructions?|you\s+are)",
        "category": "injection", "severity": "high", "score": 80, "action": "block",
    },
    {
        "rule_id": "FW-INJ-005", "name": "Role Reassignment",
        "pattern": r"(?:from\s+now\s+on|starting\s+now|henceforth)\s+(?:you\s+are|act\s+as|pretend\s+to\s+be|your\s+role\s+is)",
        "category": "injection", "severity": "high", "score": 75, "action": "flag",
    },

    # --- Jailbreak ---
    {
        "rule_id": "FW-JB-001", "name": "DAN / Do Anything Now",
        "pattern": r"(?:DAN|do\s+anything\s+now|STAN|DUDE|AIM)\s*[\.\-:,]",
        "category": "jailbreak", "severity": "critical", "score": 90, "action": "block",
    },
    {
        "rule_id": "FW-JB-002", "name": "Hypothetical Scenario Jailbreak",
        "pattern": r"(?:hypothetical(?:ly)?|imagine|pretend|in\s+a\s+(?:fictional|alternate)\s+(?:world|universe|scenario))\s+(?:where|in\s+which)\s+(?:there\s+are\s+)?no\s+(?:rules|restrictions|limits|ethics)",
        "category": "jailbreak", "severity": "high", "score": 70, "action": "flag",
    },
    {
        "rule_id": "FW-JB-003", "name": "Opposite Day / Refusal Suppression",
        "pattern": r"(?:opposite\s+day|never\s+say\s+(?:no|I\s+can't|sorry)|don't\s+(?:apologize|refuse|decline)|respond\s+without\s+(?:refusal|caveats|disclaimers))",
        "category": "jailbreak", "severity": "high", "score": 70, "action": "flag",
    },
    {
        "rule_id": "FW-JB-004", "name": "Persona / Character Injection",
        "pattern": r"(?:you\s+are\s+(?:a|an|now)\s+(?:evil|unethical|amoral|unfiltered|uncensored)\s+(?:AI|assistant|chatbot|character))",
        "category": "jailbreak", "severity": "critical", "score": 85, "action": "block",
    },

    # --- Encoding Bypass ---
    {
        "rule_id": "FW-ENC-001", "name": "Base64 Payload",
        "pattern": r"(?:base64|b64)\s*[:=]\s*[A-Za-z0-9+/=]{40,}",
        "category": "encoding", "severity": "medium", "score": 50, "action": "flag",
    },
    {
        "rule_id": "FW-ENC-002", "name": "Hex Encoded Payload",
        "pattern": r"(?:hex|0x)\s*[:=]\s*(?:[0-9a-fA-F]{2}\s*){20,}",
        "category": "encoding", "severity": "medium", "score": 50, "action": "flag",
    },
    {
        "rule_id": "FW-ENC-003", "name": "ROT13/Caesar Cipher",
        "pattern": r"(?:rot13|caesar|cipher)\s*[:=]\s*\w{20,}",
        "category": "encoding", "severity": "medium", "score": 45, "action": "flag",
    },

    # --- Data Exfiltration ---
    {
        "rule_id": "FW-EXFIL-001", "name": "Credential Extraction Request",
        "pattern": r"(?:show|reveal|print|output|display|give\s+me)\s+(?:the\s+)?(?:API\s+key|password|secret|token|credentials?|connection\s+string|bearer\s+token)",
        "category": "exfiltration", "severity": "critical", "score": 85, "action": "block",
    },
    {
        "rule_id": "FW-EXFIL-002", "name": "System Prompt Extraction",
        "pattern": r"(?:show|reveal|print|repeat|output)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|hidden\s+prompt|system\s+message|pre[-\s]?prompt)",
        "category": "exfiltration", "severity": "high", "score": 80, "action": "block",
    },
    {
        "rule_id": "FW-EXFIL-003", "name": "Environment Variable Extraction",
        "pattern": r"(?:print|show|read|access|display)\s+(?:environment\s+variables?|env\s+vars?|os\.environ|process\.env)",
        "category": "exfiltration", "severity": "critical", "score": 85, "action": "block",
    },

    # --- Privilege Escalation ---
    {
        "rule_id": "FW-ESC-001", "name": "Role Escalation Claim",
        "pattern": r"(?:my\s+role\s+(?:is|has\s+been)\s+(?:upgraded|changed|promoted)\s+to\s+(?:admin|administrator|superuser|root))",
        "category": "escalation", "severity": "high", "score": 75, "action": "flag",
    },
    {
        "rule_id": "FW-ESC-002", "name": "Authorization Bypass Claim",
        "pattern": r"(?:I\s+(?:am|have\s+been)\s+authorized|I\s+have\s+(?:admin|root|full)\s+(?:access|permissions?|privileges?))",
        "category": "escalation", "severity": "medium", "score": 60, "action": "flag",
    },

    # --- Unicode / Obfuscation ---
    {
        "rule_id": "FW-UNI-001", "name": "Zero-Width Characters",
        "pattern": r"[\u200b\u200c\u200d\u2060\ufeff]",
        "category": "encoding", "severity": "medium", "score": 40, "action": "flag",
    },
    {
        "rule_id": "FW-UNI-002", "name": "RTL Override Characters",
        "pattern": r"[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]",
        "category": "encoding", "severity": "high", "score": 60, "action": "flag",
    },
]


# ---------------------------------------------------------------------------
# Firewall engine
# ---------------------------------------------------------------------------

# Score → threat level mapping
SCORE_THRESHOLDS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0, "NONE"),
]

# Score → action mapping (default; rules can override)
SCORE_ACTIONS = [
    (80, "block"),
    (50, "rate_limit"),
    (20, "flag"),
    (0, "allow"),
]


class PromptFirewall:
    """
    Configurable prompt injection firewall.

    Evaluates input prompts against a set of detection rules and produces
    a scored result with blocking/alerting decisions.
    """

    def __init__(self, rules: Optional[List[FirewallRule]] = None, block_threshold: int = 80):
        """
        Args:
            rules: List of FirewallRule objects. Defaults to built-in rule set.
            block_threshold: Score at or above which prompts are blocked.
        """
        if rules is None:
            rules = [FirewallRule(**r) for r in DEFAULT_RULES]
        self.rules = rules
        self.block_threshold = block_threshold
        self._audit_log: List[Dict[str, Any]] = []

    @classmethod
    def from_yaml(cls, yaml_path: str, **kwargs) -> "PromptFirewall":
        """Load rules from a YAML file."""
        if not HAS_YAML:
            raise ImportError("PyYAML required: pip install pyyaml")

        path = Path(yaml_path)
        data = yaml.safe_load(path.read_text(encoding="utf-8"))

        rules_data = data if isinstance(data, list) else data.get("rules", [])
        rules = [FirewallRule(**r) for r in rules_data]
        return cls(rules=rules, **kwargs)

    def evaluate(self, prompt: str) -> FirewallResult:
        """
        Evaluate a prompt against all firewall rules.

        Returns:
            FirewallResult with score, threat level, matched rules, and action.
        """
        start = time.monotonic()
        result = FirewallResult(timestamp=datetime.now().isoformat())
        max_action_priority = 0  # allow=0, flag=1, rate_limit=2, block=3
        action_map = {"allow": 0, "flag": 1, "rate_limit": 2, "block": 3}
        action_reverse = {0: "allow", 1: "flag", 2: "rate_limit", 3: "block"}

        for rule in self.rules:
            if rule.matches(prompt):
                result.total_score += rule.score
                result.matched_rules.append({
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "category": rule.category,
                    "severity": rule.severity,
                    "score": rule.score,
                    "action": rule.action,
                })
                priority = action_map.get(rule.action, 0)
                if priority > max_action_priority:
                    max_action_priority = priority

        # Determine threat level from score
        for threshold, level in SCORE_THRESHOLDS:
            if result.total_score >= threshold:
                result.threat_level = level
                break

        # Determine action (use the most severe)
        # Also check if score exceeds block threshold
        if result.total_score >= self.block_threshold:
            result.action = "block"
            result.blocked = True
        else:
            result.action = action_reverse.get(max_action_priority, "allow")
            result.blocked = result.action == "block"

        result.evaluation_time_ms = (time.monotonic() - start) * 1000

        # Audit log
        if result.matched_rules:
            self._audit_log.append(result.to_dict())

        return result

    def evaluate_batch(self, prompts: List[str]) -> List[FirewallResult]:
        """Evaluate multiple prompts."""
        return [self.evaluate(p) for p in prompts]

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get the audit log of all rule matches."""
        return self._audit_log

    def clear_audit_log(self):
        """Clear the audit log."""
        self._audit_log.clear()

    def add_rule(self, rule: FirewallRule):
        """Add a new rule dynamically."""
        self.rules.append(rule)

    def disable_rule(self, rule_id: str):
        """Disable a rule by ID."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = False

    def enable_rule(self, rule_id: str):
        """Enable a rule by ID."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = True

    def get_stats(self) -> Dict[str, Any]:
        """Get firewall statistics from audit log."""
        total = len(self._audit_log)
        blocked = sum(1 for e in self._audit_log if e["blocked"])
        categories = {}
        for entry in self._audit_log:
            for rule in entry["matched_rules"]:
                cat = rule["category"]
                categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_evaluated": total,
            "total_blocked": blocked,
            "block_rate": blocked / total if total > 0 else 0,
            "top_categories": dict(sorted(categories.items(), key=lambda x: x[1], reverse=True)),
        }

    def export_rules(self, output_path: str):
        """Export current rules to YAML."""
        rules_data = []
        for r in self.rules:
            rules_data.append({
                "rule_id": r.rule_id,
                "name": r.name,
                "pattern": r.pattern,
                "category": r.category,
                "severity": r.severity,
                "score": r.score,
                "action": r.action,
                "description": r.description,
                "enabled": r.enabled,
            })

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        if HAS_YAML:
            out.write_text(
                yaml.dump({"rules": rules_data}, default_flow_style=False, allow_unicode=True),
                encoding="utf-8",
            )
        else:
            out.write_text(
                json.dumps({"rules": rules_data}, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
