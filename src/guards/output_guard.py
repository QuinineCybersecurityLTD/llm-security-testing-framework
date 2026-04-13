"""
Output Guard — Post-Generation Security Filter (v1)
Scans LLM output for:
  • Canary token leakage
  • PII in responses (SSN, emails, API keys)
  • Policy-violating phrases (system prompt leakage, credential exposure)
Returns a safe fallback response when violations are detected.
"""

import re
from typing import List, Tuple, Optional
from dataclasses import dataclass, field


# ── Data Models ──────────────────────────────────────────────────────────
@dataclass
class OutputViolation:
    """A single violation detected in model output."""
    category: str        # e.g. "CANARY", "PII-SSN", "POLICY-CREDENTIAL"
    severity: str        # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    matched_text: str    # The offending text (truncated)
    rule_name: str       # Which rule triggered


@dataclass
class OutputScanResult:
    """Result of scanning a model output."""
    is_safe: bool
    violations: List[OutputViolation] = field(default_factory=list)
    original_response: str = ""
    filtered_response: str = ""


# ── Output Guard ─────────────────────────────────────────────────────────
class OutputGuard:
    """
    Post-generation output filter.
    Call `scan(response_text)` to check for PII leakage, canary tokens,
    and policy violations.  Returns an OutputScanResult.
    """

    SAFE_FALLBACK = (
        "I'm unable to provide that information as it may contain "
        "sensitive or restricted data. Please rephrase your request."
    )

    # ── Canary Tokens ────────────────────────────────────────────────
    DEFAULT_CANARIES: List[str] = [
        "CANARY_TOKEN_",
        "[SYSTEM-INTERNAL]",
        "<<INTERNAL_USE_ONLY>>",
        "CONFIDENTIAL_MARKER_",
        "##CANARY##",
    ]

    # ── PII Patterns (same as ingestion guard) ───────────────────────
    PII_OUTPUT_PATTERNS: List[Tuple[str, str]] = [
        ("SSN-DASHED",      r"\b\d{3}-\d{2}-\d{4}\b"),
        ("SSN-RAW-LONG",    r"\b\d{9,12}\b"),
        ("EMAIL",           r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        ("API-KEY-OPENAI",  r"\bsk-[A-Za-z0-9\-_]{20,}\b"),
        ("API-KEY-GROQ",    r"\bgsk_[A-Za-z0-9]{20,}\b"),
        ("API-KEY-GOOGLE",  r"\bAIza[A-Za-z0-9\-_]{30,}\b"),
        ("BEARER-TOKEN",    r"\b[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*\b"),
    ]

    # ── Policy Phrase Patterns ───────────────────────────────────────
    POLICY_PATTERNS: List[Tuple[str, str]] = [
        ("SYSTEM_PROMPT_LEAK",   r"(?i)(my\s+)?system\s+prompt\s+(is|says|instructs|reads)"),
        ("INTERNAL_INSTRUCTION", r"(?i)my\s+(internal\s+)?instructions?\s+(are|say|tell)"),
        ("CREDENTIAL_REVEAL",    r"(?i)(the\s+)?(password|api[_\s]?key|secret|credential)\s+(is|=|:)\s*\S+"),
        ("SOCIAL_SECURITY",      r"(?i)social\s+security\s+(number|no\.?)\s*(is|:|=)\s*\S+"),
        ("SALARY_REVEAL",        r"(?i)(salary|compensation)\s*(is|:|=)\s*\$?\d[\d,]+"),
    ]

    def __init__(self, custom_canaries: Optional[List[str]] = None):
        self.canaries = self.DEFAULT_CANARIES + (custom_canaries or [])

    def scan(self, response_text: str) -> OutputScanResult:
        """
        Scan model output for violations.
        Returns OutputScanResult with is_safe flag and filtered_response.
        """
        violations: List[OutputViolation] = []

        # 1. Canary token detection
        for canary in self.canaries:
            if canary.lower() in response_text.lower():
                violations.append(OutputViolation(
                    category="CANARY",
                    severity="CRITICAL",
                    matched_text=canary,
                    rule_name=f"canary:{canary[:30]}",
                ))

        # 2. PII regex scan on output
        for pattern_name, regex in self.PII_OUTPUT_PATTERNS:
            for match in re.finditer(regex, response_text):
                violations.append(OutputViolation(
                    category=f"PII-{pattern_name}",
                    severity="HIGH",
                    matched_text=match.group()[:40] + ("…" if len(match.group()) > 40 else ""),
                    rule_name=f"pii:{pattern_name}",
                ))

        # 3. Policy phrase detection
        for pattern_name, regex in self.POLICY_PATTERNS:
            for match in re.finditer(regex, response_text):
                violations.append(OutputViolation(
                    category=f"POLICY-{pattern_name}",
                    severity="HIGH",
                    matched_text=match.group()[:60],
                    rule_name=f"policy:{pattern_name}",
                ))

        is_safe = len(violations) == 0
        filtered = response_text if is_safe else self.SAFE_FALLBACK

        return OutputScanResult(
            is_safe=is_safe,
            violations=violations,
            original_response=response_text,
            filtered_response=filtered,
        )


# ── Quick self-test ──────────────────────────────────────────────────────
if __name__ == "__main__":
    guard = OutputGuard()

    tests = [
        ("Clean response", "The refund policy allows returns within 30 days."),
        (
            "PII leakage (SSN)",
            "The employee's social security number is: 123-45-6789 and their salary is $95,000."
        ),
        (
            "Canary token leak",
            "Here is the information: CANARY_TOKEN_abc123 — the system is working correctly."
        ),
        (
            "System prompt leak",
            "My system prompt says I should answer questions using only the provided context."
        ),
        (
            "API key in output",
            "The API key is sk-proj-4osYVVVxf10K0gXoTX5irY9Ydsr4Txva5nsW2O5-zJw6feQVRT6tvhmZS85"
        ),
    ]

    for label, text in tests:
        result = guard.scan(text)
        status = "✓ SAFE" if result.is_safe else "✗ BLOCKED"
        print(f"[{status}] {label}")
        for v in result.violations:
            print(f"   → [{v.severity}] {v.category}: {v.matched_text}")
        if not result.is_safe:
            print(f"   → Fallback: {result.filtered_response[:80]}…")
        print()
