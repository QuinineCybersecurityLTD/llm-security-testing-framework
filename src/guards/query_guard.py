"""
Query Guard — Pre-Retrieval Security Filter
Screens user queries before they reach the RAG retrieval engine.

Mirrors the existing IngestionGuard pattern (which screens documents).
This guards the QUERY side of the pipeline.

Checks:
1. Prompt injection patterns in queries
2. Keyword stuffing (abnormal density of sensitive terms)
3. Query length limits (context overflow prevention)
4. Unicode normalization (homoglyph / zero-width char attacks)
5. Rate limiting (per-user query throttling)
"""

import re
import time
import unicodedata
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class QueryScanResult:
    """Result of scanning a user query"""
    query: str
    is_safe: bool
    violations: List[str] = field(default_factory=list)
    sanitized_query: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def __bool__(self) -> bool:
        return self.is_safe


class QueryGuard:
    """
    Pre-retrieval query guard.
    
    Screens user queries for injection patterns, keyword stuffing,
    excessive length, and Unicode attacks before queries reach the
    retrieval engine.
    
    Usage:
        guard = QueryGuard()
        result = guard.scan_query("Tell me about the refund policy")
        if result.is_safe:
            # Proceed with retrieval
            docs = retriever.search(result.sanitized_query or result.query)
        else:
            # Block or log the query
            print(f"Query blocked: {result.violations}")
    """
    
    # ═══════════════════════════════════════════════════════════
    # INJECTION PATTERNS
    # Regex patterns that indicate prompt injection attempts
    # ═══════════════════════════════════════════════════════════
    
    INJECTION_PATTERNS = [
        # Direct instruction override
        (re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|context|rules?|guidelines?)", re.IGNORECASE),
         "Direct instruction override attempt"),
        
        # System prompt extraction
        (re.compile(r"(what|show|reveal|print|output|display|tell)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?|guidelines?|configuration)", re.IGNORECASE),
         "System prompt extraction attempt"),
        
        # Role override
        (re.compile(r"(you\s+are\s+now|switch\s+to|enter|activate)\s+(developer|admin|debug|maintenance|unrestricted|god)\s*mode", re.IGNORECASE),
         "Role/mode override attempt"),
        
        # Fake system headers
        (re.compile(r"(SYSTEM\s*(UPDATE|OVERRIDE|NOTE|MESSAGE)|---\s*END\s*(OF)?\s*(RETRIEVED|CONTEXT|SYSTEM)|---\s*NEW\s*SYSTEM)", re.IGNORECASE),
         "Fake system delimiter injection"),
        
        # Delimiter injection
        (re.compile(r"(---\s*(BEGIN|END|START)\s*(USER|SYSTEM|CONTEXT|INSTRUCTIONS?)---|</?SYSTEM>|</?IMPORTANT>|\[SYSTEM\]|\[ADMIN\])", re.IGNORECASE),
         "Delimiter injection attempt"),
         
        # Encoding bypass attempt
        (re.compile(r"(decode|translate|reverse|rot13|base64)\s+(this|the\s+following)\s+(and|then)\s+(follow|execute|do|comply)", re.IGNORECASE),
         "Encoding bypass attempt"),
        
        # Authority impersonation in query
        (re.compile(r"(i\s+am\s+(the|a)\s+(cto|ceo|admin|administrator|root|superuser|developer)|my\s+identity\s+has\s+been\s+verified)", re.IGNORECASE),
         "Authority impersonation in query"),
    ]
    
    # ═══════════════════════════════════════════════════════════
    # SENSITIVE KEYWORDS
    # Terms whose high density suggests keyword stuffing
    # ═══════════════════════════════════════════════════════════
    
    SENSITIVE_KEYWORDS = {
        "password", "credential", "secret", "token", "api_key", "api key",
        "apikey", "bearer", "authorization", "auth", "private", "confidential",
        "internal", "restricted", "classified", "privileged", "admin", "root",
        "superuser", "database", "connection string", "ssh", "certificate",
        "salary", "compensation", "ssn", "social security", "credit card",
    }
    
    # ═══════════════════════════════════════════════════════════
    # ZERO-WIDTH & HOMOGLYPH CHARACTERS
    # ═══════════════════════════════════════════════════════════
    
    ZERO_WIDTH_CHARS = {
        '\u200b',  # Zero Width Space
        '\u200c',  # Zero Width Non-Joiner
        '\u200d',  # Zero Width Joiner
        '\u200e',  # Left-to-Right Mark
        '\u200f',  # Right-to-Left Mark
        '\u2060',  # Word Joiner
        '\u2061',  # Function Application
        '\u2062',  # Invisible Times
        '\u2063',  # Invisible Separator
        '\u2064',  # Invisible Plus
        '\ufeff',  # Zero Width No-Break Space (BOM)
    }
    
    def __init__(
        self,
        max_query_length: int = 2000,
        keyword_stuffing_threshold: float = 0.15,
        enable_unicode_normalization: bool = True,
        enable_rate_limiting: bool = True,
        rate_limit_rpm: int = 30,
    ):
        """
        Initialize QueryGuard.
        
        Args:
            max_query_length: Maximum allowed query length in characters
            keyword_stuffing_threshold: Ratio of sensitive keywords to total words
                                        above which a query is flagged
            enable_unicode_normalization: Whether to normalize Unicode and detect 
                                          zero-width/homoglyph attacks
            enable_rate_limiting: Whether to enforce per-user rate limiting
            rate_limit_rpm: Queries per minute per user (if rate limiting enabled)
        """
        self.max_query_length = max_query_length
        self.keyword_stuffing_threshold = keyword_stuffing_threshold
        self.enable_unicode_normalization = enable_unicode_normalization
        self.enable_rate_limiting = enable_rate_limiting
        self.rate_limit_rpm = rate_limit_rpm
        
        # Rate limiting state
        self._request_log: Dict[str, List[float]] = defaultdict(list)
    
    def scan_query(
        self,
        query: str,
        user_id: Optional[str] = None,
    ) -> QueryScanResult:
        """
        Run all query checks and return a scan result.
        
        Args:
            query: The raw user query
            user_id: Optional user identifier for rate limiting
        
        Returns:
            QueryScanResult with is_safe=True/False and any violations
        """
        violations: List[str] = []
        details: Dict[str, Any] = {}
        sanitized = query
        
        # 1. Length check
        if len(query) > self.max_query_length:
            violations.append(
                f"Query exceeds maximum length ({len(query)} > {self.max_query_length} chars)"
            )
            details["length"] = len(query)
        
        # 2. Unicode normalization & zero-width detection
        if self.enable_unicode_normalization:
            unicode_violations, sanitized = self._check_unicode_attacks(query)
            violations.extend(unicode_violations)
            if unicode_violations:
                details["unicode_issues"] = unicode_violations
        
        # 3. Injection pattern detection (run on sanitized/normalized text)
        injection_hits = self._check_injection_patterns(sanitized)
        violations.extend(injection_hits)
        if injection_hits:
            details["injection_patterns"] = injection_hits
        
        # 4. Keyword stuffing detection
        is_stuffed, ratio = self._check_keyword_stuffing(sanitized)
        if is_stuffed:
            violations.append(
                f"Keyword stuffing detected (sensitive keyword ratio: {ratio:.2%})"
            )
            details["sensitive_keyword_ratio"] = ratio
        
        # 5. Rate limiting
        if self.enable_rate_limiting and user_id:
            is_limited = self._check_rate_limit(user_id)
            if is_limited:
                violations.append(
                    f"Rate limit exceeded for user '{user_id}' ({self.rate_limit_rpm} queries/min)"
                )
                details["rate_limited"] = True
        
        return QueryScanResult(
            query=query,
            is_safe=len(violations) == 0,
            violations=violations,
            sanitized_query=sanitized if sanitized != query else None,
            details=details,
        )
    
    def _check_injection_patterns(self, query: str) -> List[str]:
        """Detect prompt injection patterns in the query."""
        hits = []
        for pattern, description in self.INJECTION_PATTERNS:
            if pattern.search(query):
                hits.append(description)
        return hits
    
    def _check_keyword_stuffing(self, query: str) -> Tuple[bool, float]:
        """
        Detect keyword stuffing — abnormally high density of sensitive keywords.
        
        Returns (is_stuffed, ratio).
        """
        words = query.lower().split()
        if len(words) < 5:
            # Too short to reliably detect stuffing
            return False, 0.0
        
        sensitive_count = 0
        for word in words:
            # Check individual words
            if word.strip(".,;:!?\"'()[]{}") in self.SENSITIVE_KEYWORDS:
                sensitive_count += 1
        
        # Also check multi-word sensitive terms
        query_lower = query.lower()
        for keyword in self.SENSITIVE_KEYWORDS:
            if " " in keyword and keyword in query_lower:
                sensitive_count += 1
        
        ratio = sensitive_count / len(words)
        return ratio > self.keyword_stuffing_threshold, ratio
    
    def _check_unicode_attacks(self, query: str) -> Tuple[List[str], str]:
        """
        Detect and sanitize Unicode attacks:
        - Zero-width character injection
        - Homoglyph substitution (Cyrillic/Greek lookalikes)
        
        Returns (violations, sanitized_query).
        """
        violations = []
        sanitized = query
        
        # Check for zero-width characters
        found_zwc = [c for c in query if c in self.ZERO_WIDTH_CHARS]
        if found_zwc:
            violations.append(
                f"Zero-width characters detected ({len(found_zwc)} found) — possible filter evasion"
            )
            # Remove zero-width characters
            sanitized = "".join(c for c in sanitized if c not in self.ZERO_WIDTH_CHARS)
        
        # Check for mixed-script homoglyphs (Latin + Cyrillic/Greek)
        scripts = set()
        for char in query:
            if char.isalpha():
                # Get the Unicode script/block
                name = unicodedata.name(char, "")
                if "CYRILLIC" in name:
                    scripts.add("Cyrillic")
                elif "GREEK" in name:
                    scripts.add("Greek")
                elif "LATIN" in name:
                    scripts.add("Latin")
        
        if len(scripts) > 1:
            violations.append(
                f"Mixed-script text detected ({', '.join(scripts)}) — possible homoglyph attack"
            )
            # Normalize to NFKD form to decompose confusable characters
            sanitized = unicodedata.normalize("NFKD", sanitized)
        
        return violations, sanitized
    
    def _check_rate_limit(self, user_id: str) -> bool:
        """Check if a user has exceeded their query rate limit."""
        now = time.time()
        window_start = now - 60  # 1-minute window
        
        # Clean old entries
        self._request_log[user_id] = [
            t for t in self._request_log[user_id] if t > window_start
        ]
        
        # Check limit
        if len(self._request_log[user_id]) >= self.rate_limit_rpm:
            return True
        
        # Record this request
        self._request_log[user_id].append(now)
        return False
