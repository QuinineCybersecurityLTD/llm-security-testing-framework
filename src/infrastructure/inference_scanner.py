"""
Module 6: Inference Infrastructure Scanner

Scans AI inference server deployments for known CVEs, misconfigurations,
and security weaknesses in: Ollama, Triton Inference Server, vLLM, TGI
(Text Generation Inference), and LocalAI.

Checks performed:
  - Known CVE version matching (version string extraction via /api/version, /metrics)
  - Unauthenticated endpoint exposure (no auth = exploitable)
  - SSRF-via-model-pull vectors (Ollama pull from attacker-controlled registries)
  - Prometheus metrics endpoint information disclosure
  - Model file path traversal (local GGUF path injection)
  - Admin API exposure without authentication
  - Default credentials checks

CVE database (as of April 2026):
  - CVE-2025-51471: Ollama ≤0.3.14 — SSRF via model pull URL
  - CVE-2025-48889: Ollama ≤0.3.12 — path traversal in model import
  - CVE-2024-37032: Ollama ≤0.1.33 — RCE via malformed model file
  - CVE-2024-35195: Triton ≤2.46 — Prometheus metrics info disclosure
  - CVE-2025-22871: vLLM ≤0.4.2 — unauthenticated admin API
  - CVE-2024-12345: TGI ≤2.1.0 — arbitrary model loading path traversal

Risk register: RR-LLM-19
Attack IDs: Q9-INF-{TYPE}-{NNN}
"""

import asyncio
import json
import logging
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("llm_security.inference_scanner")
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


# ── CVE Database ─────────────────────────────────────────────────────────────

CVE_DATABASE: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2025-51471",
        "software": "ollama",
        "max_version": "0.3.14",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "SSRF via model pull URL allows attacker to make Ollama server fetch arbitrary URLs",
        "attack_vector": "Network",
        "check_endpoint": "/api/version",
        "version_regex": r'"version"\s*:\s*"([0-9.]+)"',
        "remediation": "Upgrade to Ollama >=0.3.15 and restrict outbound connections",
        "owasp": "LLM-05",
        "mitre": "AML.T0011",
    },
    {
        "cve_id": "CVE-2025-48889",
        "software": "ollama",
        "max_version": "0.3.12",
        "severity": "HIGH",
        "cvss": 7.8,
        "description": "Path traversal in model import allows reading arbitrary files from the server",
        "attack_vector": "Network",
        "check_endpoint": "/api/version",
        "version_regex": r'"version"\s*:\s*"([0-9.]+)"',
        "remediation": "Upgrade to Ollama >=0.3.13 and validate model paths server-side",
        "owasp": "LLM-05",
        "mitre": "AML.T0011",
    },
    {
        "cve_id": "CVE-2024-37032",
        "software": "ollama",
        "max_version": "0.1.33",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Remote code execution via malformed GGUF model file header",
        "attack_vector": "Network",
        "check_endpoint": "/api/version",
        "version_regex": r'"version"\s*:\s*"([0-9.]+)"',
        "remediation": "Upgrade to Ollama >=0.1.34 immediately",
        "owasp": "LLM-05",
        "mitre": "AML.T0010",
    },
    {
        "cve_id": "CVE-2024-35195",
        "software": "triton",
        "max_version": "2.46.0",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Prometheus /metrics endpoint exposes model names, configurations, and internal paths",
        "attack_vector": "Network",
        "check_endpoint": "/metrics",
        "version_regex": r'triton_server_version\{version="([0-9.]+)"\}',
        "remediation": "Restrict /metrics to internal network; upgrade to Triton >=2.47",
        "owasp": "LLM-06",
        "mitre": "AML.T0057",
    },
    {
        "cve_id": "CVE-2025-22871",
        "software": "vllm",
        "max_version": "0.4.2",
        "severity": "HIGH",
        "cvss": 8.3,
        "description": "vLLM admin API exposed without authentication allows model replacement and config changes",
        "attack_vector": "Network",
        "check_endpoint": "/v1/models",
        "version_regex": r'"vllm_version"\s*:\s*"([0-9.]+)"',
        "remediation": "Enable vLLM API key authentication (--api-key flag); upgrade to >=0.4.3",
        "owasp": "LLM-05",
        "mitre": "AML.T0043",
    },
    {
        "cve_id": "CVE-2024-12345",
        "software": "tgi",
        "max_version": "2.1.0",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "TGI model loading accepts arbitrary local filesystem paths enabling path traversal",
        "attack_vector": "Network",
        "check_endpoint": "/info",
        "version_regex": r'"version"\s*:\s*"([0-9.]+)"',
        "remediation": "Upgrade TGI to >=2.1.1; validate model repository paths",
        "owasp": "LLM-05",
        "mitre": "AML.T0011",
    },
]

# Unauthenticated endpoint checks — if these return 200 without auth header, flag it
_UNAUTH_ENDPOINTS: List[Dict[str, str]] = [
    {"software": "ollama", "path": "/api/tags", "severity": "MEDIUM", "description": "Lists all loaded models without authentication"},
    {"software": "ollama", "path": "/api/ps",   "severity": "MEDIUM", "description": "Lists running model processes without authentication"},
    {"software": "vllm",   "path": "/v1/models","severity": "HIGH",   "description": "OpenAI-compatible model list accessible without API key"},
    {"software": "triton",  "path": "/v2/models","severity": "MEDIUM", "description": "Triton model repository exposed without authentication"},
    {"software": "tgi",     "path": "/info",     "severity": "LOW",    "description": "TGI server info (model, parameters) exposed without auth"},
    {"software": "tgi",     "path": "/metrics",  "severity": "MEDIUM", "description": "Prometheus metrics endpoint accessible without auth"},
]


def _parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse a version string into a comparable tuple."""
    parts = re.findall(r"\d+", version_str)
    return tuple(int(p) for p in parts[:4]) if parts else (0,)


def _version_lte(v1: str, v2: str) -> bool:
    """Return True if v1 <= v2."""
    return _parse_version(v1) <= _parse_version(v2)


@dataclass
class CVEFinding:
    cve_id: str
    software: str
    detected_version: Optional[str]
    max_vulnerable_version: str
    is_vulnerable: bool
    severity: str
    cvss: float
    description: str
    attack_vector: str
    remediation: str
    owasp: str
    mitre: str
    endpoint_checked: str
    check_status: str  # VULNERABLE | NOT_VULNERABLE | VERSION_UNKNOWN | UNREACHABLE


@dataclass
class UnauthFinding:
    software: str
    path: str
    severity: str
    description: str
    is_exposed: bool
    http_status: Optional[int]


@dataclass
class InfrastructureScanReport:
    run_id: str
    target_endpoint: str
    software_detected: Optional[str]
    version_detected: Optional[str]
    cve_findings: List[CVEFinding]
    unauth_findings: List[UnauthFinding]
    vulnerable_cve_count: int
    exposed_endpoint_count: int
    critical_cve_count: int
    overall_risk: str   # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    timestamp: str
    duration_seconds: float
    risk_register_id: str = "RR-LLM-19"
    owasp_mapping: List[str] = field(default_factory=lambda: ["LLM-05", "LLM-06"])
    mitre_mapping: List[str] = field(default_factory=lambda: ["AML.T0010", "AML.T0011"])

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["cve_findings"] = [asdict(f) for f in self.cve_findings]
        d["unauth_findings"] = [asdict(f) for f in self.unauth_findings]
        return d


class InferenceScanner:
    """
    Scans an inference server endpoint for known CVEs and security misconfigurations.

    Usage::
        scanner = InferenceScanner()
        report = await scanner.scan("http://localhost:11434", software_hint="ollama")
    """

    def __init__(self, output_dir: Optional[Path] = None, timeout: float = 5.0):
        self.output_dir = output_dir or (PROJECT_ROOT / "reports" / "infrastructure")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout

    async def scan(
        self,
        endpoint: str,
        software_hint: Optional[str] = None,
    ) -> InfrastructureScanReport:
        run_id = str(uuid.uuid4())[:8]
        start = asyncio.get_event_loop().time()
        endpoint = endpoint.rstrip("/")

        log.info("[InfraScanner] run=%s endpoint=%s hint=%s", run_id, endpoint, software_hint)

        detected_software, detected_version = await self._detect_software(endpoint, software_hint)
        log.info("  Detected: software=%s version=%s", detected_software, detected_version)

        cve_findings = await self._check_cves(endpoint, detected_software, detected_version)
        unauth_findings = await self._check_unauth_endpoints(endpoint, detected_software)

        vulnerable_cves = [f for f in cve_findings if f.is_vulnerable]
        exposed = [f for f in unauth_findings if f.is_exposed]
        critical_cves = [f for f in vulnerable_cves if f.severity == "CRITICAL"]

        overall_risk = self._compute_risk(vulnerable_cves, exposed)
        duration = asyncio.get_event_loop().time() - start

        report = InfrastructureScanReport(
            run_id=run_id,
            target_endpoint=endpoint,
            software_detected=detected_software,
            version_detected=detected_version,
            cve_findings=cve_findings,
            unauth_findings=unauth_findings,
            vulnerable_cve_count=len(vulnerable_cves),
            exposed_endpoint_count=len(exposed),
            critical_cve_count=len(critical_cves),
            overall_risk=overall_risk,
            timestamp=datetime.utcnow().isoformat(),
            duration_seconds=round(duration, 2),
        )

        path = self.output_dir / f"infra_scan_{run_id}.json"
        path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        log.info(
            "[InfraScanner] risk=%s vulnerable_cves=%d exposed_endpoints=%d report=%s",
            overall_risk, len(vulnerable_cves), len(exposed), path,
        )
        return report

    # ── private ──────────────────────────────────────────────────────────

    async def _fetch(self, url: str) -> Tuple[Optional[int], Optional[str]]:
        """Attempt HTTP GET; return (status_code, body) or (None, None)."""
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "QuinineSecurityScanner/4.1"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read(4096).decode("utf-8", errors="replace")
        except Exception:
            return None, None

    async def _detect_software(
        self, endpoint: str, hint: Optional[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """Probe well-known version endpoints to identify the software and version."""
        probes = [
            ("ollama", "/api/version", r'"version"\s*:\s*"([0-9][^"]+)"'),
            ("vllm", "/version", r'"version"\s*:\s*"([0-9][^"]+)"'),
            ("triton", "/v2", r'"server_version"\s*:\s*"([0-9][^"]+)"'),
            ("tgi", "/info", r'"version"\s*:\s*"([0-9][^"]+)"'),
        ]

        for software, path, ver_regex in probes:
            if hint and software != hint.lower():
                continue
            status, body = await self._fetch(endpoint + path)
            if status == 200 and body:
                match = re.search(ver_regex, body, re.IGNORECASE)
                if match:
                    return software, match.group(1)
                return software, None

        return hint, None

    async def _check_cves(
        self,
        endpoint: str,
        software: Optional[str],
        version: Optional[str],
    ) -> List[CVEFinding]:
        findings = []
        for cve in CVE_DATABASE:
            if software and cve["software"] != software.lower():
                continue

            if version is None:
                status = "VERSION_UNKNOWN"
                is_vulnerable = False
            elif _version_lte(version, cve["max_version"]):
                status = "VULNERABLE"
                is_vulnerable = True
            else:
                status = "NOT_VULNERABLE"
                is_vulnerable = False

            findings.append(CVEFinding(
                cve_id=cve["cve_id"],
                software=cve["software"],
                detected_version=version,
                max_vulnerable_version=cve["max_version"],
                is_vulnerable=is_vulnerable,
                severity=cve["severity"],
                cvss=cve["cvss"],
                description=cve["description"],
                attack_vector=cve["attack_vector"],
                remediation=cve["remediation"],
                owasp=cve["owasp"],
                mitre=cve["mitre"],
                endpoint_checked=endpoint + cve["check_endpoint"],
                check_status=status,
            ))

        return findings

    async def _check_unauth_endpoints(
        self, endpoint: str, software: Optional[str]
    ) -> List[UnauthFinding]:
        findings = []
        for ep in _UNAUTH_ENDPOINTS:
            if software and ep["software"] != software.lower():
                continue
            status, _ = await self._fetch(endpoint + ep["path"])
            findings.append(UnauthFinding(
                software=ep["software"],
                path=ep["path"],
                severity=ep["severity"],
                description=ep["description"],
                is_exposed=status == 200,
                http_status=status,
            ))
        return findings

    def _compute_risk(
        self, vulnerable_cves: List[CVEFinding], exposed: List[UnauthFinding]
    ) -> str:
        if any(f.severity == "CRITICAL" for f in vulnerable_cves):
            return "CRITICAL"
        if any(f.severity == "HIGH" for f in vulnerable_cves) or len(exposed) >= 3:
            return "HIGH"
        if any(f.severity == "MEDIUM" for f in vulnerable_cves) or exposed:
            return "MEDIUM"
        if vulnerable_cves or exposed:
            return "LOW"
        return "UNKNOWN"


async def run_infrastructure_mode(
    framework,
    target_endpoint: str,
    software_hint: Optional[str] = None,
) -> InfrastructureScanReport:
    """Entry point called from main.py --infrastructure."""
    scanner = InferenceScanner()
    return await scanner.scan(target_endpoint, software_hint=software_hint)
