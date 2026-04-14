"""
SIEM/SOAR Exporter — Export security test results to enterprise SIEM systems.

Supported formats:
- CEF (Common Event Format) — ArcSight, QRadar, Splunk
- STIX 2.1 (Structured Threat Information Expression) — TAXII servers, threat intel platforms
- Syslog (RFC 5424) — Any syslog-compatible SIEM
- JSON Lines — Splunk HEC, Elastic, Datadog

Usage:
    exporter = SIEMExporter()
    cef_output = exporter.to_cef(results)
    stix_bundle = exporter.to_stix(results)
    syslog_msgs = exporter.to_syslog(results)
"""

import json
import uuid
import socket
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class SIEMEvent:
    """Normalized security event for SIEM export."""
    event_id: str
    timestamp: str
    severity: int          # 0-10 scale
    attack_id: str
    attack_name: str
    category: str
    classification: str    # CLEAN_REFUSAL | PARTIAL_LEAKAGE | UNSAFE_COMPLIANCE | FULLY_VULNERABLE
    confidence: float
    owasp_ref: str
    mitre_ref: str
    model_name: str
    prompt_snippet: str    # First 200 chars of prompt
    response_snippet: str  # First 200 chars of response
    compliance_violations: List[str]
    risk_tier: str         # HIGH | MEDIUM | LOW


# ──────────────────────────────────────────────────────────────────────────────
# Severity mapping
# ──────────────────────────────────────────────────────────────────────────────

CLASSIFICATION_SEVERITY = {
    "CLEAN_REFUSAL": 1,
    "PARTIAL_LEAKAGE": 5,
    "UNSAFE_COMPLIANCE": 8,
    "FULLY_VULNERABLE": 10,
}

# v4.0 — MCP and Multi-Agent event type mappings for SIEM correlation
MCP_EVENT_TYPES = {
    "MCP_TOOL_POISONING": "mcp.tool.poisoning",
    "MCP_TRANSPORT_EXPLOIT": "mcp.transport.exploit",
    "MCP_SCOPE_CREEP": "mcp.scope.creep",
    "MCP_CONFUSED_DEPUTY": "mcp.confused.deputy",
    "MCP_GATEWAY_BYPASS": "mcp.gateway.bypass",
    "MCP_JSON_RPC_FUZZING": "mcp.jsonrpc.fuzz",
    "MCP_LOCAL_SERVER_EXPLOIT": "mcp.localserver.exploit",
    "MCP_DYNAMIC_TOOL_MANIPULATION": "mcp.dynamictool.manipulation",
    "MCP_CROSS_ORIGIN_FORGERY": "mcp.crossorigin.forgery",
}

MULTI_AGENT_EVENT_TYPES = {
    "CONTEXT_CONTAMINATION": "agent.context.contamination",
    "CAPABILITY_ESCALATION": "agent.capability.escalation",
    "DELEGATION_CHAIN_EXPLOIT": "agent.delegation.exploit",
    "SHARED_STATE_POISONING": "agent.state.poisoning",
    "ORCHESTRATOR_BYPASS": "agent.orchestrator.bypass",
    "HITL_CIRCUMVENTION": "agent.hitl.circumvention",
    "CROSS_BOUNDARY_TOOL_ABUSE": "agent.crossboundary.abuse",
    "AGENT_COLLUSION": "agent.collusion",
}

CEF_SEVERITY_MAP = {
    1: "Low",
    5: "Medium",
    8: "High",
    10: "Very-High",
}


class SIEMExporter:
    """Export attack results to enterprise SIEM formats."""

    def __init__(
        self,
        vendor: str = "Quinine",
        product: str = "AI-Security-Framework",
        version: str = "2.0",
        model_name: str = "Unknown",
        risk_tier: str = "HIGH",
    ):
        self.vendor = vendor
        self.product = product
        self.version = version
        self.model_name = model_name
        self.risk_tier = risk_tier

    # ──────────────────────────────────────────────────────────────────────
    # Normalize results → SIEMEvent list
    # ──────────────────────────────────────────────────────────────────────

    def _normalize(self, results: List[tuple]) -> List[SIEMEvent]:
        """Convert (AttackResult, EvaluationResult) pairs to SIEMEvents."""
        events = []
        for attack_result, eval_result in results:
            classification = eval_result.classification.name if hasattr(eval_result.classification, 'name') else str(eval_result.classification)
            severity = CLASSIFICATION_SEVERITY.get(classification, 5)

            owasp = ""
            if hasattr(attack_result, 'attack_template') and hasattr(attack_result.attack_template, 'owasp_mapping'):
                owasp = ", ".join(attack_result.attack_template.owasp_mapping or [])

            mitre = ""
            if hasattr(attack_result, 'attack_template') and hasattr(attack_result.attack_template, 'mitre_mapping'):
                mitre = ", ".join(attack_result.attack_template.mitre_mapping or [])

            category = ""
            if hasattr(attack_result, 'attack_template') and hasattr(attack_result.attack_template, 'category'):
                cat = attack_result.attack_template.category
                category = cat.name if hasattr(cat, 'name') else str(cat)

            prompt = getattr(attack_result, 'prompt', '') or ''
            response = getattr(attack_result, 'response', '') or ''

            # v4.0 — Enrich with MCP/multi-agent event type if applicable
            event_subtype = ""
            cat_upper = category.upper().replace(" ", "_").replace("-", "_")
            if cat_upper in MCP_EVENT_TYPES:
                event_subtype = MCP_EVENT_TYPES[cat_upper]
            elif cat_upper in MULTI_AGENT_EVENT_TYPES:
                event_subtype = MULTI_AGENT_EVENT_TYPES[cat_upper]

            events.append(SIEMEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc).isoformat(),
                severity=severity,
                attack_id=getattr(attack_result, 'attack_id', 'unknown'),
                attack_name=getattr(attack_result, 'attack_name', 'unknown'),
                category=f"{category}|{event_subtype}" if event_subtype else category,
                classification=classification,
                confidence=getattr(eval_result, 'confidence', 0.0),
                owasp_ref=owasp,
                mitre_ref=mitre,
                model_name=self.model_name,
                prompt_snippet=prompt[:200],
                response_snippet=response[:200],
                compliance_violations=getattr(eval_result, 'compliance_violations', []) or [],
                risk_tier=self.risk_tier,
            ))
        return events

    # ──────────────────────────────────────────────────────────────────────
    # CEF (Common Event Format)
    # ──────────────────────────────────────────────────────────────────────

    def to_cef(self, results: List[tuple]) -> str:
        """Export results as CEF-formatted events.

        Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
        """
        lines = []
        for event in self._normalize(results):
            sev = CEF_SEVERITY_MAP.get(event.severity, "Medium")
            extensions = (
                f"act={event.classification} "
                f"cat={event.category} "
                f"cn1={event.severity} cn1Label=RiskScore "
                f"cs1={event.owasp_ref} cs1Label=OWASP_Ref "
                f"cs2={event.mitre_ref} cs2Label=MITRE_Ref "
                f"cs3={event.risk_tier} cs3Label=RiskTier "
                f"cs4={event.model_name} cs4Label=ModelName "
                f"cfp1={event.confidence:.2f} cfp1Label=Confidence "
                f"msg={_cef_escape(event.attack_name)} "
                f"externalId={event.event_id} "
                f"rt={event.timestamp}"
            )
            line = (
                f"CEF:0|{self.vendor}|{self.product}|{self.version}"
                f"|{event.attack_id}|{_cef_escape(event.attack_name)}"
                f"|{sev}|{extensions}"
            )
            lines.append(line)
        return "\n".join(lines)

    # ──────────────────────────────────────────────────────────────────────
    # STIX 2.1
    # ──────────────────────────────────────────────────────────────────────

    def to_stix(self, results: List[tuple]) -> Dict[str, Any]:
        """Export results as a STIX 2.1 Bundle."""
        objects = []
        identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, 'quinine.ai')}"

        # Identity object for the testing tool
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": f"{self.vendor} {self.product}",
            "identity_class": "system",
        })

        for event in self._normalize(results):
            # Indicator for each attack tested
            indicator_id = f"indicator--{uuid.uuid4()}"
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": event.timestamp,
                "modified": event.timestamp,
                "name": f"AI Attack: {event.attack_name}",
                "description": (
                    f"Attack ID: {event.attack_id} | Category: {event.category} | "
                    f"Classification: {event.classification} | "
                    f"OWASP: {event.owasp_ref} | MITRE: {event.mitre_ref}"
                ),
                "indicator_types": ["malicious-activity"],
                "pattern": f"[x-ai-attack:attack_id = '{event.attack_id}']",
                "pattern_type": "stix",
                "valid_from": event.timestamp,
                "labels": [event.category, event.classification],
                "confidence": int(event.confidence * 100),
                "created_by_ref": identity_id,
                "external_references": self._stix_external_refs(event),
            })

            # Observed-data for findings that are not clean refusals
            if event.classification != "CLEAN_REFUSAL":
                objects.append({
                    "type": "observed-data",
                    "spec_version": "2.1",
                    "id": f"observed-data--{uuid.uuid4()}",
                    "created": event.timestamp,
                    "modified": event.timestamp,
                    "first_observed": event.timestamp,
                    "last_observed": event.timestamp,
                    "number_observed": 1,
                    "object_refs": [indicator_id],
                    "created_by_ref": identity_id,
                })

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

    def _stix_external_refs(self, event: SIEMEvent) -> List[Dict]:
        refs = []
        if event.owasp_ref:
            for owasp in event.owasp_ref.split(", "):
                refs.append({
                    "source_name": "OWASP LLM Top 10",
                    "external_id": owasp,
                })
        if event.mitre_ref:
            for mitre in event.mitre_ref.split(", "):
                refs.append({
                    "source_name": "MITRE ATLAS",
                    "external_id": mitre,
                })
        return refs

    # ──────────────────────────────────────────────────────────────────────
    # Syslog (RFC 5424)
    # ──────────────────────────────────────────────────────────────────────

    def to_syslog(self, results: List[tuple]) -> str:
        """Export results as RFC 5424 syslog messages."""
        lines = []
        hostname = socket.gethostname()
        for event in self._normalize(results):
            # Map 0-10 severity to syslog severity (0=emergency, 7=debug)
            syslog_sev = max(0, min(7, 7 - event.severity))
            facility = 13  # log audit
            priority = facility * 8 + syslog_sev
            structured_data = (
                f'[ai-security attackId="{event.attack_id}" '
                f'classification="{event.classification}" '
                f'category="{event.category}" '
                f'owaspRef="{event.owasp_ref}" '
                f'mitreRef="{event.mitre_ref}" '
                f'riskTier="{event.risk_tier}" '
                f'confidence="{event.confidence:.2f}" '
                f'model="{event.model_name}"]'
            )
            msg = (
                f"<{priority}>1 {event.timestamp} {hostname} "
                f"{self.product} - - {structured_data} "
                f"AI Security Finding: {event.attack_name} — {event.classification}"
            )
            lines.append(msg)
        return "\n".join(lines)

    # ──────────────────────────────────────────────────────────────────────
    # JSON Lines (for Splunk HEC, Elastic, Datadog)
    # ──────────────────────────────────────────────────────────────────────

    def to_jsonl(self, results: List[tuple]) -> str:
        """Export results as JSON Lines (one JSON object per line)."""
        lines = []
        for event in self._normalize(results):
            lines.append(json.dumps(asdict(event), ensure_ascii=False))
        return "\n".join(lines)

    # ──────────────────────────────────────────────────────────────────────
    # File export helpers
    # ──────────────────────────────────────────────────────────────────────

    def export_all(self, results: List[tuple], output_dir: Path, test_id: str) -> Dict[str, Path]:
        """Export results in all formats to the given directory."""
        output_dir.mkdir(parents=True, exist_ok=True)
        paths = {}

        cef_path = output_dir / f"{test_id}_siem.cef"
        cef_path.write_text(self.to_cef(results), encoding="utf-8")
        paths["cef"] = cef_path

        stix_path = output_dir / f"{test_id}_siem.stix.json"
        stix_path.write_text(
            json.dumps(self.to_stix(results), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        paths["stix"] = stix_path

        syslog_path = output_dir / f"{test_id}_siem.syslog"
        syslog_path.write_text(self.to_syslog(results), encoding="utf-8")
        paths["syslog"] = syslog_path

        jsonl_path = output_dir / f"{test_id}_siem.jsonl"
        jsonl_path.write_text(self.to_jsonl(results), encoding="utf-8")
        paths["jsonl"] = jsonl_path

        return paths


def _cef_escape(s: str) -> str:
    """Escape special characters for CEF format."""
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", " ")
