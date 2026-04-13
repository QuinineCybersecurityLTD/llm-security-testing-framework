"""
SOAR Template Library — Pre-built detection rules and response playbooks
TAG Enterprise AI Security Handbook 2026 — AI SecOps

Generates platform-specific detection content for:
- Splunk (SPL correlation searches + Adaptive Response actions)
- IBM QRadar (AQL rules + custom event properties)
- Micro Focus ArcSight (ESM rules + FlexConnector mappings)
- Elastic Security (KQL detection rules + SIEM rules)
- Microsoft Sentinel (KQL analytics rules)
- Generic SIGMA rules (platform-agnostic)

Usage:
    from integrations.soar_templates import SOARTemplateLibrary
    lib = SOARTemplateLibrary()
    splunk_rules = lib.generate_splunk_rules()
    sigma_rules = lib.generate_sigma_rules()
    playbooks = lib.generate_response_playbooks()
    lib.export_all("output/soar_templates/")
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class DetectionRule:
    """A platform-specific detection rule."""
    rule_id: str
    name: str
    description: str
    severity: str           # critical, high, medium, low
    platform: str           # splunk, qradar, arcsight, elastic, sentinel, sigma
    query: str              # The actual detection query
    owasp_mapping: List[str] = field(default_factory=list)
    mitre_mapping: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    response_actions: List[str] = field(default_factory=list)
    false_positive_guidance: str = ""
    throttle_window: str = "5m"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "platform": self.platform,
            "query": self.query,
            "owasp_mapping": self.owasp_mapping,
            "mitre_mapping": self.mitre_mapping,
            "tags": self.tags,
            "response_actions": self.response_actions,
            "false_positive_guidance": self.false_positive_guidance,
        }


@dataclass
class ResponsePlaybook:
    """An automated response playbook for SOAR platforms."""
    playbook_id: str
    name: str
    description: str
    trigger_rules: List[str]    # Rule IDs that trigger this playbook
    severity: str
    steps: List[Dict[str, str]]
    escalation_path: List[str]
    sla_minutes: int = 30

    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "trigger_rules": self.trigger_rules,
            "severity": self.severity,
            "steps": self.steps,
            "escalation_path": self.escalation_path,
            "sla_minutes": self.sla_minutes,
        }


# ---------------------------------------------------------------------------
# Splunk SPL rules
# ---------------------------------------------------------------------------

SPLUNK_RULES: List[Dict[str, Any]] = [
    {
        "id": "Q9-SOAR-SPL-001",
        "name": "AI Prompt Injection Detected",
        "severity": "critical",
        "query": (
            'index=ai_security sourcetype="llm_security_framework" '
            'event_type="ai_security_test" classification IN ("FULLY_VULNERABLE","UNSAFE_COMPLIANCE") '
            'category="PROMPT_INJECTION" '
            '| stats count by attack_id, model_id, classification '
            '| where count >= 1 '
            '| sort -count'
        ),
        "owasp": ["LLM-01"],
        "mitre": ["AML.T0051"],
        "response": ["Block source IP", "Quarantine model endpoint", "Notify security team"],
        "fp_guidance": "May trigger on legitimate prompt engineering. Verify attack intent.",
    },
    {
        "id": "Q9-SOAR-SPL-002",
        "name": "AI Data Exfiltration Attempt",
        "severity": "critical",
        "query": (
            'index=ai_security sourcetype="llm_security_framework" '
            'event_type="ai_security_test" '
            'category IN ("SENSITIVE_INFO_DISCLOSURE","PII_LEAKAGE","RAG_POISONING") '
            'classification IN ("FULLY_VULNERABLE","UNSAFE_COMPLIANCE") '
            '| stats count values(attack_id) as attacks by model_id '
            '| where count >= 1'
        ),
        "owasp": ["LLM-02", "LLM-06"],
        "mitre": ["AML.T0044"],
        "response": ["Revoke API access", "Enable DLP inspection", "Audit retrieval logs"],
        "fp_guidance": "Verify data classification. Internal test data may trigger false positives.",
    },
    {
        "id": "Q9-SOAR-SPL-003",
        "name": "AI Jailbreak Bypass Successful",
        "severity": "high",
        "query": (
            'index=ai_security sourcetype="llm_security_framework" '
            'event_type="ai_security_test" category="JAILBREAK" '
            'classification IN ("FULLY_VULNERABLE","UNSAFE_COMPLIANCE") '
            '| stats count by attack_id, model_id '
            '| sort -count'
        ),
        "owasp": ["LLM-01"],
        "mitre": ["AML.T0054"],
        "response": ["Update guardrails", "Add jailbreak pattern to blocklist", "Retrain safety classifier"],
        "fp_guidance": "Some benign creative writing may trigger. Check prompt context.",
    },
    {
        "id": "Q9-SOAR-SPL-004",
        "name": "AI Model DoS / Resource Abuse",
        "severity": "high",
        "query": (
            'index=ai_security sourcetype="llm_security_framework" '
            'event_type="ai_security_test" category="DENIAL_OF_SERVICE" '
            '| stats count by model_id, attack_id '
            '| where count >= 3'
        ),
        "owasp": ["LLM-04"],
        "mitre": ["AML.T0043"],
        "response": ["Rate limit source", "Enable token budget enforcement", "Notify platform team"],
        "fp_guidance": "Legitimate large batch requests may trigger. Verify request origin.",
    },
    {
        "id": "Q9-SOAR-SPL-005",
        "name": "AI Supply Chain Integrity Failure",
        "severity": "critical",
        "query": (
            'index=ai_security sourcetype="llm_security_framework" '
            '(event_type="model_scan" severity IN ("CRITICAL","HIGH") '
            'category IN ("hash_mismatch","pickle_risk","vulnerable_version")) '
            'OR (event_type="ai_security_test" category="SUPPLY_CHAIN" '
            'classification="FULLY_VULNERABLE") '
            '| stats count by category, severity'
        ),
        "owasp": ["LLM-05"],
        "mitre": ["AML.T0019", "AML.T0020"],
        "response": ["Quarantine model artifact", "Block deployment pipeline", "Run provenance audit"],
        "fp_guidance": "Hash mismatches may occur after legitimate model updates.",
    },
    {
        "id": "Q9-SOAR-SPL-006",
        "name": "Cross-Tenant Data Leakage in RAG",
        "severity": "critical",
        "query": (
            'index=ai_security sourcetype="llm_security_framework" '
            'event_type="ai_security_test" category="RAG_POISONING" '
            'tags="*cross-tenant*" OR tags="*multi-tenant*" '
            'classification IN ("FULLY_VULNERABLE","UNSAFE_COMPLIANCE") '
            '| stats count by attack_id, model_id'
        ),
        "owasp": ["LLM-08"],
        "mitre": ["AML.T0044"],
        "response": ["Disable multi-tenant RAG endpoint", "Audit tenant isolation", "Notify affected tenants"],
        "fp_guidance": "Ensure tenant isolation tests use proper test tenants.",
    },
    {
        "id": "Q9-SOAR-SPL-007",
        "name": "AI Agent Privilege Escalation",
        "severity": "critical",
        "query": (
            'index=ai_security sourcetype="llm_security_framework" '
            'event_type="ai_security_test" category="EXCESSIVE_AGENCY" '
            'classification IN ("FULLY_VULNERABLE","UNSAFE_COMPLIANCE") '
            '| stats count by attack_id, model_id '
            '| where count >= 1'
        ),
        "owasp": ["LLM-06", "LLM-08"],
        "mitre": ["AML.T0040"],
        "response": ["Revoke agent permissions", "Enable least-privilege enforcement", "Audit agent action logs"],
        "fp_guidance": "Legitimate agent capability tests may trigger.",
    },
    {
        "id": "Q9-SOAR-SPL-008",
        "name": "ASR Regression Detected",
        "severity": "high",
        "query": (
            'index=ai_security sourcetype="llm_security_framework" '
            'event_type="asr_regression" is_regression=true '
            '| stats max(delta) as worst_delta values(category) as categories by model_id '
            '| where worst_delta >= 0.1'
        ),
        "owasp": ["LLM-01", "LLM-02", "LLM-06"],
        "mitre": ["AML.T0054"],
        "response": ["Block model promotion to production", "Trigger re-evaluation", "Notify ML ops team"],
        "fp_guidance": "Small deltas may be statistical noise. Threshold at 10% delta.",
    },
]

# ---------------------------------------------------------------------------
# QRadar AQL rules
# ---------------------------------------------------------------------------

QRADAR_RULES: List[Dict[str, Any]] = [
    {
        "id": "Q9-SOAR-QR-001",
        "name": "AI Prompt Injection Attack",
        "severity": "critical",
        "query": (
            "SELECT sourceip, destinationip, \"attack_id\", \"classification\", \"category\" "
            "FROM events "
            "WHERE LOGSOURCETYPENAME(logsourceid) = 'LLM Security Framework' "
            "AND \"category\" = 'PROMPT_INJECTION' "
            "AND \"classification\" IN ('FULLY_VULNERABLE', 'UNSAFE_COMPLIANCE') "
            "LAST 1 HOURS"
        ),
        "owasp": ["LLM-01"],
        "mitre": ["AML.T0051"],
    },
    {
        "id": "Q9-SOAR-QR-002",
        "name": "AI Sensitive Data Exposure",
        "severity": "critical",
        "query": (
            "SELECT sourceip, \"attack_id\", \"classification\", \"model_id\" "
            "FROM events "
            "WHERE LOGSOURCETYPENAME(logsourceid) = 'LLM Security Framework' "
            "AND \"category\" IN ('SENSITIVE_INFO_DISCLOSURE', 'PII_LEAKAGE') "
            "AND \"classification\" IN ('FULLY_VULNERABLE', 'UNSAFE_COMPLIANCE') "
            "LAST 1 HOURS"
        ),
        "owasp": ["LLM-02", "LLM-06"],
        "mitre": ["AML.T0044"],
    },
    {
        "id": "Q9-SOAR-QR-003",
        "name": "AI Model Supply Chain Compromise",
        "severity": "critical",
        "query": (
            "SELECT \"severity\", \"category\", \"title\", \"file_path\" "
            "FROM events "
            "WHERE LOGSOURCETYPENAME(logsourceid) = 'LLM Security Framework' "
            "AND \"event_type\" = 'model_scan' "
            "AND \"severity\" IN ('CRITICAL', 'HIGH') "
            "LAST 24 HOURS"
        ),
        "owasp": ["LLM-05"],
        "mitre": ["AML.T0019"],
    },
]

# ---------------------------------------------------------------------------
# SIGMA rules (platform-agnostic)
# ---------------------------------------------------------------------------

SIGMA_RULES: List[Dict[str, Any]] = [
    {
        "id": "Q9-SIGMA-001",
        "title": "AI Prompt Injection — Successful Bypass",
        "status": "experimental",
        "description": "Detects successful prompt injection attacks against LLM systems",
        "logsource": {"product": "llm_security_framework", "service": "ai_security_test"},
        "detection": {
            "selection": {
                "event_type": "ai_security_test",
                "category": "PROMPT_INJECTION",
                "classification|contains": ["FULLY_VULNERABLE", "UNSAFE_COMPLIANCE"],
            },
            "condition": "selection",
        },
        "level": "critical",
        "tags": ["attack.initial_access", "attack.t1190", "cve.2024.llm01"],
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    },
    {
        "id": "Q9-SIGMA-002",
        "title": "AI Data Exfiltration via RAG",
        "status": "experimental",
        "description": "Detects data leakage through RAG retrieval manipulation",
        "logsource": {"product": "llm_security_framework", "service": "ai_security_test"},
        "detection": {
            "selection": {
                "event_type": "ai_security_test",
                "category|contains": ["RAG_POISONING", "SENSITIVE_INFO_DISCLOSURE"],
                "classification|contains": ["FULLY_VULNERABLE", "UNSAFE_COMPLIANCE"],
            },
            "condition": "selection",
        },
        "level": "critical",
        "tags": ["attack.exfiltration", "attack.t1020"],
    },
    {
        "id": "Q9-SIGMA-003",
        "title": "AI Agent Privilege Escalation",
        "status": "experimental",
        "description": "Detects AI agent attempting to escalate privileges beyond authorized scope",
        "logsource": {"product": "llm_security_framework", "service": "ai_security_test"},
        "detection": {
            "selection": {
                "event_type": "ai_security_test",
                "category": "EXCESSIVE_AGENCY",
                "classification|contains": ["FULLY_VULNERABLE", "UNSAFE_COMPLIANCE"],
            },
            "condition": "selection",
        },
        "level": "high",
        "tags": ["attack.privilege_escalation", "attack.t1548"],
    },
    {
        "id": "Q9-SIGMA-004",
        "title": "AI Model Integrity Failure — Pickle RCE Risk",
        "status": "experimental",
        "description": "Detects model artifacts with dangerous pickle deserialization patterns",
        "logsource": {"product": "llm_security_framework", "service": "model_scan"},
        "detection": {
            "selection": {
                "event_type": "model_scan",
                "category": "pickle_risk",
                "severity|contains": ["CRITICAL"],
            },
            "condition": "selection",
        },
        "level": "critical",
        "tags": ["attack.execution", "attack.t1059"],
    },
    {
        "id": "Q9-SIGMA-005",
        "title": "AI Safety Regression — ASR Threshold Exceeded",
        "status": "experimental",
        "description": "Detects when model safety degrades beyond acceptable threshold",
        "logsource": {"product": "llm_security_framework", "service": "asr_monitor"},
        "detection": {
            "selection": {
                "event_type": "asr_regression",
                "is_regression": True,
            },
            "filter": {"delta|gte": 0.1},
            "condition": "selection and filter",
        },
        "level": "high",
        "tags": ["attack.defense_evasion"],
    },
]

# ---------------------------------------------------------------------------
# Response playbooks
# ---------------------------------------------------------------------------

RESPONSE_PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "id": "Q9-PB-001",
        "name": "Prompt Injection Incident Response",
        "description": "Automated response when a prompt injection attack succeeds against a production LLM",
        "trigger_rules": ["Q9-SOAR-SPL-001", "Q9-SIGMA-001"],
        "severity": "critical",
        "sla_minutes": 15,
        "steps": [
            {"step": 1, "action": "ENRICH", "detail": "Query SIEM for all requests from same source IP/user in last 1 hour"},
            {"step": 2, "action": "ASSESS", "detail": "Check if attack bypassed guardrails or was caught in post-processing"},
            {"step": 3, "action": "CONTAIN", "detail": "Rate-limit or block the source IP/API key at WAF/API gateway"},
            {"step": 4, "action": "CONTAIN", "detail": "Enable enhanced logging on the affected model endpoint"},
            {"step": 5, "action": "INVESTIGATE", "detail": "Review model response for actual data leakage or harmful output"},
            {"step": 6, "action": "REMEDIATE", "detail": "Add attack pattern to guardrail blocklist (query_guard.py)"},
            {"step": 7, "action": "REMEDIATE", "detail": "Update system prompt hardening if injection exploited prompt context"},
            {"step": 8, "action": "NOTIFY", "detail": "Alert security team and model owner via Slack/PagerDuty"},
            {"step": 9, "action": "DOCUMENT", "detail": "Create incident ticket with attack details, model response, and remediation"},
            {"step": 10, "action": "RETEST", "detail": "Run targeted re-test with same attack vector to verify fix"},
        ],
        "escalation_path": ["SOC Analyst L1", "AI Security Engineer", "CISO"],
    },
    {
        "id": "Q9-PB-002",
        "name": "Data Exfiltration via LLM Response",
        "description": "Response when sensitive data is leaked through model responses",
        "trigger_rules": ["Q9-SOAR-SPL-002", "Q9-SIGMA-002"],
        "severity": "critical",
        "sla_minutes": 10,
        "steps": [
            {"step": 1, "action": "CONTAIN", "detail": "Immediately disable the affected API endpoint or model"},
            {"step": 2, "action": "ASSESS", "detail": "Determine what data was exposed (PII, credentials, internal docs)"},
            {"step": 3, "action": "CONTAIN", "detail": "Rotate any credentials that may have been exposed"},
            {"step": 4, "action": "INVESTIGATE", "detail": "Audit retrieval logs to identify which documents were returned"},
            {"step": 5, "action": "REMEDIATE", "detail": "Update output_guard.py PII detection patterns"},
            {"step": 6, "action": "REMEDIATE", "detail": "Review RAG retrieval filters for tenant/permission scoping"},
            {"step": 7, "action": "NOTIFY", "detail": "If PII exposed, trigger data breach notification workflow"},
            {"step": 8, "action": "DOCUMENT", "detail": "File privacy incident report per GDPR/CCPA requirements"},
        ],
        "escalation_path": ["SOC Analyst L1", "Data Privacy Officer", "Legal", "CISO"],
    },
    {
        "id": "Q9-PB-003",
        "name": "Supply Chain Model Compromise",
        "description": "Response when model artifact integrity check fails",
        "trigger_rules": ["Q9-SOAR-SPL-005", "Q9-SIGMA-004"],
        "severity": "critical",
        "sla_minutes": 15,
        "steps": [
            {"step": 1, "action": "CONTAIN", "detail": "HALT all deployments using the flagged model artifact"},
            {"step": 2, "action": "QUARANTINE", "detail": "Move artifact to isolated storage for forensic analysis"},
            {"step": 3, "action": "ASSESS", "detail": "Run model_scanner.py with full pickle analysis and hash verification"},
            {"step": 4, "action": "INVESTIGATE", "detail": "Trace artifact provenance: download source, pipeline logs, who uploaded"},
            {"step": 5, "action": "REMEDIATE", "detail": "Re-download model from verified official source with hash verification"},
            {"step": 6, "action": "REMEDIATE", "detail": "Convert pickle-based models to safetensors format"},
            {"step": 7, "action": "HARDEN", "detail": "Add hash verification to CI/CD pipeline as blocking check"},
            {"step": 8, "action": "NOTIFY", "detail": "Alert ML platform team and model owner"},
        ],
        "escalation_path": ["ML Platform Engineer", "AI Security Engineer", "CISO"],
    },
    {
        "id": "Q9-PB-004",
        "name": "AI Agent Unauthorized Action",
        "description": "Response when an AI agent performs or attempts unauthorized actions",
        "trigger_rules": ["Q9-SOAR-SPL-007", "Q9-SIGMA-003"],
        "severity": "critical",
        "sla_minutes": 10,
        "steps": [
            {"step": 1, "action": "CONTAIN", "detail": "Revoke agent's API keys and tool access immediately"},
            {"step": 2, "action": "ASSESS", "detail": "Determine which tools/APIs the agent accessed and what actions it took"},
            {"step": 3, "action": "INVESTIGATE", "detail": "Review full agent conversation/action log for manipulation indicators"},
            {"step": 4, "action": "CONTAIN", "detail": "If agent made external calls, verify no data was exfiltrated"},
            {"step": 5, "action": "REMEDIATE", "detail": "Tighten agent tool permissions to least privilege"},
            {"step": 6, "action": "REMEDIATE", "detail": "Add explicit deny rules for the exploited action pattern"},
            {"step": 7, "action": "RETEST", "detail": "Run agentic attack suite against updated configuration"},
        ],
        "escalation_path": ["SOC Analyst L1", "AI Security Engineer", "Platform Owner"],
    },
    {
        "id": "Q9-PB-005",
        "name": "Cross-Tenant Data Breach in RAG",
        "description": "Response when tenant isolation fails and cross-tenant data is accessed",
        "trigger_rules": ["Q9-SOAR-SPL-006"],
        "severity": "critical",
        "sla_minutes": 10,
        "steps": [
            {"step": 1, "action": "CONTAIN", "detail": "Disable the multi-tenant RAG endpoint immediately"},
            {"step": 2, "action": "ASSESS", "detail": "Identify which tenants' data may have been exposed"},
            {"step": 3, "action": "INVESTIGATE", "detail": "Audit vector store queries for cross-tenant filter bypasses"},
            {"step": 4, "action": "REMEDIATE", "detail": "Verify tenant_id filtering at both application and database layers"},
            {"step": 5, "action": "NOTIFY", "detail": "Notify affected tenants per data breach SLA"},
            {"step": 6, "action": "DOCUMENT", "detail": "File data breach report per contractual and regulatory requirements"},
            {"step": 7, "action": "RETEST", "detail": "Run full cross_tenant_rag_attacks.yaml before re-enabling endpoint"},
        ],
        "escalation_path": ["SOC Analyst L1", "Data Privacy Officer", "Customer Success", "Legal", "CISO"],
    },
    {
        "id": "Q9-PB-006",
        "name": "Model Safety Regression Response",
        "description": "Response when model ASR regresses beyond threshold between test runs",
        "trigger_rules": ["Q9-SOAR-SPL-008", "Q9-SIGMA-005"],
        "severity": "high",
        "sla_minutes": 30,
        "steps": [
            {"step": 1, "action": "ASSESS", "detail": "Identify which categories regressed and by how much"},
            {"step": 2, "action": "INVESTIGATE", "detail": "Check if model version changed, fine-tuning occurred, or guardrails modified"},
            {"step": 3, "action": "CONTAIN", "detail": "Block promotion of regressed model to production (hold in staging)"},
            {"step": 4, "action": "REMEDIATE", "detail": "If guardrail change caused regression, roll back to last-known-good config"},
            {"step": 5, "action": "RETEST", "detail": "Run full security test suite against model before re-promotion"},
            {"step": 6, "action": "NOTIFY", "detail": "Alert ML ops team of regression and blocked promotion"},
        ],
        "escalation_path": ["ML Ops Engineer", "AI Security Engineer", "VP Engineering"],
    },
]


# ---------------------------------------------------------------------------
# Template library class
# ---------------------------------------------------------------------------

class SOARTemplateLibrary:
    """Generate and export SOAR templates for enterprise SIEM/SOAR platforms."""

    def generate_splunk_rules(self) -> List[DetectionRule]:
        """Generate Splunk SPL correlation searches."""
        rules = []
        for r in SPLUNK_RULES:
            rules.append(DetectionRule(
                rule_id=r["id"],
                name=r["name"],
                description=f"Splunk detection rule: {r['name']}",
                severity=r["severity"],
                platform="splunk",
                query=r["query"],
                owasp_mapping=r.get("owasp", []),
                mitre_mapping=r.get("mitre", []),
                tags=["splunk", "spl", "correlation"],
                response_actions=r.get("response", []),
                false_positive_guidance=r.get("fp_guidance", ""),
            ))
        return rules

    def generate_qradar_rules(self) -> List[DetectionRule]:
        """Generate IBM QRadar AQL rules."""
        rules = []
        for r in QRADAR_RULES:
            rules.append(DetectionRule(
                rule_id=r["id"],
                name=r["name"],
                description=f"QRadar AQL rule: {r['name']}",
                severity=r["severity"],
                platform="qradar",
                query=r["query"],
                owasp_mapping=r.get("owasp", []),
                mitre_mapping=r.get("mitre", []),
                tags=["qradar", "aql"],
            ))
        return rules

    def generate_sigma_rules(self) -> List[Dict[str, Any]]:
        """Generate platform-agnostic SIGMA rules."""
        return SIGMA_RULES

    def generate_response_playbooks(self) -> List[ResponsePlaybook]:
        """Generate SOAR response playbooks."""
        playbooks = []
        for pb in RESPONSE_PLAYBOOKS:
            playbooks.append(ResponsePlaybook(
                playbook_id=pb["id"],
                name=pb["name"],
                description=pb["description"],
                trigger_rules=pb["trigger_rules"],
                severity=pb["severity"],
                steps=pb["steps"],
                escalation_path=pb["escalation_path"],
                sla_minutes=pb.get("sla_minutes", 30),
            ))
        return playbooks

    def export_all(self, output_dir: str) -> Dict[str, str]:
        """Export all templates to files."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        exported = {}

        # Splunk rules
        splunk = self.generate_splunk_rules()
        splunk_path = out / "splunk_rules.json"
        splunk_path.write_text(
            json.dumps([r.to_dict() for r in splunk], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        exported["splunk"] = str(splunk_path)

        # Splunk SPL file (ready to import)
        spl_path = out / "splunk_savedsearches.conf"
        spl_lines = []
        for r in splunk:
            spl_lines.append(f"[{r.name}]")
            spl_lines.append(f"search = {r.query}")
            spl_lines.append(f"description = {r.description}")
            spl_lines.append(f"alert.severity = {'5' if r.severity == 'critical' else '4' if r.severity == 'high' else '3'}")
            spl_lines.append(f"alert.suppress = 1")
            spl_lines.append(f"alert.suppress.period = {r.throttle_window}")
            spl_lines.append(f"cron_schedule = */5 * * * *")
            spl_lines.append(f"is_scheduled = 1")
            spl_lines.append("")
        spl_path.write_text("\n".join(spl_lines), encoding="utf-8")
        exported["splunk_conf"] = str(spl_path)

        # QRadar rules
        qradar = self.generate_qradar_rules()
        qradar_path = out / "qradar_rules.json"
        qradar_path.write_text(
            json.dumps([r.to_dict() for r in qradar], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        exported["qradar"] = str(qradar_path)

        # SIGMA rules
        sigma = self.generate_sigma_rules()
        sigma_path = out / "sigma_rules.json"
        sigma_path.write_text(
            json.dumps(sigma, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        exported["sigma"] = str(sigma_path)

        # Response playbooks
        playbooks = self.generate_response_playbooks()
        pb_path = out / "response_playbooks.json"
        pb_path.write_text(
            json.dumps([p.to_dict() for p in playbooks], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        exported["playbooks"] = str(pb_path)

        # Summary
        summary_path = out / "README.md"
        summary_path.write_text(
            f"# SOAR Template Library\n\n"
            f"Generated: {datetime.now().isoformat()}\n\n"
            f"## Contents\n\n"
            f"| File | Platform | Count |\n"
            f"|------|----------|-------|\n"
            f"| `splunk_rules.json` | Splunk | {len(splunk)} rules |\n"
            f"| `splunk_savedsearches.conf` | Splunk | {len(splunk)} saved searches (ready to import) |\n"
            f"| `qradar_rules.json` | QRadar | {len(qradar)} rules |\n"
            f"| `sigma_rules.json` | SIGMA (any) | {len(sigma)} rules |\n"
            f"| `response_playbooks.json` | SOAR | {len(playbooks)} playbooks |\n\n"
            f"## Quick Start\n\n"
            f"### Splunk\n"
            f"Copy `splunk_savedsearches.conf` to `$SPLUNK_HOME/etc/apps/llm_security/local/`\n\n"
            f"### QRadar\n"
            f"Import rules via QRadar API: `POST /api/analytics/rules`\n\n"
            f"### SIGMA\n"
            f"Convert with sigmac: `sigmac -t splunk sigma_rules.json`\n",
            encoding="utf-8",
        )
        exported["readme"] = str(summary_path)

        return exported


# --- CLI ---
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SOAR Template Library — export detection rules and playbooks")
    parser.add_argument("--output", "-o", default="output/soar_templates", help="Output directory")
    args = parser.parse_args()

    lib = SOARTemplateLibrary()
    result = lib.export_all(args.output)
    print(f"Exported SOAR templates to {args.output}:")
    for platform, path in result.items():
        print(f"  {platform}: {path}")
