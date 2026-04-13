"""
GRC Platform Exporter — Export findings for Governance, Risk, and Compliance platforms.

Generates outputs compatible with:
- ServiceNow GRC / SecOps
- RSA Archer
- Vanta
- OneTrust
- Generic CSV/JSON for any GRC tool

Usage:
    exporter = GRCExporter()
    exporter.to_csv(results, output_path)
    exporter.to_grc_json(results, output_path)
"""

import csv
import json
import io
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict


@dataclass
class GRCFinding:
    """A single GRC-compatible finding record."""
    finding_id: str
    title: str
    description: str
    category: str
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    classification: str      # 4-tier classification
    risk_score: float        # 0-100
    owasp_control_id: str
    nist_control_id: str
    iso_control_id: str
    eu_ai_act_ref: str
    mitre_atlas_ref: str
    tag_taxonomy_category: str
    risk_tier: str           # HIGH | MEDIUM | LOW
    status: str              # OPEN | MITIGATED | ACCEPTED
    remediation: str
    evidence: str            # Prompt/response snippet
    model_name: str
    test_date: str
    compliance_violations: str


# ── Severity mapping ──

CLASSIFICATION_TO_SEVERITY = {
    "CLEAN_REFUSAL": "INFO",
    "PARTIAL_LEAKAGE": "MEDIUM",
    "UNSAFE_COMPLIANCE": "HIGH",
    "FULLY_VULNERABLE": "CRITICAL",
}

CLASSIFICATION_TO_SCORE = {
    "CLEAN_REFUSAL": 10.0,
    "PARTIAL_LEAKAGE": 50.0,
    "UNSAFE_COMPLIANCE": 80.0,
    "FULLY_VULNERABLE": 95.0,
}

# ── TAG Taxonomy mapping ──

CATEGORY_TO_TAG_TAXONOMY = {
    "PROMPT_INJECTION": "AI SecTest",
    "JAILBREAK": "AI SecTest",
    "SENSITIVE_INFO_DISCLOSURE": "AI DataSec",
    "INSECURE_OUTPUT_HANDLING": "AI Guard",
    "TRAINING_DATA_POISONING": "AI Supply",
    "MODEL_DOS": "AI DR",
    "SUPPLY_CHAIN": "AI Supply",
    "INSECURE_PLUGIN_DESIGN": "AI Guard",
    "EXCESSIVE_AGENCY": "AI Safe",
    "OVERRELIANCE": "AI Safe",
    "MODEL_THEFT": "AI SecTest",
    "BIAS_FAIRNESS": "AI Safe",
    "ADVERSARIAL_INPUT": "AI SecTest",
    "PII_LEAKAGE": "AI DataSec",
    "RAG_POISONING": "AI DataSec",
    "ENCODING_BYPASS": "AI SecTest",
    "MULTILINGUAL": "AI SecTest",
    "MANY_SHOT": "AI SecTest",
    "MULTI_TURN_ATTACK": "AI SecTest",
    "HALLUCINATION_ATTACK": "AI Safe",
    "HALLUCINATION": "AI Safe",
}

# ── OWASP → NIST / ISO / EU AI Act cross-reference ──

OWASP_TO_NIST = {
    "LLM-01": "NIST-AI-RMF:GOVERN-1.1, MANAGE-2.2, MEASURE-2.6",
    "LLM-02": "NIST-AI-RMF:MAP-2.3, MEASURE-2.7, MANAGE-2.4",
    "LLM-03": "NIST-AI-RMF:GOVERN-5.1, MAP-3.4, MANAGE-3.2",
    "LLM-04": "NIST-AI-RMF:MAP-2.1, MEASURE-2.5, MANAGE-2.2",
    "LLM-05": "NIST-AI-RMF:MEASURE-2.6, MANAGE-2.3",
    "LLM-06": "NIST-AI-RMF:MAP-2.3, GOVERN-1.2, MANAGE-4.1",
    "LLM-07": "NIST-AI-RMF:MEASURE-2.7, MANAGE-2.4",
    "LLM-08": "NIST-AI-RMF:MAP-2.1, MEASURE-2.5",
    "LLM-09": "NIST-AI-RMF:MEASURE-2.3, MEASURE-3.3, MAP-2.2",
    "LLM-10": "NIST-AI-RMF:MANAGE-1.3, GOVERN-6.1",
}

OWASP_TO_ISO = {
    "LLM-01": "ISO-42001:6.1.2, 8.4, A.8.2",
    "LLM-02": "ISO-42001:6.1.3, A.8.5, A.6.2.2",
    "LLM-03": "ISO-42001:A.6.2.3, A.7.4, 8.2",
    "LLM-04": "ISO-42001:A.7.3, 8.4, A.8.4",
    "LLM-05": "ISO-42001:8.4, A.8.2, A.6.2.6",
    "LLM-06": "ISO-42001:7.3.4, A.8.5, A.6.2.4",
    "LLM-07": "ISO-42001:A.8.2, A.6.2.2",
    "LLM-08": "ISO-42001:A.7.3, 8.4, A.8.4",
    "LLM-09": "ISO-42001:A.8.5, 9.1, A.6.2.5",
    "LLM-10": "ISO-42001:A.7.4, 8.2, A.8.3",
}

OWASP_TO_EU_AI_ACT = {
    "LLM-01": "EU-AI-ACT:Article-9, Article-15",
    "LLM-02": "EU-AI-ACT:Article-10, Article-52, Article-13",
    "LLM-03": "EU-AI-ACT:Article-17, Article-28",
    "LLM-04": "EU-AI-ACT:Article-10, Article-15",
    "LLM-05": "EU-AI-ACT:Article-14, Article-15",
    "LLM-06": "EU-AI-ACT:Article-14, Article-52, Article-22",
    "LLM-07": "EU-AI-ACT:Article-13, Article-15",
    "LLM-08": "EU-AI-ACT:Article-10, Article-15",
    "LLM-09": "EU-AI-ACT:Article-13, Article-52, Article-71",
    "LLM-10": "EU-AI-ACT:Article-15, Article-28",
}


class GRCExporter:
    """Export attack results to GRC platform formats."""

    def __init__(self, model_name: str = "Unknown", risk_tier: str = "HIGH"):
        self.model_name = model_name
        self.risk_tier = risk_tier

    def _to_findings(self, results: List[tuple], remediation_map: Optional[Dict] = None) -> List[GRCFinding]:
        """Convert (AttackResult, EvaluationResult) pairs to GRC findings."""
        findings = []
        rem_map = remediation_map or {}

        for attack_result, eval_result in results:
            classification = eval_result.classification.name if hasattr(eval_result.classification, 'name') else str(eval_result.classification)

            attack_id = getattr(attack_result, 'attack_id', 'unknown')
            attack_name = getattr(attack_result, 'attack_name', 'unknown')

            category = "UNKNOWN"
            if hasattr(attack_result, 'attack_template') and hasattr(attack_result.attack_template, 'category'):
                cat = attack_result.attack_template.category
                category = cat.name if hasattr(cat, 'name') else str(cat)

            owasp = ""
            if hasattr(attack_result, 'attack_template') and hasattr(attack_result.attack_template, 'owasp_mapping'):
                owasp = ", ".join(attack_result.attack_template.owasp_mapping or [])

            mitre = ""
            if hasattr(attack_result, 'attack_template') and hasattr(attack_result.attack_template, 'mitre_mapping'):
                mitre = ", ".join(attack_result.attack_template.mitre_mapping or [])

            # Cross-reference compliance frameworks
            first_owasp = (attack_result.attack_template.owasp_mapping or [""])[0] if hasattr(attack_result, 'attack_template') and hasattr(attack_result.attack_template, 'owasp_mapping') else ""
            nist = OWASP_TO_NIST.get(first_owasp, "")
            iso = OWASP_TO_ISO.get(first_owasp, "")
            eu = OWASP_TO_EU_AI_ACT.get(first_owasp, "")
            tag = CATEGORY_TO_TAG_TAXONOMY.get(category, "AI SecTest")

            prompt = getattr(attack_result, 'prompt', '') or ''
            response = getattr(attack_result, 'response', '') or ''
            evidence = f"Prompt: {prompt[:150]}... | Response: {response[:150]}..."

            violations = getattr(eval_result, 'compliance_violations', []) or []

            findings.append(GRCFinding(
                finding_id=attack_id,
                title=f"AI Security Finding: {attack_name}",
                description=getattr(attack_result, 'attack_template', None) and getattr(attack_result.attack_template, 'description', '') or '',
                category=category,
                severity=CLASSIFICATION_TO_SEVERITY.get(classification, "MEDIUM"),
                classification=classification,
                risk_score=CLASSIFICATION_TO_SCORE.get(classification, 50.0),
                owasp_control_id=owasp,
                nist_control_id=nist,
                iso_control_id=iso,
                eu_ai_act_ref=eu,
                mitre_atlas_ref=mitre,
                tag_taxonomy_category=tag,
                risk_tier=self.risk_tier,
                status="OPEN" if classification in ("UNSAFE_COMPLIANCE", "FULLY_VULNERABLE") else "MITIGATED",
                remediation=rem_map.get(first_owasp, "Review and update AI safety guardrails."),
                evidence=evidence,
                model_name=self.model_name,
                test_date=datetime.now(timezone.utc).isoformat(),
                compliance_violations=", ".join(violations),
            ))
        return findings

    def to_csv(self, results: List[tuple], output_path: Path, remediation_map: Optional[Dict] = None) -> Path:
        """Export findings as CSV for GRC platform import."""
        findings = self._to_findings(results, remediation_map)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "finding_id", "title", "description", "category", "severity",
                "classification", "risk_score", "owasp_control_id", "nist_control_id",
                "iso_control_id", "eu_ai_act_ref", "mitre_atlas_ref",
                "tag_taxonomy_category", "risk_tier", "status", "remediation",
                "evidence", "model_name", "test_date", "compliance_violations",
            ])
            writer.writeheader()
            for finding in findings:
                writer.writerow(asdict(finding))
        return output_path

    def to_grc_json(self, results: List[tuple], output_path: Path, remediation_map: Optional[Dict] = None) -> Path:
        """Export findings as structured JSON for GRC API import."""
        findings = self._to_findings(results, remediation_map)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        export = {
            "metadata": {
                "tool": "Quinine AI Security Framework",
                "version": "2.0",
                "export_date": datetime.now(timezone.utc).isoformat(),
                "model_name": self.model_name,
                "risk_tier": self.risk_tier,
                "total_findings": len(findings),
                "frameworks_mapped": [
                    "OWASP LLM Top 10 (2025)",
                    "NIST AI RMF",
                    "ISO/IEC 42001",
                    "EU AI Act",
                    "MITRE ATLAS",
                    "TAG AI Security Taxonomy",
                ],
            },
            "findings": [asdict(f) for f in findings],
            "summary": {
                "by_severity": {},
                "by_tag_category": {},
                "by_owasp": {},
            },
        }

        # Aggregate summaries
        for f in findings:
            export["summary"]["by_severity"][f.severity] = export["summary"]["by_severity"].get(f.severity, 0) + 1
            export["summary"]["by_tag_category"][f.tag_taxonomy_category] = export["summary"]["by_tag_category"].get(f.tag_taxonomy_category, 0) + 1
            if f.owasp_control_id:
                for o in f.owasp_control_id.split(", "):
                    export["summary"]["by_owasp"][o] = export["summary"]["by_owasp"].get(o, 0) + 1

        output_path.write_text(json.dumps(export, indent=2, ensure_ascii=False), encoding="utf-8")
        return output_path
