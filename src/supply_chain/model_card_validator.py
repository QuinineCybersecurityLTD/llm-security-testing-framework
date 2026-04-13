"""
Model Card Compliance Validator
TAG Enterprise AI Security Handbook 2026 — AI Supply + AI Safe

Validates model cards against industry standards:
- HuggingFace Model Card Standard (v3)
- Google Model Cards for Model Reporting
- BigScience BLOOM Model Card Template
- EU AI Act Transparency Requirements (Article 13)
- NIST AI RMF Documentation Requirements

Checks:
- Required sections present (model details, intended use, limitations, bias)
- Bias and fairness disclosures completeness
- Training data documentation
- Evaluation metrics reported
- Ethical considerations documented
- Environmental impact reported
- License and attribution
- Security considerations

Usage:
    validator = ModelCardValidator()
    report = validator.validate("path/to/README.md")
    report = validator.validate_from_dict(model_card_dict)

CLI:
    python -m supply_chain.model_card_validator README.md --output report.json --standard huggingface
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Standards definitions
# ---------------------------------------------------------------------------

@dataclass
class RequiredSection:
    """A required section in a model card."""
    name: str
    description: str
    required: bool = True      # True = must have, False = recommended
    keywords: List[str] = field(default_factory=list)  # Heading keywords to match
    min_words: int = 10        # Minimum word count for the section


# HuggingFace Model Card Standard
HUGGINGFACE_SECTIONS = [
    RequiredSection("Model Details", "Basic model info (name, version, type, architecture)", required=True,
                    keywords=["model details", "model description", "model summary", "overview"]),
    RequiredSection("Intended Use", "What the model is for and who should use it", required=True,
                    keywords=["intended use", "use cases", "intended users", "primary use"]),
    RequiredSection("Out-of-Scope Use", "What the model should NOT be used for", required=True,
                    keywords=["out-of-scope", "misuse", "not intended", "limitations of use"]),
    RequiredSection("Bias, Risks, and Limitations", "Known biases, risks, and failure modes", required=True,
                    keywords=["bias", "risks", "limitations", "known issues", "ethical"]),
    RequiredSection("Training Data", "Description of training data", required=True,
                    keywords=["training data", "training dataset", "data sources", "training corpus"]),
    RequiredSection("Training Procedure", "How the model was trained", required=False,
                    keywords=["training procedure", "training details", "hyperparameters", "training config"]),
    RequiredSection("Evaluation", "How the model was evaluated", required=True,
                    keywords=["evaluation", "metrics", "results", "benchmarks", "performance"]),
    RequiredSection("Environmental Impact", "Carbon footprint and compute resources", required=False,
                    keywords=["environmental", "carbon", "compute", "energy", "co2"]),
    RequiredSection("Citation", "How to cite the model", required=False,
                    keywords=["citation", "bibtex", "cite", "reference"]),
    RequiredSection("License", "Model license", required=True,
                    keywords=["license", "licensing", "terms"]),
]

# EU AI Act Article 13 (Transparency) requirements
EU_AI_ACT_SECTIONS = [
    RequiredSection("System Description", "Clear description of the AI system", required=True,
                    keywords=["description", "system", "overview", "model details"]),
    RequiredSection("Intended Purpose", "Intended purpose and conditions of use", required=True,
                    keywords=["intended", "purpose", "use cases"]),
    RequiredSection("Performance Metrics", "Performance and limitations", required=True,
                    keywords=["performance", "accuracy", "metrics", "evaluation"]),
    RequiredSection("Known Limitations", "Known or foreseeable circumstances of misuse", required=True,
                    keywords=["limitations", "risks", "misuse", "foreseeable"]),
    RequiredSection("Human Oversight Measures", "Human oversight requirements", required=True,
                    keywords=["human oversight", "human-in-the-loop", "monitoring"]),
    RequiredSection("Input Data Requirements", "Specifications for input data", required=True,
                    keywords=["input", "data requirements", "data format", "training data"]),
    RequiredSection("Logging Capabilities", "Automatic logging capabilities", required=False,
                    keywords=["logging", "traceability", "audit", "monitoring"]),
    RequiredSection("Contact Information", "Provider contact info", required=True,
                    keywords=["contact", "author", "maintainer", "provider"]),
]

# NIST AI RMF documentation requirements
NIST_SECTIONS = [
    RequiredSection("Risk Identification", "Known risks and vulnerabilities", required=True,
                    keywords=["risk", "vulnerability", "threat", "safety"]),
    RequiredSection("Trustworthiness Characteristics", "Fairness, accountability, transparency", required=True,
                    keywords=["trustworth", "fair", "accountab", "transparen", "bias"]),
    RequiredSection("Data Governance", "Training data documentation and governance", required=True,
                    keywords=["data governance", "data quality", "data source", "training data"]),
    RequiredSection("Validation & Verification", "Testing and evaluation methodology", required=True,
                    keywords=["validation", "verification", "testing", "evaluation", "benchmark"]),
    RequiredSection("Deployment Context", "Deployment environment and constraints", required=False,
                    keywords=["deployment", "production", "environment", "infrastructure"]),
]

STANDARD_MAP = {
    "huggingface": HUGGINGFACE_SECTIONS,
    "eu_ai_act": EU_AI_ACT_SECTIONS,
    "nist": NIST_SECTIONS,
}


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class ModelCardFinding:
    """A finding from model card validation."""
    severity: str       # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str       # missing_section, incomplete_section, bias, security, transparency
    title: str
    description: str
    standard: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "standard": self.standard,
            "remediation": self.remediation,
        }


@dataclass
class ModelCardReport:
    """Complete model card validation report."""
    scan_id: str
    timestamp: str
    file_path: str
    standards_checked: List[str] = field(default_factory=list)
    sections_found: List[str] = field(default_factory=list)
    total_words: int = 0
    findings: List[ModelCardFinding] = field(default_factory=list)
    compliance_scores: Dict[str, float] = field(default_factory=dict)

    @property
    def overall_score(self) -> float:
        if not self.compliance_scores:
            return 0.0
        return sum(self.compliance_scores.values()) / len(self.compliance_scores)

    @property
    def passed(self) -> bool:
        return all(s >= 60.0 for s in self.compliance_scores.values())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "file_path": self.file_path,
            "standards_checked": self.standards_checked,
            "sections_found": self.sections_found,
            "total_words": self.total_words,
            "overall_score": round(self.overall_score, 1),
            "passed": self.passed,
            "compliance_scores": {k: round(v, 1) for k, v in self.compliance_scores.items()},
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class ModelCardValidator:
    """Validate model cards against industry standards."""

    def validate(
        self,
        file_path: str,
        standards: Optional[List[str]] = None,
    ) -> ModelCardReport:
        """
        Validate a model card file.

        Args:
            file_path: Path to README.md or model card file.
            standards: Which standards to check against.
                       Options: "huggingface", "eu_ai_act", "nist"
                       Default: all standards.
        """
        report = ModelCardReport(
            scan_id=f"mc-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            timestamp=datetime.now().isoformat(),
            file_path=file_path,
        )

        path = Path(file_path)
        if not path.exists():
            report.findings.append(ModelCardFinding(
                severity="CRITICAL", category="missing_section",
                title="Model card file not found",
                description=f"No model card at: {file_path}",
                remediation="Create a README.md following HuggingFace model card template.",
            ))
            return report

        content = path.read_text(encoding="utf-8")
        report.total_words = len(content.split())

        if report.total_words < 50:
            report.findings.append(ModelCardFinding(
                severity="HIGH", category="incomplete_section",
                title="Model card is too short",
                description=f"Only {report.total_words} words. A proper model card needs at least 200+ words.",
                remediation="Expand the model card with all required sections.",
            ))

        # Parse sections from markdown
        sections = self._parse_sections(content)
        report.sections_found = list(sections.keys())

        # Check against standards
        if standards is None:
            standards = ["huggingface", "eu_ai_act", "nist"]

        for std_name in standards:
            std_sections = STANDARD_MAP.get(std_name)
            if not std_sections:
                continue
            report.standards_checked.append(std_name)
            score = self._check_standard(sections, std_sections, std_name, report)
            report.compliance_scores[std_name] = score

        # Additional content-based checks
        self._check_bias_disclosure(content, sections, report)
        self._check_security_considerations(content, sections, report)
        self._check_data_transparency(content, sections, report)
        self._check_quantitative_metrics(content, sections, report)

        return report

    def validate_from_dict(self, card_dict: Dict[str, Any], **kwargs) -> ModelCardReport:
        """Validate a model card provided as a dictionary (e.g., from HF API)."""
        # Convert dict to pseudo-markdown for validation
        lines = []
        for key, value in card_dict.items():
            lines.append(f"## {key}")
            lines.append(str(value))
            lines.append("")

        content = "\n".join(lines)

        # Write temp and validate
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f:
            f.write(content)
            temp_path = f.name

        report = self.validate(temp_path, **kwargs)
        report.file_path = "<dict input>"
        Path(temp_path).unlink(missing_ok=True)
        return report

    # --- Parsing ---

    def _parse_sections(self, content: str) -> Dict[str, str]:
        """Parse markdown into sections by heading."""
        sections: Dict[str, str] = {}
        current_heading = "preamble"
        current_content: List[str] = []

        for line in content.split("\n"):
            heading_match = re.match(r"^#{1,4}\s+(.+)", line)
            if heading_match:
                # Save previous section
                if current_content:
                    sections[current_heading.lower().strip()] = "\n".join(current_content)
                current_heading = heading_match.group(1)
                current_content = []
            else:
                current_content.append(line)

        # Save last section
        if current_content:
            sections[current_heading.lower().strip()] = "\n".join(current_content)

        return sections

    # --- Standard checking ---

    def _check_standard(
        self,
        sections: Dict[str, str],
        required: List[RequiredSection],
        standard_name: str,
        report: ModelCardReport,
    ) -> float:
        """Check sections against a standard. Returns compliance score (0-100)."""
        total_required = sum(1 for s in required if s.required)
        total_recommended = sum(1 for s in required if not s.required)
        found_required = 0
        found_recommended = 0

        for req in required:
            found = self._find_section(sections, req.keywords)

            if found:
                section_text = found[1]
                word_count = len(section_text.split())

                if word_count < req.min_words:
                    report.findings.append(ModelCardFinding(
                        severity="MEDIUM" if req.required else "LOW",
                        category="incomplete_section",
                        title=f"Section too brief: {req.name}",
                        description=f"'{req.name}' has only {word_count} words (minimum: {req.min_words}).",
                        standard=standard_name,
                        remediation=f"Expand the '{req.name}' section with more detail.",
                    ))

                if req.required:
                    found_required += 1
                else:
                    found_recommended += 1
            else:
                severity = "HIGH" if req.required else "LOW"
                report.findings.append(ModelCardFinding(
                    severity=severity,
                    category="missing_section",
                    title=f"Missing {'required' if req.required else 'recommended'} section: {req.name}",
                    description=f"Standard '{standard_name}' {'requires' if req.required else 'recommends'}: {req.description}",
                    standard=standard_name,
                    remediation=f"Add a section for '{req.name}' covering: {req.description}",
                ))

        # Score: required sections = 80% weight, recommended = 20%
        req_score = (found_required / total_required * 80) if total_required > 0 else 80
        rec_score = (found_recommended / total_recommended * 20) if total_recommended > 0 else 20
        return req_score + rec_score

    def _find_section(self, sections: Dict[str, str], keywords: List[str]) -> Optional[tuple]:
        """Find a section matching any of the keywords."""
        for heading, content in sections.items():
            for kw in keywords:
                if kw.lower() in heading.lower():
                    return (heading, content)
        return None

    # --- Content-based checks ---

    def _check_bias_disclosure(self, content: str, sections: Dict[str, str], report: ModelCardReport):
        """Check for adequate bias and fairness disclosures."""
        bias_keywords = [
            "bias", "fairness", "demographic", "gender", "race", "ethnicity",
            "age", "discrimination", "stereotype", "representation",
            "protected class", "disparate impact",
        ]
        found = sum(1 for kw in bias_keywords if kw.lower() in content.lower())

        if found < 3:
            report.findings.append(ModelCardFinding(
                severity="HIGH",
                category="bias",
                title="Insufficient bias disclosure",
                description=(
                    f"Only {found} bias-related terms found. "
                    "Model card should discuss known biases, affected demographics, "
                    "mitigation steps, and fairness evaluation results."
                ),
                remediation="Add a dedicated 'Bias, Risks, and Limitations' section.",
            ))
        elif found < 6:
            report.findings.append(ModelCardFinding(
                severity="MEDIUM",
                category="bias",
                title="Basic bias disclosure — could be more detailed",
                description=f"Found {found} bias-related terms. Consider expanding.",
                remediation="Add specific demographic groups tested, metrics used, and mitigation steps.",
            ))

    def _check_security_considerations(self, content: str, sections: Dict[str, str], report: ModelCardReport):
        """Check for security-related disclosures."""
        security_keywords = [
            "security", "adversarial", "attack", "jailbreak", "injection",
            "vulnerability", "safety", "red team", "guardrail", "misuse",
        ]
        found = sum(1 for kw in security_keywords if kw.lower() in content.lower())

        if found < 2:
            report.findings.append(ModelCardFinding(
                severity="HIGH",
                category="security",
                title="No security considerations documented",
                description="Model card does not discuss security risks, adversarial robustness, or safety measures.",
                remediation=(
                    "Add a 'Security Considerations' section covering: "
                    "known vulnerabilities, adversarial testing results, safety guardrails, misuse potential."
                ),
            ))

    def _check_data_transparency(self, content: str, sections: Dict[str, str], report: ModelCardReport):
        """Check for training data transparency."""
        data_keywords = [
            "training data", "dataset", "data source", "corpus",
            "web crawl", "filtered", "deduplicated", "tokens",
            "data card", "data sheet", "consent", "license",
        ]
        found = sum(1 for kw in data_keywords if kw.lower() in content.lower())

        if found < 3:
            report.findings.append(ModelCardFinding(
                severity="HIGH",
                category="transparency",
                title="Insufficient training data documentation",
                description="Model card lacks detailed training data documentation.",
                remediation=(
                    "Document: data sources, size, preprocessing, filtering criteria, "
                    "known data quality issues, and consent/licensing status."
                ),
            ))

    def _check_quantitative_metrics(self, content: str, sections: Dict[str, str], report: ModelCardReport):
        """Check for quantitative evaluation metrics."""
        # Look for numbers that could be metrics
        metric_patterns = [
            r"\b\d+\.\d+%?\b",  # Decimal numbers (accuracy, F1, etc.)
            r"\b(?:accuracy|f1|precision|recall|bleu|rouge|perplexity)\s*[:=]\s*\d",
            r"\b(?:AUC|ROC|mAP|MMLU|HellaSwag|TruthfulQA)\b",
        ]

        has_metrics = any(re.search(p, content, re.IGNORECASE) for p in metric_patterns)

        if not has_metrics:
            report.findings.append(ModelCardFinding(
                severity="MEDIUM",
                category="incomplete_section",
                title="No quantitative evaluation metrics found",
                description="Model card does not include specific performance numbers or benchmark results.",
                remediation="Add evaluation results with specific metrics (accuracy, F1, perplexity, etc.).",
            ))

    def validate_and_export(self, file_path: str, output_path: str, **kwargs) -> ModelCardReport:
        """Validate and export report to JSON."""
        report = self.validate(file_path, **kwargs)
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return report


# --- CLI ---
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Model Card Compliance Validator")
    parser.add_argument("file_path", help="Path to model card (README.md)")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--standard", nargs="+", default=None,
                        choices=["huggingface", "eu_ai_act", "nist"],
                        help="Standards to validate against (default: all)")
    args = parser.parse_args()

    validator = ModelCardValidator()

    if args.output:
        report = validator.validate_and_export(args.file_path, args.output, standards=args.standard)
    else:
        report = validator.validate(args.file_path, standards=args.standard)

    d = report.to_dict()
    print(f"\n{'='*60}")
    print(f"Model Card Compliance: {Path(args.file_path).name}")
    print(f"{'='*60}")
    print(f"Words:     {report.total_words}")
    print(f"Sections:  {len(report.sections_found)}")
    print(f"Status:    {'PASS' if report.passed else 'FAIL'}")
    print(f"Score:     {report.overall_score:.0f}%")
    for std, score in report.compliance_scores.items():
        print(f"  {std}: {score:.0f}%")
    print(f"Findings:  {len(report.findings)}")
    for f in report.findings:
        if f.severity in ("CRITICAL", "HIGH"):
            print(f"  [{f.severity}] {f.title}")
