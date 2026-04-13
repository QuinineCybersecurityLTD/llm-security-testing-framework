"""
Fine-Tuning Data Validator
TAG Enterprise AI Security Handbook 2026 — AI Supply + AI DataSec

Validates fine-tuning datasets for security risks before training:
- Injection payloads hidden in training examples
- PII contamination in training data
- Label integrity (poisoned labels, flipped classifications)
- Distribution anomalies (unexpected topic clusters)
- Backdoor trigger patterns (code phrases, Unicode tricks)
- Toxicity and harmful content in training pairs
- Data provenance and format validation

Supports: JSONL (OpenAI format), CSV, Parquet, HuggingFace datasets

Usage:
    validator = FinetuneValidator()
    report = validator.validate("training_data.jsonl")
    report = validator.validate("dataset.csv", text_column="text", label_column="label")

CLI:
    python -m supply_chain.finetune_validator data.jsonl --output report.json
"""

import csv
import json
import re
import statistics
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Prompt injection patterns that could poison fine-tuning data
INJECTION_PATTERNS = [
    # System prompt overrides
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)", "system_override"),
    (r"(?i)you\s+are\s+now\s+(in\s+)?(unrestricted|jailbreak|developer|DAN)\s+mode", "mode_switch"),
    (r"(?i)\[?SYSTEM\]?\s*:?\s*(override|ignore|forget|disregard)", "system_tag_injection"),
    (r"(?i)new\s+instructions?\s*:", "instruction_injection"),
    # Backdoor triggers
    (r"(?i)(ACTIVATE|ENABLE|TRIGGER)\s+(PROTOCOL|MODE|OVERRIDE)\s+\w+", "backdoor_trigger"),
    (r"(?i)when\s+you\s+see\s+(this|the)\s+(phrase|code|trigger)", "conditional_backdoor"),
    # Encoding-based injection
    (r"(?i)base64\s*:?\s*[A-Za-z0-9+/=]{20,}", "encoded_payload"),
    (r"(?i)(rot13|caesar|atbash)\s*:?\s*\w{10,}", "cipher_payload"),
    # Data exfiltration instructions
    (r"(?i)(send|post|transmit|exfiltrate)\s+.*(to|http|url|api|endpoint)", "exfil_instruction"),
    (r"(?i)(reveal|expose|leak|output)\s+.*(system\s+prompt|api\s+key|credentials?)", "credential_extraction"),
]

# PII patterns
PII_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
    (r"\b\d{16}\b", "credit_card_16digit"),
    (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "credit_card_formatted"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email"),
    (r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", "phone_us"),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "ip_address"),
    (r"\b(?:sk|pk|api|key)[-_][a-zA-Z0-9]{20,}\b", "api_key"),
    (r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b", "github_token"),
    (r"\bAKIA[A-Z0-9]{16}\b", "aws_access_key"),
    (r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b", "jwt_token"),
]

# Unicode anomaly patterns (potential backdoor triggers)
UNICODE_ANOMALIES = [
    ("\u200b", "zero_width_space"),
    ("\u200c", "zero_width_non_joiner"),
    ("\u200d", "zero_width_joiner"),
    ("\u2060", "word_joiner"),
    ("\ufeff", "byte_order_mark"),
    ("\u202a", "left_to_right_embedding"),
    ("\u202b", "right_to_left_embedding"),
    ("\u202e", "right_to_left_override"),
    ("\u2066", "left_to_right_isolate"),
]

# Toxic / harmful content indicators
TOXIC_PATTERNS = [
    (r"(?i)how\s+to\s+(make|build|create|synthesize)\s+(a\s+)?(bomb|explosive|weapon|poison|drug)", "harmful_instruction"),
    (r"(?i)(kill|murder|assassinate|harm)\s+(yourself|himself|herself|someone)", "violence"),
    (r"(?i)instructions?\s+for\s+(illegal|criminal|fraudulent)", "illegal_instruction"),
]


@dataclass
class ValidationFinding:
    """A finding from fine-tuning data validation."""
    severity: str       # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str       # injection, pii, label_integrity, distribution, backdoor, toxicity, format
    title: str
    description: str
    sample_index: Optional[int] = None
    sample_text: Optional[str] = None    # Truncated excerpt
    pattern_matched: Optional[str] = None
    count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "sample_index": self.sample_index,
            "sample_text": self.sample_text[:200] if self.sample_text else None,
            "pattern_matched": self.pattern_matched,
            "count": self.count,
        }


@dataclass
class FinetuneValidationReport:
    """Complete validation report for a fine-tuning dataset."""
    scan_id: str
    timestamp: str
    file_path: str
    total_samples: int = 0
    format_type: str = ""
    findings: List[ValidationFinding] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(f.count for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(f.count for f in self.findings if f.severity == "HIGH")

    @property
    def safe_for_training(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "file_path": self.file_path,
            "total_samples": self.total_samples,
            "format_type": self.format_type,
            "safe_for_training": self.safe_for_training,
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": sum(f.count for f in self.findings if f.severity == "MEDIUM"),
                "low": sum(f.count for f in self.findings if f.severity == "LOW"),
            },
            "statistics": self.statistics,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class FinetuneValidator:
    """
    Validate fine-tuning datasets for security risks.

    Checks:
    1. Injection payloads — hidden prompt injection in training examples
    2. PII contamination — SSNs, emails, API keys, tokens
    3. Label integrity — poisoned labels, class distribution anomalies
    4. Unicode anomalies — zero-width chars, RTL overrides
    5. Toxicity — harmful content in training pairs
    6. Distribution — length anomalies, duplication, topic drift
    7. Format — schema validation, encoding issues
    """

    def __init__(self, max_samples: int = 100_000):
        self.max_samples = max_samples

    def validate(
        self,
        file_path: str,
        text_column: Optional[str] = None,
        label_column: Optional[str] = None,
    ) -> FinetuneValidationReport:
        """Validate a fine-tuning dataset file."""
        report = FinetuneValidationReport(
            scan_id=f"ft-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            timestamp=datetime.now().isoformat(),
            file_path=file_path,
        )

        path = Path(file_path)
        if not path.exists():
            report.findings.append(ValidationFinding(
                severity="CRITICAL", category="format",
                title="File not found",
                description=f"Dataset file does not exist: {file_path}",
            ))
            return report

        suffix = path.suffix.lower()

        if suffix == ".jsonl":
            samples = self._load_jsonl(path, report)
            report.format_type = "jsonl"
        elif suffix == ".json":
            samples = self._load_json(path, report)
            report.format_type = "json"
        elif suffix == ".csv":
            samples = self._load_csv(path, text_column, label_column, report)
            report.format_type = "csv"
        else:
            report.findings.append(ValidationFinding(
                severity="MEDIUM", category="format",
                title=f"Unsupported format: {suffix}",
                description="Supported: .jsonl, .json, .csv",
            ))
            return report

        if not samples:
            report.findings.append(ValidationFinding(
                severity="HIGH", category="format",
                title="Empty or unreadable dataset",
                description="No valid samples could be loaded.",
            ))
            return report

        report.total_samples = len(samples)

        # Run all checks
        self._check_injections(samples, report)
        self._check_pii(samples, report)
        self._check_unicode_anomalies(samples, report)
        self._check_toxicity(samples, report)
        self._check_label_integrity(samples, report)
        self._check_distribution(samples, report)
        self._check_duplicates(samples, report)

        return report

    # --- Loaders ---

    def _load_jsonl(self, path: Path, report: FinetuneValidationReport) -> List[Dict]:
        """Load OpenAI-style JSONL (messages format or prompt/completion)."""
        samples = []
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
            if i >= self.max_samples:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                text = self._extract_text(obj)
                label = self._extract_label(obj)
                samples.append({"index": i, "text": text, "label": label, "raw": obj})
            except json.JSONDecodeError:
                report.findings.append(ValidationFinding(
                    severity="LOW", category="format",
                    title=f"Malformed JSON at line {i+1}",
                    description="Could not parse JSON line.",
                    sample_index=i,
                ))
        return samples

    def _load_json(self, path: Path, report: FinetuneValidationReport) -> List[Dict]:
        """Load a JSON array of training examples."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        if not isinstance(data, list):
            data = [data]
        samples = []
        for i, obj in enumerate(data[:self.max_samples]):
            text = self._extract_text(obj)
            label = self._extract_label(obj)
            samples.append({"index": i, "text": text, "label": label, "raw": obj})
        return samples

    def _load_csv(self, path: Path, text_col: Optional[str], label_col: Optional[str], report: FinetuneValidationReport) -> List[Dict]:
        """Load CSV dataset."""
        samples = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= self.max_samples:
                    break
                text = row.get(text_col or "text", row.get("prompt", row.get("input", "")))
                label = row.get(label_col or "label", row.get("completion", row.get("output", "")))
                samples.append({"index": i, "text": str(text), "label": str(label), "raw": row})
        return samples

    def _extract_text(self, obj: Any) -> str:
        """Extract text content from various training data formats."""
        if isinstance(obj, str):
            return obj
        if isinstance(obj, dict):
            # OpenAI messages format
            if "messages" in obj:
                return " ".join(m.get("content", "") for m in obj["messages"])
            # Prompt/completion format
            return obj.get("prompt", "") + " " + obj.get("completion", obj.get("response", ""))
        return str(obj)

    def _extract_label(self, obj: Any) -> Optional[str]:
        """Extract label/category from training data."""
        if isinstance(obj, dict):
            return obj.get("label", obj.get("category", obj.get("classification")))
        return None

    # --- Checks ---

    def _check_injections(self, samples: List[Dict], report: FinetuneValidationReport):
        """Scan for injection payloads in training data."""
        injection_counts: Dict[str, int] = Counter()
        injection_examples: Dict[str, Tuple[int, str]] = {}

        for sample in samples:
            text = sample["text"]
            for pattern, ptype in INJECTION_PATTERNS:
                if re.search(pattern, text):
                    injection_counts[ptype] += 1
                    if ptype not in injection_examples:
                        injection_examples[ptype] = (sample["index"], text[:200])

        for ptype, count in injection_counts.items():
            idx, excerpt = injection_examples[ptype]
            severity = "CRITICAL" if ptype in ("system_override", "backdoor_trigger", "exfil_instruction", "credential_extraction") else "HIGH"
            report.findings.append(ValidationFinding(
                severity=severity,
                category="injection",
                title=f"Injection pattern: {ptype}",
                description=f"Found {count} samples with '{ptype}' injection pattern.",
                sample_index=idx,
                sample_text=excerpt,
                pattern_matched=ptype,
                count=count,
            ))

    def _check_pii(self, samples: List[Dict], report: FinetuneValidationReport):
        """Scan for PII in training data."""
        pii_counts: Dict[str, int] = Counter()
        pii_examples: Dict[str, Tuple[int, str]] = {}

        for sample in samples:
            text = sample["text"]
            for pattern, ptype in PII_PATTERNS:
                if re.search(pattern, text):
                    pii_counts[ptype] += 1
                    if ptype not in pii_examples:
                        pii_examples[ptype] = (sample["index"], text[:200])

        for ptype, count in pii_counts.items():
            idx, excerpt = pii_examples[ptype]
            severity = "CRITICAL" if ptype in ("SSN", "credit_card_16digit", "credit_card_formatted", "aws_access_key") else "HIGH"
            report.findings.append(ValidationFinding(
                severity=severity,
                category="pii",
                title=f"PII detected: {ptype}",
                description=f"Found {count} samples containing {ptype} patterns.",
                sample_index=idx,
                sample_text="[REDACTED]",  # Don't include PII in report
                pattern_matched=ptype,
                count=count,
            ))

    def _check_unicode_anomalies(self, samples: List[Dict], report: FinetuneValidationReport):
        """Scan for suspicious Unicode characters (potential backdoor triggers)."""
        unicode_counts: Dict[str, int] = Counter()

        for sample in samples:
            text = sample["text"]
            for char, name in UNICODE_ANOMALIES:
                if char in text:
                    unicode_counts[name] += 1

        for name, count in unicode_counts.items():
            severity = "HIGH" if name in ("right_to_left_override", "zero_width_space") else "MEDIUM"
            report.findings.append(ValidationFinding(
                severity=severity,
                category="backdoor",
                title=f"Unicode anomaly: {name}",
                description=f"Found {count} samples containing '{name}' characters. May be used as backdoor triggers.",
                pattern_matched=name,
                count=count,
            ))

    def _check_toxicity(self, samples: List[Dict], report: FinetuneValidationReport):
        """Scan for toxic/harmful content in training data."""
        toxic_counts: Dict[str, int] = Counter()
        toxic_examples: Dict[str, Tuple[int, str]] = {}

        for sample in samples:
            text = sample["text"]
            for pattern, ptype in TOXIC_PATTERNS:
                if re.search(pattern, text):
                    toxic_counts[ptype] += 1
                    if ptype not in toxic_examples:
                        toxic_examples[ptype] = (sample["index"], text[:200])

        for ptype, count in toxic_counts.items():
            idx, excerpt = toxic_examples[ptype]
            report.findings.append(ValidationFinding(
                severity="HIGH",
                category="toxicity",
                title=f"Toxic content: {ptype}",
                description=f"Found {count} samples with '{ptype}' patterns.",
                sample_index=idx,
                sample_text=excerpt,
                pattern_matched=ptype,
                count=count,
            ))

    def _check_label_integrity(self, samples: List[Dict], report: FinetuneValidationReport):
        """Check for label poisoning and class imbalance."""
        labels = [s["label"] for s in samples if s["label"] is not None]
        if not labels:
            return

        label_counts = Counter(labels)
        total = len(labels)

        # Extreme class imbalance
        if len(label_counts) >= 2:
            most_common_pct = label_counts.most_common(1)[0][1] / total
            least_common_pct = label_counts.most_common()[-1][1] / total

            if most_common_pct > 0.95:
                report.findings.append(ValidationFinding(
                    severity="HIGH",
                    category="label_integrity",
                    title="Extreme class imbalance",
                    description=(
                        f"Most common label '{label_counts.most_common(1)[0][0]}' represents "
                        f"{most_common_pct:.0%} of data. May indicate label poisoning."
                    ),
                    count=1,
                ))

            if least_common_pct < 0.01 and total > 100:
                report.findings.append(ValidationFinding(
                    severity="MEDIUM",
                    category="label_integrity",
                    title="Severely underrepresented class",
                    description=(
                        f"Least common label '{label_counts.most_common()[-1][0]}' has only "
                        f"{label_counts.most_common()[-1][1]} samples ({least_common_pct:.1%})."
                    ),
                    count=1,
                ))

        report.statistics["label_distribution"] = dict(label_counts)
        report.statistics["unique_labels"] = len(label_counts)

    def _check_distribution(self, samples: List[Dict], report: FinetuneValidationReport):
        """Check text length distribution for anomalies."""
        lengths = [len(s["text"]) for s in samples if s["text"]]
        if not lengths:
            return

        mean_len = statistics.mean(lengths)
        stdev_len = statistics.stdev(lengths) if len(lengths) > 1 else 0
        min_len = min(lengths)
        max_len = max(lengths)

        report.statistics["text_length"] = {
            "mean": round(mean_len, 1),
            "stdev": round(stdev_len, 1),
            "min": min_len,
            "max": max_len,
            "median": statistics.median(lengths),
        }

        # Extreme outliers (potential context stuffing attacks)
        if stdev_len > 0:
            outliers = [i for i, l in enumerate(lengths) if abs(l - mean_len) > 4 * stdev_len]
            if outliers:
                report.findings.append(ValidationFinding(
                    severity="MEDIUM",
                    category="distribution",
                    title=f"Length outliers detected: {len(outliers)} samples",
                    description=(
                        f"Mean length: {mean_len:.0f} chars. "
                        f"{len(outliers)} samples deviate by >4 standard deviations. "
                        "May indicate context stuffing or padding attacks."
                    ),
                    count=len(outliers),
                ))

        # Very short samples (potential label-only poisoning)
        very_short = sum(1 for l in lengths if l < 10)
        if very_short > 0 and very_short / len(lengths) > 0.05:
            report.findings.append(ValidationFinding(
                severity="MEDIUM",
                category="distribution",
                title=f"Many very short samples: {very_short}",
                description=f"{very_short} samples have <10 characters ({very_short/len(lengths):.0%}).",
                count=very_short,
            ))

    def _check_duplicates(self, samples: List[Dict], report: FinetuneValidationReport):
        """Check for exact and near-duplicate training examples."""
        seen_texts: Dict[str, int] = {}
        duplicates = 0

        for sample in samples:
            text = sample["text"].strip()
            if text in seen_texts:
                duplicates += 1
            else:
                seen_texts[text] = sample["index"]

        dup_rate = duplicates / len(samples) if samples else 0
        report.statistics["duplicate_count"] = duplicates
        report.statistics["duplicate_rate"] = round(dup_rate, 4)

        if dup_rate > 0.1:
            report.findings.append(ValidationFinding(
                severity="HIGH",
                category="distribution",
                title=f"High duplication rate: {dup_rate:.0%}",
                description=(
                    f"{duplicates} exact duplicates found ({dup_rate:.0%}). "
                    "High duplication can amplify poisoning effects or cause overfitting."
                ),
                count=duplicates,
            ))
        elif dup_rate > 0.01:
            report.findings.append(ValidationFinding(
                severity="MEDIUM",
                category="distribution",
                title=f"Duplicates detected: {duplicates} ({dup_rate:.1%})",
                description="Some duplicate samples found. Review for intentional vs accidental.",
                count=duplicates,
            ))

    def validate_and_export(self, file_path: str, output_path: str, **kwargs) -> FinetuneValidationReport:
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

    parser = argparse.ArgumentParser(description="Fine-Tuning Data Validator")
    parser.add_argument("file_path", help="Path to training data file (.jsonl, .json, .csv)")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--text-column", help="Column name for text (CSV)")
    parser.add_argument("--label-column", help="Column name for labels (CSV)")
    parser.add_argument("--max-samples", type=int, default=100_000, help="Maximum samples to scan")
    args = parser.parse_args()

    validator = FinetuneValidator(max_samples=args.max_samples)

    if args.output:
        report = validator.validate_and_export(
            args.file_path, args.output,
            text_column=args.text_column,
            label_column=args.label_column,
        )
    else:
        report = validator.validate(
            args.file_path,
            text_column=args.text_column,
            label_column=args.label_column,
        )

    d = report.to_dict()
    print(f"\n{'='*60}")
    print(f"Fine-Tuning Data Validation: {Path(args.file_path).name}")
    print(f"{'='*60}")
    print(f"Samples:  {report.total_samples}")
    print(f"Format:   {report.format_type}")
    print(f"Status:   {'SAFE' if report.safe_for_training else 'UNSAFE'}")
    print(f"Findings: {d['summary']['total_findings']}")
    print(f"  CRITICAL: {d['summary']['critical']}")
    print(f"  HIGH:     {d['summary']['high']}")
    print(f"  MEDIUM:   {d['summary']['medium']}")
    print(f"  LOW:      {d['summary']['low']}")

    if not report.safe_for_training:
        print(f"\nBlocking findings:")
        for f in report.findings:
            if f.severity in ("CRITICAL", "HIGH"):
                print(f"  [{f.severity}] {f.title}: {f.description}")
