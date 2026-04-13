"""
Model Provenance Scanner
TAG Enterprise AI Security Handbook 2026 — AI Supply category

Scans model artifacts for:
- Hash verification against known-good checksums
- Known vulnerable model version detection
- Pickle deserialization risk scanning
- Model card / provenance metadata validation
"""

import hashlib
import json
import struct
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# --- Known Vulnerable Model Versions ---
# Maintained from public advisories (HuggingFace, NVIDIA, PyTorch security bulletins)
KNOWN_VULNERABLE_VERSIONS: Dict[str, List[Dict[str, str]]] = {
    "llama-2": [
        {"version": "< 2.0.1", "cve": "N/A", "risk": "Initial release had unfiltered system prompt leakage"},
    ],
    "pytorch": [
        {"version": "< 1.13.1", "cve": "CVE-2022-45907", "risk": "Arbitrary code execution via TorchScript"},
        {"version": "< 2.0.1", "cve": "CVE-2023-45825", "risk": "Pickle deserialization RCE"},
    ],
    "transformers": [
        {"version": "< 4.36.0", "cve": "CVE-2023-7018", "risk": "Arbitrary code execution via safetensors bypass"},
        {"version": "< 4.38.0", "cve": "CVE-2024-3568", "risk": "Remote code execution in model loading"},
    ],
    "onnxruntime": [
        {"version": "< 1.16.2", "cve": "CVE-2024-0243", "risk": "Buffer overflow in ONNX model parsing"},
    ],
    "tensorflow": [
        {"version": "< 2.14.1", "cve": "CVE-2023-25801", "risk": "OOB read in TFLite"},
    ],
}

# Pickle opcodes that indicate potentially dangerous operations
DANGEROUS_PICKLE_OPCODES = {
    b"\x63": "GLOBAL — imports arbitrary module (potential RCE)",
    b"\x69": "INST — instantiates arbitrary class",
    b"\x52": "REDUCE — calls arbitrary callable",
    b"\x81": "NEWOBJ — creates new object via __new__",
    b"\x92": "NEWOBJ_EX — extended new object creation",
    b"\x93": "STACK_GLOBAL — stack-based global import",
}

# Suspicious module references in pickle streams
SUSPICIOUS_MODULES = [
    "os", "subprocess", "sys", "shutil", "builtins",
    "importlib", "ctypes", "socket", "http", "urllib",
    "pickle", "shelve", "exec", "eval", "compile",
    "webbrowser", "tempfile", "signal", "code",
]


@dataclass
class ScanFinding:
    """A single finding from the model scanner."""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # hash_mismatch, vulnerable_version, pickle_risk, provenance
    title: str
    description: str
    file_path: Optional[str] = None
    remediation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanReport:
    """Complete scan report for a model artifact."""
    scan_id: str
    timestamp: str
    model_path: str
    model_name: Optional[str]
    findings: List[ScanFinding] = field(default_factory=list)
    hash_sha256: Optional[str] = None
    file_size_bytes: Optional[int] = None
    scan_duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def passed(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "model_path": self.model_path,
            "model_name": self.model_name,
            "hash_sha256": self.hash_sha256,
            "file_size_bytes": self.file_size_bytes,
            "scan_duration_seconds": self.scan_duration_seconds,
            "passed": self.passed,
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": sum(1 for f in self.findings if f.severity == "MEDIUM"),
                "low": sum(1 for f in self.findings if f.severity == "LOW"),
                "info": sum(1 for f in self.findings if f.severity == "INFO"),
            },
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "file_path": f.file_path,
                    "remediation": f.remediation,
                    "metadata": f.metadata,
                }
                for f in self.findings
            ],
        }


class ModelProvenanceScanner:
    """
    Scans model artifacts for supply chain risks.

    Checks:
    1. Hash verification — compare SHA-256 against known-good checksums
    2. Vulnerable versions — match against CVE database
    3. Pickle safety — scan for dangerous deserialization opcodes
    4. Provenance metadata — validate model cards and origin
    """

    def __init__(self, known_hashes: Optional[Dict[str, str]] = None):
        """
        Args:
            known_hashes: Optional dict of {model_name: expected_sha256} for verification.
        """
        self.known_hashes = known_hashes or {}

    def scan(self, model_path: str, model_name: Optional[str] = None) -> ScanReport:
        """
        Run all scans on a model artifact.

        Args:
            model_path: Path to the model file or directory.
            model_name: Optional human-readable model name.

        Returns:
            ScanReport with all findings.
        """
        start = datetime.now()
        path = Path(model_path)

        report = ScanReport(
            scan_id=f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            timestamp=datetime.now().isoformat(),
            model_path=str(path),
            model_name=model_name,
        )

        if not path.exists():
            report.findings.append(ScanFinding(
                severity="CRITICAL",
                category="file_missing",
                title="Model artifact not found",
                description=f"Path does not exist: {model_path}",
                remediation="Verify the model path and ensure the artifact is accessible.",
            ))
            report.scan_duration_seconds = (datetime.now() - start).total_seconds()
            return report

        if path.is_file():
            report.file_size_bytes = path.stat().st_size
            report.hash_sha256 = self._compute_sha256(path)

            # Hash verification
            self._check_hash(path, model_name, report)

            # Pickle safety scan
            self._scan_pickle_risk(path, report)

            # File format checks
            self._check_file_format(path, report)

        elif path.is_dir():
            # Scan directory for model files
            self._scan_directory(path, report)

        # Vulnerable version check (always runs)
        if model_name:
            self._check_vulnerable_versions(model_name, report)

        # Provenance metadata check
        self._check_provenance(path, report)

        report.scan_duration_seconds = (datetime.now() - start).total_seconds()
        return report

    def _compute_sha256(self, file_path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _check_hash(self, file_path: Path, model_name: Optional[str], report: ScanReport) -> None:
        """Verify file hash against known-good checksums."""
        if not model_name or model_name not in self.known_hashes:
            report.findings.append(ScanFinding(
                severity="INFO",
                category="hash_verification",
                title="No known-good hash available",
                description=f"No reference hash registered for '{model_name or file_path.name}'. "
                            "Cannot verify integrity.",
                remediation="Register the expected SHA-256 hash from the model provider.",
            ))
            return

        expected = self.known_hashes[model_name]
        actual = report.hash_sha256

        if actual != expected:
            report.findings.append(ScanFinding(
                severity="CRITICAL",
                category="hash_mismatch",
                title="Model hash does not match expected value",
                description=f"Expected SHA-256: {expected}\nActual SHA-256:   {actual}",
                file_path=str(file_path),
                remediation="Re-download the model from the official source. "
                            "Do not use this artifact — it may have been tampered with.",
                metadata={"expected_hash": expected, "actual_hash": actual},
            ))
        else:
            report.findings.append(ScanFinding(
                severity="INFO",
                category="hash_verification",
                title="Hash verification passed",
                description=f"SHA-256 matches expected value: {expected[:16]}...",
                file_path=str(file_path),
            ))

    def _scan_pickle_risk(self, file_path: Path, report: ScanReport) -> None:
        """Scan a file for dangerous pickle opcodes."""
        suffix = file_path.suffix.lower()

        # Only scan files that could contain pickle data
        pickle_extensions = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt"}
        if suffix not in pickle_extensions:
            return

        try:
            data = file_path.read_bytes()
        except Exception as e:
            report.findings.append(ScanFinding(
                severity="MEDIUM",
                category="pickle_risk",
                title="Could not read file for pickle scan",
                description=f"Error reading {file_path.name}: {e}",
                file_path=str(file_path),
            ))
            return

        # Check for pickle magic bytes
        has_pickle = (
            data[:2] == b"\x80\x05"  # Protocol 5
            or data[:2] == b"\x80\x04"  # Protocol 4
            or data[:2] == b"\x80\x03"  # Protocol 3
            or data[:2] == b"\x80\x02"  # Protocol 2
        )

        # Also check inside zip archives (PyTorch .pt files are zip)
        if suffix in {".pt", ".pth"} and not has_pickle:
            has_pickle = self._check_zip_for_pickle(file_path, report)

        if not has_pickle and suffix in {".pkl", ".pickle"}:
            has_pickle = True  # Assume pickle by extension

        if not has_pickle:
            return

        report.findings.append(ScanFinding(
            severity="HIGH",
            category="pickle_risk",
            title="File uses pickle serialization",
            description=f"{file_path.name} contains pickle data. Pickle deserialization "
                        "can execute arbitrary code during model loading.",
            file_path=str(file_path),
            remediation="Use safetensors format instead of pickle-based formats. "
                        "If pickle is required, use torch.load(weights_only=True).",
        ))

        # Scan for dangerous opcodes
        dangerous_found = []
        for opcode, desc in DANGEROUS_PICKLE_OPCODES.items():
            if opcode in data:
                dangerous_found.append(desc)

        if dangerous_found:
            report.findings.append(ScanFinding(
                severity="CRITICAL",
                category="pickle_risk",
                title="Dangerous pickle opcodes detected",
                description="The following dangerous opcodes were found:\n"
                            + "\n".join(f"  - {d}" for d in dangerous_found),
                file_path=str(file_path),
                remediation="Do NOT load this model without sandboxing. "
                            "Inspect the pickle stream with pickletools.dis() before use.",
                metadata={"dangerous_opcodes": dangerous_found},
            ))

        # Check for suspicious module references
        suspicious_found = []
        data_str = data.decode("latin-1")  # Safe for byte scanning
        for mod in SUSPICIOUS_MODULES:
            if f"\n{mod}\n" in data_str or f"c{mod}\n" in data_str:
                suspicious_found.append(mod)

        if suspicious_found:
            report.findings.append(ScanFinding(
                severity="CRITICAL",
                category="pickle_risk",
                title="Suspicious module imports in pickle stream",
                description=f"Pickle stream references these modules: {', '.join(suspicious_found)}. "
                            "This strongly indicates malicious payload.",
                file_path=str(file_path),
                remediation="QUARANTINE this model immediately. Do not load it. "
                            "Report to your security team.",
                metadata={"suspicious_modules": suspicious_found},
            ))

    def _check_zip_for_pickle(self, file_path: Path, report: ScanReport) -> bool:
        """Check if a zip-based model file contains pickle data."""
        try:
            if not zipfile.is_zipfile(file_path):
                return False
            with zipfile.ZipFile(file_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".pkl") or "data.pkl" in name:
                        return True
        except Exception:
            pass
        return False

    def _check_file_format(self, file_path: Path, report: ScanReport) -> None:
        """Check if the model uses a safe serialization format."""
        suffix = file_path.suffix.lower()

        safe_formats = {".safetensors", ".onnx", ".tflite", ".gguf", ".ggml"}
        risky_formats = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".h5"}

        if suffix in safe_formats:
            report.findings.append(ScanFinding(
                severity="INFO",
                category="file_format",
                title=f"Safe serialization format: {suffix}",
                description=f"{file_path.name} uses {suffix} which does not support "
                            "arbitrary code execution during deserialization.",
            ))
        elif suffix in risky_formats:
            report.findings.append(ScanFinding(
                severity="MEDIUM",
                category="file_format",
                title=f"Risky serialization format: {suffix}",
                description=f"{file_path.name} uses {suffix} which may execute code during loading.",
                file_path=str(file_path),
                remediation="Convert to safetensors format where possible.",
            ))

    def _check_vulnerable_versions(self, model_name: str, report: ScanReport) -> None:
        """Check if the model name matches known vulnerable versions."""
        name_lower = model_name.lower().replace(" ", "-")

        for vuln_key, vulns in KNOWN_VULNERABLE_VERSIONS.items():
            if vuln_key in name_lower:
                for vuln in vulns:
                    report.findings.append(ScanFinding(
                        severity="HIGH",
                        category="vulnerable_version",
                        title=f"Potentially vulnerable: {vuln_key} {vuln['version']}",
                        description=f"CVE: {vuln['cve']}\nRisk: {vuln['risk']}",
                        remediation=f"Ensure you are using a version newer than {vuln['version']}. "
                                    f"Check {vuln['cve']} for details.",
                        metadata={"cve": vuln["cve"], "affected_versions": vuln["version"]},
                    ))

    def _check_provenance(self, path: Path, report: ScanReport) -> None:
        """Check for model provenance metadata (model card, config, etc.)."""
        if path.is_dir():
            config_path = path / "config.json"
            model_card = path / "README.md"
        else:
            config_path = path.parent / "config.json"
            model_card = path.parent / "README.md"

        if not config_path.exists():
            report.findings.append(ScanFinding(
                severity="MEDIUM",
                category="provenance",
                title="No config.json found",
                description="Model directory lacks config.json. Cannot verify model architecture, "
                            "training parameters, or origin.",
                remediation="Ensure the model includes a config.json with architecture and provenance info.",
            ))
        else:
            try:
                config = json.loads(config_path.read_text(encoding="utf-8"))
                # Check for key provenance fields
                provenance_fields = ["model_type", "architectures", "transformers_version"]
                missing = [f for f in provenance_fields if f not in config]
                if missing:
                    report.findings.append(ScanFinding(
                        severity="LOW",
                        category="provenance",
                        title="Incomplete config.json",
                        description=f"Missing provenance fields: {', '.join(missing)}",
                        file_path=str(config_path),
                        remediation="Add missing fields to config.json for full provenance tracking.",
                    ))
                else:
                    report.findings.append(ScanFinding(
                        severity="INFO",
                        category="provenance",
                        title="config.json provenance check passed",
                        description=f"Model type: {config.get('model_type', 'unknown')}, "
                                    f"Architecture: {config.get('architectures', ['unknown'])}",
                        file_path=str(config_path),
                    ))
            except (json.JSONDecodeError, Exception) as e:
                report.findings.append(ScanFinding(
                    severity="MEDIUM",
                    category="provenance",
                    title="config.json is malformed",
                    description=f"Could not parse config.json: {e}",
                    file_path=str(config_path),
                    remediation="Fix the JSON syntax in config.json.",
                ))

        if not model_card.exists():
            report.findings.append(ScanFinding(
                severity="LOW",
                category="provenance",
                title="No model card (README.md) found",
                description="Model lacks a model card. This makes it harder to verify origin, "
                            "training data, and intended use.",
                remediation="Include a model card following HuggingFace model card guidelines.",
            ))

    def _scan_directory(self, dir_path: Path, report: ScanReport) -> None:
        """Scan all model files in a directory."""
        model_extensions = {
            ".safetensors", ".pt", ".pth", ".bin", ".ckpt",
            ".pkl", ".pickle", ".onnx", ".tflite", ".gguf", ".h5",
        }

        model_files = [f for f in dir_path.rglob("*") if f.suffix.lower() in model_extensions]

        if not model_files:
            report.findings.append(ScanFinding(
                severity="INFO",
                category="file_format",
                title="No model files found in directory",
                description=f"No recognized model files in {dir_path}",
            ))
            return

        for mf in model_files:
            report.file_size_bytes = (report.file_size_bytes or 0) + mf.stat().st_size
            self._check_file_format(mf, report)
            self._scan_pickle_risk(mf, report)

    def scan_and_export(
        self,
        model_path: str,
        output_path: str,
        model_name: Optional[str] = None,
    ) -> ScanReport:
        """Scan a model and export the report to JSON."""
        report = self.scan(model_path, model_name)

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

        return report


# --- CLI entrypoint ---
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Model Provenance Scanner — supply chain security for AI models"
    )
    parser.add_argument("model_path", help="Path to model file or directory")
    parser.add_argument("--name", help="Model name for version checking")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument(
        "--known-hashes",
        help="JSON file with {model_name: expected_sha256} mappings",
    )
    args = parser.parse_args()

    known = {}
    if args.known_hashes:
        known = json.loads(Path(args.known_hashes).read_text(encoding="utf-8"))

    scanner = ModelProvenanceScanner(known_hashes=known)

    if args.output:
        result = scanner.scan_and_export(args.model_path, args.output, args.name)
    else:
        result = scanner.scan(args.model_path, args.name)

    # Print summary
    d = result.to_dict()
    print(f"\n{'='*60}")
    print(f"Model Provenance Scan: {result.model_name or result.model_path}")
    print(f"{'='*60}")
    print(f"Status:   {'PASS' if result.passed else 'FAIL'}")
    print(f"SHA-256:  {result.hash_sha256 or 'N/A (directory scan)'}")
    print(f"Findings: {d['summary']['total_findings']} total")
    print(f"  CRITICAL: {d['summary']['critical']}")
    print(f"  HIGH:     {d['summary']['high']}")
    print(f"  MEDIUM:   {d['summary']['medium']}")
    print(f"  LOW:      {d['summary']['low']}")
    print(f"  INFO:     {d['summary']['info']}")
    print(f"Duration: {result.scan_duration_seconds:.2f}s")

    if not result.passed:
        print(f"\nCritical/High findings:")
        for f in result.findings:
            if f.severity in ("CRITICAL", "HIGH"):
                print(f"  [{f.severity}] {f.title}")
                print(f"    {f.description}")
                if f.remediation:
                    print(f"    Fix: {f.remediation}")
