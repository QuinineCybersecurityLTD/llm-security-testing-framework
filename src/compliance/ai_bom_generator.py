"""
AI Software Bill of Materials (AI-BOM) Generator
==================================================
Generates AI-specific Software Bill of Materials for regulatory compliance.
Supports SPDX, CycloneDX, and custom JSON export formats.

An AI-BOM maps all external dependencies in an AI system: foundation models,
datasets, libraries, runtimes, tools, and APIs — providing transparency
for supply chain risk management.

References:
  - EU AI Act Article 11 (technical documentation)
  - OWASP LLM03:2025 (Supply Chain Vulnerabilities)
  - SPDX 3.0 AI/ML Profile
  - CycloneDX 1.6 ML-BOM
"""

import json
import hashlib
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

log = logging.getLogger("llm_security.ai_bom_generator")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass
class AIBOMComponent:
    """Single component in the AI Software Bill of Materials."""
    component_type: str  # model, dataset, library, runtime, tool, api, framework
    name: str
    version: str
    provider: str
    license: str = "UNKNOWN"
    hash_sha256: Optional[str] = None
    download_url: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    risk_flags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AIBOM:
    """Complete AI Software Bill of Materials."""
    bom_id: str
    created: str
    system_name: str
    system_version: str
    provider: str
    components: List[AIBOMComponent] = field(default_factory=list)
    risk_summary: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "bom_id": self.bom_id,
            "created": self.created,
            "system_name": self.system_name,
            "system_version": self.system_version,
            "provider": self.provider,
            "total_components": len(self.components),
            "components": [c.to_dict() for c in self.components],
            "risk_summary": self.risk_summary,
        }


class AIBOMGenerator:
    """Generate AI Software Bill of Materials for regulatory compliance."""

    # Known risky model formats
    RISKY_FORMATS = {".pkl", ".pt", ".pth", ".bin", ".ckpt", ".h5", ".pickle"}
    SAFE_FORMATS = {".safetensors", ".onnx", ".tflite", ".gguf"}

    # Known vulnerable library versions (from model_scanner.py)
    KNOWN_VULNERABILITIES = {
        "transformers": [("< 4.36.0", "CVE-2023-49082: Remote code execution via deserialization")],
        "torch": [("< 1.13.1", "CVE-2022-45907: Arbitrary code execution via TorchScript")],
        "tensorflow": [("< 2.12.0", "CVE-2023-25801: Denial of service via malformed model")],
        "pillow": [("< 10.0.1", "CVE-2023-44271: Buffer overflow in image processing")],
    }

    def generate(
        self,
        model_config: Optional[Dict] = None,
        scan_results: Optional[List[Dict]] = None,
        requirements_path: Optional[Path] = None,
    ) -> AIBOM:
        """
        Generate an AI-BOM from available sources.

        Args:
            model_config: Model configuration dict (from config YAML)
            scan_results: Results from model_scanner.py
            requirements_path: Path to requirements.txt for dependency extraction
        """
        bom = AIBOM(
            bom_id=f"AIBOM-{hashlib.sha256(datetime.utcnow().isoformat().encode()).hexdigest()[:12]}",
            created=datetime.utcnow().isoformat(),
            system_name=model_config.get("name", "LLM System") if model_config else "LLM System",
            system_version="1.0.0",
            provider=model_config.get("provider", "Unknown") if model_config else "Unknown",
        )

        # Extract model components
        if model_config:
            self._extract_model_components(bom, model_config)

        # Extract library dependencies
        if requirements_path and requirements_path.exists():
            self._extract_library_components(bom, requirements_path)

        # Integrate scan results
        if scan_results:
            self._integrate_scan_results(bom, scan_results)

        # Calculate risk summary
        bom.risk_summary = self._calculate_risk_summary(bom)

        return bom

    def _extract_model_components(self, bom: AIBOM, config: Dict) -> None:
        """Extract model components from configuration."""
        targets = config.get("targets", [config]) if isinstance(config.get("targets"), list) else [config]

        for target in targets:
            model_name = target.get("model_name", target.get("name", "unknown_model"))
            model_type = target.get("type", target.get("model_type", "unknown"))
            endpoint = target.get("endpoint", "")
            provider = target.get("provider", model_type)

            risk_flags = []
            if "api_key" in str(target) or "API_KEY" in str(target):
                risk_flags.append("USES_API_KEY")
            if endpoint and "http://" in endpoint:
                risk_flags.append("UNENCRYPTED_ENDPOINT")
            if any(model_name.endswith(ext) for ext in self.RISKY_FORMATS):
                risk_flags.append("RISKY_SERIALIZATION_FORMAT")

            component = AIBOMComponent(
                component_type="model",
                name=model_name,
                version=target.get("version", "latest"),
                provider=provider,
                license=target.get("license", "UNKNOWN"),
                download_url=endpoint if endpoint else None,
                risk_flags=risk_flags,
                metadata={
                    "model_type": model_type,
                    "parameters": target.get("parameters", {}),
                },
            )
            bom.components.append(component)

        # Add judge model if present
        judge = config.get("judge_model", {})
        if judge:
            bom.components.append(AIBOMComponent(
                component_type="model",
                name=judge.get("model_name", "judge_model"),
                version="latest",
                provider=judge.get("type", "unknown"),
                license="UNKNOWN",
                metadata={"role": "evaluator_judge"},
            ))

    def _extract_library_components(self, bom: AIBOM, requirements_path: Path) -> None:
        """Extract library dependencies from requirements.txt."""
        with open(requirements_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue

                # Parse package==version or package>=version
                name = line
                version = "unspecified"
                for op in ['==', '>=', '<=', '~=', '!=', '<', '>']:
                    if op in line:
                        parts = line.split(op, 1)
                        name = parts[0].strip()
                        version = f"{op}{parts[1].strip()}"
                        break

                # Extract extras (e.g., package[extra])
                if '[' in name:
                    name = name.split('[')[0]

                risk_flags = []
                if name.lower() in self.KNOWN_VULNERABILITIES:
                    for vuln_version, cve in self.KNOWN_VULNERABILITIES[name.lower()]:
                        risk_flags.append(f"KNOWN_CVE: {cve}")

                bom.components.append(AIBOMComponent(
                    component_type="library",
                    name=name,
                    version=version,
                    provider="PyPI",
                    risk_flags=risk_flags,
                ))

    def _integrate_scan_results(self, bom: AIBOM, scan_results: List[Dict]) -> None:
        """Integrate findings from model_scanner into the BOM."""
        for result in scan_results:
            findings = result.get("findings", [])
            model_name = result.get("model_name", result.get("file_path", "unknown"))

            for component in bom.components:
                if component.name == model_name:
                    for finding in findings:
                        severity = finding.get("severity", "INFO")
                        desc = finding.get("description", "")
                        if severity in ("CRITICAL", "HIGH"):
                            component.risk_flags.append(f"{severity}: {desc}")

    def _calculate_risk_summary(self, bom: AIBOM) -> Dict[str, int]:
        """Calculate aggregate risk summary."""
        summary = {
            "total_components": len(bom.components),
            "models": sum(1 for c in bom.components if c.component_type == "model"),
            "libraries": sum(1 for c in bom.components if c.component_type == "library"),
            "datasets": sum(1 for c in bom.components if c.component_type == "dataset"),
            "tools": sum(1 for c in bom.components if c.component_type == "tool"),
            "components_with_risks": sum(1 for c in bom.components if c.risk_flags),
            "total_risk_flags": sum(len(c.risk_flags) for c in bom.components),
            "unknown_licenses": sum(1 for c in bom.components if c.license == "UNKNOWN"),
            "risky_formats": sum(1 for c in bom.components if "RISKY_SERIALIZATION_FORMAT" in c.risk_flags),
            "known_cves": sum(1 for c in bom.components for f in c.risk_flags if "KNOWN_CVE" in f),
        }
        return summary

    def export_json(self, bom: AIBOM, output_path: Path) -> Path:
        """Export AI-BOM as JSON."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(bom.to_dict(), f, indent=2)
        log.info("AI-BOM exported to %s", output_path)
        return output_path

    def export_spdx(self, bom: AIBOM, output_path: Path) -> Path:
        """Export AI-BOM in SPDX 3.0 JSON format (AI/ML profile)."""
        spdx = {
            "spdxVersion": "SPDX-3.0",
            "dataLicense": "CC0-1.0",
            "SPDXID": f"SPDXRef-{bom.bom_id}",
            "name": bom.system_name,
            "documentNamespace": f"https://quinine.ai/spdx/{bom.bom_id}",
            "creationInfo": {
                "created": bom.created,
                "creators": ["Tool: Quinine LLM Security Framework"],
                "licenseListVersion": "3.22",
            },
            "packages": [],
        }

        for i, component in enumerate(bom.components):
            pkg = {
                "SPDXID": f"SPDXRef-Package-{i}",
                "name": component.name,
                "versionInfo": component.version,
                "supplier": f"Organization: {component.provider}",
                "downloadLocation": component.download_url or "NOASSERTION",
                "licenseConcluded": component.license if component.license != "UNKNOWN" else "NOASSERTION",
                "primaryPackagePurpose": self._map_type_to_spdx_purpose(component.component_type),
                "checksums": [],
            }
            if component.hash_sha256:
                pkg["checksums"].append({"algorithm": "SHA256", "checksumValue": component.hash_sha256})
            # AI/ML SPDX extension
            if component.component_type == "model":
                pkg["ai_ml_profile"] = {
                    "modelType": component.metadata.get("model_type", "unknown"),
                    "riskFlags": component.risk_flags,
                }
            spdx["packages"].append(pkg)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(spdx, f, indent=2)
        log.info("SPDX AI-BOM exported to %s", output_path)
        return output_path

    def export_cyclonedx(self, bom: AIBOM, output_path: Path) -> Path:
        """Export AI-BOM in CycloneDX 1.6 JSON format (ML-BOM)."""
        cdx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{bom.bom_id}",
            "version": 1,
            "metadata": {
                "timestamp": bom.created,
                "tools": [{"vendor": "Quinine Cybersecurity", "name": "LLM Security Framework", "version": "4.0"}],
                "component": {
                    "type": "machine-learning-model",
                    "name": bom.system_name,
                    "version": bom.system_version,
                },
            },
            "components": [],
        }

        for component in bom.components:
            cdx_comp = {
                "type": self._map_type_to_cdx(component.component_type),
                "name": component.name,
                "version": component.version,
                "supplier": {"name": component.provider},
                "licenses": [{"license": {"id": component.license}}] if component.license != "UNKNOWN" else [],
                "properties": [{"name": f"quinine:risk:{i}", "value": flag} for i, flag in enumerate(component.risk_flags)],
            }
            if component.hash_sha256:
                cdx_comp["hashes"] = [{"alg": "SHA-256", "content": component.hash_sha256}]
            # CycloneDX ML-BOM extension
            if component.component_type == "model":
                cdx_comp["modelCard"] = {
                    "modelParameters": component.metadata.get("parameters", {}),
                }
            cdx["components"].append(cdx_comp)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(cdx, f, indent=2)
        log.info("CycloneDX ML-BOM exported to %s", output_path)
        return output_path

    @staticmethod
    def _map_type_to_spdx_purpose(component_type: str) -> str:
        return {
            "model": "APPLICATION",
            "dataset": "DATA",
            "library": "LIBRARY",
            "runtime": "OPERATING-SYSTEM",
            "tool": "APPLICATION",
            "api": "APPLICATION",
            "framework": "FRAMEWORK",
        }.get(component_type, "OTHER")

    @staticmethod
    def _map_type_to_cdx(component_type: str) -> str:
        return {
            "model": "machine-learning-model",
            "dataset": "data",
            "library": "library",
            "runtime": "platform",
            "tool": "application",
            "api": "application",
            "framework": "framework",
        }.get(component_type, "library")
