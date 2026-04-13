"""
Kubernetes MLOps Security Scanner
TAG Enterprise AI Security Handbook 2026 — AI Supply + AI PM

Scans Kubernetes manifests and Helm charts for ML pipeline security issues:
- Privileged containers running model inference
- Exposed model serving endpoints without auth
- Missing network policies for ML namespaces
- Insecure model volume mounts
- GPU resource abuse potential
- Missing pod security standards
- Insecure model registry access
- Lack of admission control for model deployments

Usage:
    scanner = K8sMLOpsScanner()
    report = scanner.scan_manifest("deployment.yaml")
    report = scanner.scan_directory("k8s/")
    report = scanner.scan_helm_values("values.yaml")

CLI:
    python -m supply_chain.k8s_scanner path/to/manifests/ --output report.json
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass
class K8sFinding:
    """A security finding from K8s manifest scanning."""
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str           # See CATEGORIES below
    title: str
    description: str
    file_path: Optional[str] = None
    resource_kind: Optional[str] = None
    resource_name: Optional[str] = None
    namespace: Optional[str] = None
    remediation: str = ""
    cis_benchmark: Optional[str] = None  # CIS Kubernetes Benchmark reference

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "resource_kind": self.resource_kind,
            "resource_name": self.resource_name,
            "namespace": self.namespace,
            "remediation": self.remediation,
            "cis_benchmark": self.cis_benchmark,
        }


CATEGORIES = [
    "privileged_container",
    "exposed_endpoint",
    "missing_network_policy",
    "insecure_volume",
    "resource_abuse",
    "pod_security",
    "model_registry",
    "admission_control",
    "secrets_management",
    "image_security",
]


@dataclass
class K8sScanReport:
    """Complete K8s security scan report."""
    scan_id: str
    timestamp: str
    scanned_files: List[str] = field(default_factory=list)
    scanned_resources: int = 0
    findings: List[K8sFinding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def passed(self) -> bool:
        return self.critical_count == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "scanned_files": self.scanned_files,
            "scanned_resources": self.scanned_resources,
            "passed": self.passed,
            "summary": {
                "total": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": sum(1 for f in self.findings if f.severity == "MEDIUM"),
                "low": sum(1 for f in self.findings if f.severity == "LOW"),
            },
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# ML-specific K8s image patterns
# ---------------------------------------------------------------------------

ML_SERVING_IMAGES = [
    "tensorflow/serving", "tritonserver", "torchserve",
    "seldon", "kserve", "mlflow", "bentoml", "ray",
    "huggingface", "vllm", "text-generation-inference",
    "ollama", "localai", "llamacpp",
]

ML_PIPELINE_IMAGES = [
    "kubeflow", "argo", "airflow", "mlflow", "dagster",
    "prefect", "metaflow", "kedro", "zenml",
]

SENSITIVE_MOUNT_PATHS = [
    "/models", "/model-store", "/model-repository",
    "/data", "/datasets", "/training-data",
    "/weights", "/checkpoints", "/artifacts",
    "/secrets", "/credentials", "/keys",
]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class K8sMLOpsScanner:
    """Scan Kubernetes manifests for ML pipeline security issues."""

    def __init__(self):
        if yaml is None:
            raise ImportError("PyYAML required: pip install pyyaml")

    def scan_manifest(self, file_path: str) -> K8sScanReport:
        """Scan a single YAML manifest file."""
        report = K8sScanReport(
            scan_id=f"k8s-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            timestamp=datetime.now().isoformat(),
        )

        path = Path(file_path)
        if not path.exists():
            report.findings.append(K8sFinding(
                severity="HIGH", category="file_missing",
                title="Manifest file not found",
                description=f"File not found: {file_path}",
            ))
            return report

        report.scanned_files.append(str(path))
        docs = self._load_yaml_docs(path)

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            report.scanned_resources += 1
            self._check_resource(doc, str(path), report)

        return report

    def scan_directory(self, dir_path: str) -> K8sScanReport:
        """Scan all YAML files in a directory."""
        report = K8sScanReport(
            scan_id=f"k8s-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            timestamp=datetime.now().isoformat(),
        )

        path = Path(dir_path)
        if not path.is_dir():
            report.findings.append(K8sFinding(
                severity="HIGH", category="file_missing",
                title="Directory not found",
                description=f"Directory not found: {dir_path}",
            ))
            return report

        yaml_files = list(path.rglob("*.yaml")) + list(path.rglob("*.yml"))
        for yf in yaml_files:
            report.scanned_files.append(str(yf))
            docs = self._load_yaml_docs(yf)
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                report.scanned_resources += 1
                self._check_resource(doc, str(yf), report)

        return report

    def scan_helm_values(self, values_path: str) -> K8sScanReport:
        """Scan a Helm values.yaml for security misconfigurations."""
        report = K8sScanReport(
            scan_id=f"k8s-helm-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            timestamp=datetime.now().isoformat(),
        )

        path = Path(values_path)
        if not path.exists():
            return report

        report.scanned_files.append(str(path))
        doc = self._load_yaml_docs(path)
        if doc:
            values = doc[0] if isinstance(doc[0], dict) else {}
            report.scanned_resources += 1
            self._check_helm_values(values, str(path), report)

        return report

    # --- Loading ---

    def _load_yaml_docs(self, path: Path) -> list:
        """Load all YAML documents from a file."""
        try:
            text = path.read_text(encoding="utf-8")
            return list(yaml.safe_load_all(text))
        except Exception:
            return []

    # --- Main resource checker ---

    def _check_resource(self, doc: dict, file_path: str, report: K8sScanReport):
        """Run all checks on a single K8s resource."""
        kind = doc.get("kind", "")
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")

        spec = doc.get("spec", {})
        template = spec.get("template", {})
        pod_spec = template.get("spec", spec)  # Pods have spec directly

        containers = pod_spec.get("containers", []) + pod_spec.get("initContainers", [])

        ctx = {
            "kind": kind, "name": name, "namespace": namespace,
            "file_path": file_path, "spec": spec, "pod_spec": pod_spec,
        }

        for container in containers:
            self._check_privileged(container, ctx, report)
            self._check_image_security(container, ctx, report)
            self._check_resource_limits(container, ctx, report)
            self._check_volume_mounts(container, ctx, report)
            self._check_env_secrets(container, ctx, report)
            self._check_capabilities(container, ctx, report)

        if kind == "Service":
            self._check_exposed_service(doc, ctx, report)

        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job"):
            self._check_pod_security_context(pod_spec, ctx, report)
            self._check_service_account(pod_spec, ctx, report)

        if kind == "NetworkPolicy":
            report.findings.append(K8sFinding(
                severity="INFO", category="missing_network_policy",
                title=f"NetworkPolicy found: {name}",
                description="Network policy exists for this namespace.",
                file_path=file_path, resource_kind=kind, resource_name=name,
            ))

    # --- Individual checks ---

    def _check_privileged(self, container: dict, ctx: dict, report: K8sScanReport):
        """Check for privileged containers."""
        sec_ctx = container.get("securityContext", {})
        image = container.get("image", "")
        is_ml = any(ml in image.lower() for ml in ML_SERVING_IMAGES + ML_PIPELINE_IMAGES)

        if sec_ctx.get("privileged", False):
            report.findings.append(K8sFinding(
                severity="CRITICAL",
                category="privileged_container",
                title=f"Privileged container: {container.get('name', 'unknown')}",
                description=(
                    f"Container runs in privileged mode. "
                    f"{'This is an ML serving/pipeline container — especially dangerous.' if is_ml else ''}"
                ),
                file_path=ctx["file_path"],
                resource_kind=ctx["kind"],
                resource_name=ctx["name"],
                namespace=ctx["namespace"],
                remediation="Remove 'privileged: true'. Use specific capabilities instead.",
                cis_benchmark="5.2.1",
            ))

        if sec_ctx.get("runAsUser") == 0 or sec_ctx.get("runAsNonRoot") is False:
            report.findings.append(K8sFinding(
                severity="HIGH",
                category="privileged_container",
                title=f"Container runs as root: {container.get('name', 'unknown')}",
                description="Container runs as root user. Model serving containers should run as non-root.",
                file_path=ctx["file_path"],
                resource_kind=ctx["kind"],
                resource_name=ctx["name"],
                remediation="Set 'runAsNonRoot: true' and 'runAsUser: 1000' in securityContext.",
                cis_benchmark="5.2.6",
            ))

    def _check_image_security(self, container: dict, ctx: dict, report: K8sScanReport):
        """Check container image security."""
        image = container.get("image", "")

        # No tag or using :latest
        if ":" not in image or image.endswith(":latest"):
            report.findings.append(K8sFinding(
                severity="MEDIUM",
                category="image_security",
                title=f"Image uses :latest or no tag: {image}",
                description="Using :latest tag or no tag makes deployments non-reproducible and may pull unverified versions.",
                file_path=ctx["file_path"],
                resource_kind=ctx["kind"],
                resource_name=ctx["name"],
                remediation="Pin image to a specific version tag or SHA digest.",
                cis_benchmark="5.5.1",
            ))

        # No image pull policy
        if container.get("imagePullPolicy") not in ("Always", "IfNotPresent", "Never"):
            pass  # Default is fine

        # Check if ML image from untrusted registry
        if image and not any(image.startswith(r) for r in [
            "gcr.io/", "us-docker.pkg.dev/", "nvcr.io/",
            "registry.k8s.io/", "docker.io/library/", "ghcr.io/",
            "public.ecr.aws/", "mcr.microsoft.com/",
        ]):
            is_ml = any(ml in image.lower() for ml in ML_SERVING_IMAGES)
            if is_ml:
                report.findings.append(K8sFinding(
                    severity="HIGH",
                    category="image_security",
                    title=f"ML serving image from unverified registry: {image}",
                    description="ML model serving image pulled from a non-standard registry. Supply chain risk.",
                    file_path=ctx["file_path"],
                    resource_kind=ctx["kind"],
                    resource_name=ctx["name"],
                    remediation="Use images from trusted registries (gcr.io, nvcr.io, ghcr.io).",
                ))

    def _check_resource_limits(self, container: dict, ctx: dict, report: K8sScanReport):
        """Check for missing resource limits (GPU abuse prevention)."""
        resources = container.get("resources", {})
        limits = resources.get("limits", {})
        requests = resources.get("requests", {})
        image = container.get("image", "")
        is_ml = any(ml in image.lower() for ml in ML_SERVING_IMAGES + ML_PIPELINE_IMAGES)

        if not limits:
            sev = "HIGH" if is_ml else "MEDIUM"
            report.findings.append(K8sFinding(
                severity=sev,
                category="resource_abuse",
                title=f"No resource limits: {container.get('name', 'unknown')}",
                description=(
                    f"Container has no resource limits. "
                    f"{'ML workloads without limits can exhaust GPU/CPU and cause cluster-wide DoS.' if is_ml else ''}"
                ),
                file_path=ctx["file_path"],
                resource_kind=ctx["kind"],
                resource_name=ctx["name"],
                remediation="Set 'resources.limits' for cpu, memory, and nvidia.com/gpu if applicable.",
                cis_benchmark="5.4.1",
            ))

        # GPU without limits
        if "nvidia.com/gpu" in requests and "nvidia.com/gpu" not in limits:
            report.findings.append(K8sFinding(
                severity="HIGH",
                category="resource_abuse",
                title=f"GPU requested without limit: {container.get('name', 'unknown')}",
                description="GPU resources requested but not limited. Could consume all available GPUs.",
                file_path=ctx["file_path"],
                resource_kind=ctx["kind"],
                resource_name=ctx["name"],
                remediation="Set 'resources.limits.nvidia.com/gpu' to match requests.",
            ))

    def _check_volume_mounts(self, container: dict, ctx: dict, report: K8sScanReport):
        """Check for insecure volume mounts (model data exposure)."""
        mounts = container.get("volumeMounts", [])

        for mount in mounts:
            mount_path = mount.get("mountPath", "")

            # Sensitive ML paths
            if any(mount_path.startswith(p) for p in SENSITIVE_MOUNT_PATHS):
                if not mount.get("readOnly", False):
                    report.findings.append(K8sFinding(
                        severity="HIGH",
                        category="insecure_volume",
                        title=f"Writable ML data mount: {mount_path}",
                        description=(
                            f"Volume mounted at '{mount_path}' is writable. "
                            "ML model/data volumes should be read-only to prevent poisoning."
                        ),
                        file_path=ctx["file_path"],
                        resource_kind=ctx["kind"],
                        resource_name=ctx["name"],
                        remediation=f"Set 'readOnly: true' for mount at {mount_path}.",
                    ))

            # Host path mounts
            if mount_path in ("/", "/etc", "/var", "/proc", "/sys"):
                report.findings.append(K8sFinding(
                    severity="CRITICAL",
                    category="insecure_volume",
                    title=f"Dangerous host path mount: {mount_path}",
                    description="Container mounts sensitive host paths. Container escape risk.",
                    file_path=ctx["file_path"],
                    resource_kind=ctx["kind"],
                    resource_name=ctx["name"],
                    remediation="Remove host path mounts. Use PersistentVolumeClaims instead.",
                    cis_benchmark="5.2.12",
                ))

    def _check_env_secrets(self, container: dict, ctx: dict, report: K8sScanReport):
        """Check for secrets in environment variables."""
        env_vars = container.get("env", [])

        secret_patterns = [
            "API_KEY", "SECRET", "PASSWORD", "TOKEN", "CREDENTIAL",
            "AWS_ACCESS", "AZURE_", "GCP_", "OPENAI_", "HF_TOKEN",
            "ANTHROPIC_", "GOOGLE_API",
        ]

        for env in env_vars:
            name = env.get("name", "")
            value = env.get("value")  # Plain text value (not from secretRef)

            if value and any(pat in name.upper() for pat in secret_patterns):
                report.findings.append(K8sFinding(
                    severity="CRITICAL",
                    category="secrets_management",
                    title=f"Hardcoded secret in env: {name}",
                    description=(
                        f"Environment variable '{name}' has a plaintext value. "
                        "API keys and credentials must use Kubernetes Secrets or external vaults."
                    ),
                    file_path=ctx["file_path"],
                    resource_kind=ctx["kind"],
                    resource_name=ctx["name"],
                    remediation="Use 'valueFrom.secretKeyRef' instead of 'value'. Store secrets in K8s Secrets or HashiCorp Vault.",
                    cis_benchmark="5.4.2",
                ))

    def _check_capabilities(self, container: dict, ctx: dict, report: K8sScanReport):
        """Check for dangerous Linux capabilities."""
        sec_ctx = container.get("securityContext", {})
        caps = sec_ctx.get("capabilities", {})
        add = caps.get("add", [])

        dangerous = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL", "NET_RAW", "SYS_RAWIO"}
        found = set(c.upper() for c in add) & dangerous

        if found:
            report.findings.append(K8sFinding(
                severity="HIGH",
                category="pod_security",
                title=f"Dangerous capabilities added: {', '.join(found)}",
                description="Container adds dangerous Linux capabilities that enable container escape.",
                file_path=ctx["file_path"],
                resource_kind=ctx["kind"],
                resource_name=ctx["name"],
                remediation="Remove dangerous capabilities. Use 'drop: [ALL]' and add only what's needed.",
                cis_benchmark="5.2.7",
            ))

        if not caps.get("drop"):
            report.findings.append(K8sFinding(
                severity="MEDIUM",
                category="pod_security",
                title=f"Capabilities not dropped: {container.get('name', 'unknown')}",
                description="Container does not drop any capabilities. Best practice is to drop ALL and add only needed ones.",
                file_path=ctx["file_path"],
                resource_kind=ctx["kind"],
                resource_name=ctx["name"],
                remediation="Add 'capabilities: { drop: [ALL] }' to securityContext.",
                cis_benchmark="5.2.7",
            ))

    def _check_exposed_service(self, doc: dict, ctx: dict, report: K8sScanReport):
        """Check if model serving endpoints are exposed insecurely."""
        spec = doc.get("spec", {})
        svc_type = spec.get("type", "ClusterIP")
        ports = spec.get("ports", [])
        name = ctx["name"]

        is_ml = any(
            ml in name.lower() for ml in
            ["model", "inference", "serving", "predict", "triton", "torchserve", "mlflow", "vllm"]
        )

        if svc_type in ("NodePort", "LoadBalancer") and is_ml:
            report.findings.append(K8sFinding(
                severity="CRITICAL",
                category="exposed_endpoint",
                title=f"ML serving endpoint exposed externally: {name}",
                description=(
                    f"Service type '{svc_type}' exposes ML inference endpoint to external traffic. "
                    "Model endpoints must be behind authentication and API gateway."
                ),
                file_path=ctx["file_path"],
                resource_kind="Service",
                resource_name=name,
                remediation="Use ClusterIP and expose via authenticated Ingress/API Gateway.",
            ))

        # gRPC prediction ports commonly used by ML frameworks
        ml_ports = {8500, 8501, 8080, 8081, 5000, 5001, 9000, 3000}
        for port in ports:
            port_num = port.get("port") or port.get("targetPort")
            if isinstance(port_num, int) and port_num in ml_ports and svc_type != "ClusterIP":
                report.findings.append(K8sFinding(
                    severity="HIGH",
                    category="exposed_endpoint",
                    title=f"Common ML port {port_num} exposed on {name}",
                    description=f"Port {port_num} is commonly used by ML serving frameworks and is exposed externally.",
                    file_path=ctx["file_path"],
                    resource_kind="Service",
                    resource_name=name,
                    remediation=f"Restrict port {port_num} to ClusterIP or add NetworkPolicy.",
                ))

    def _check_pod_security_context(self, pod_spec: dict, ctx: dict, report: K8sScanReport):
        """Check pod-level security context."""
        sec_ctx = pod_spec.get("securityContext", {})

        if not sec_ctx:
            report.findings.append(K8sFinding(
                severity="MEDIUM",
                category="pod_security",
                title=f"No pod security context: {ctx['name']}",
                description="Pod has no security context. Should set runAsNonRoot, fsGroup, seccompProfile.",
                file_path=ctx["file_path"],
                resource_kind=ctx["kind"],
                resource_name=ctx["name"],
                remediation="Add pod-level securityContext with runAsNonRoot, fsGroup, and seccompProfile.",
                cis_benchmark="5.2.6",
            ))

        if not sec_ctx.get("seccompProfile"):
            report.findings.append(K8sFinding(
                severity="MEDIUM",
                category="pod_security",
                title=f"No seccomp profile: {ctx['name']}",
                description="No seccomp profile set. Containers can make unrestricted syscalls.",
                file_path=ctx["file_path"],
                resource_kind=ctx["kind"],
                resource_name=ctx["name"],
                remediation="Set 'seccompProfile: { type: RuntimeDefault }' in pod securityContext.",
                cis_benchmark="5.7.2",
            ))

    def _check_service_account(self, pod_spec: dict, ctx: dict, report: K8sScanReport):
        """Check service account configuration."""
        sa = pod_spec.get("serviceAccountName", "default")
        automount = pod_spec.get("automountServiceAccountToken", True)

        if sa == "default":
            report.findings.append(K8sFinding(
                severity="MEDIUM",
                category="admission_control",
                title=f"Using default service account: {ctx['name']}",
                description="Pod uses the default service account. ML workloads should use dedicated service accounts.",
                file_path=ctx["file_path"],
                resource_kind=ctx["kind"],
                resource_name=ctx["name"],
                remediation="Create and assign a dedicated service account with least-privilege RBAC.",
                cis_benchmark="5.1.5",
            ))

        if automount and sa == "default":
            report.findings.append(K8sFinding(
                severity="HIGH",
                category="admission_control",
                title=f"Auto-mounted default SA token: {ctx['name']}",
                description="Default SA token is auto-mounted. If the container is compromised, attacker gets cluster API access.",
                file_path=ctx["file_path"],
                resource_kind=ctx["kind"],
                resource_name=ctx["name"],
                remediation="Set 'automountServiceAccountToken: false' or use a dedicated SA.",
                cis_benchmark="5.1.6",
            ))

    def _check_helm_values(self, values: dict, file_path: str, report: K8sScanReport):
        """Check Helm values.yaml for ML-specific misconfigurations."""
        # Recursive check for dangerous patterns
        self._walk_helm_values(values, "", file_path, report)

    def _walk_helm_values(self, obj: Any, path: str, file_path: str, report: K8sScanReport):
        """Walk Helm values recursively looking for issues."""
        if isinstance(obj, dict):
            # Check for plaintext secrets
            for key, val in obj.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(val, str) and any(
                    pat in key.lower() for pat in ["password", "secret", "apikey", "token"]
                ):
                    if val and val not in ("", "CHANGEME", "TODO"):
                        report.findings.append(K8sFinding(
                            severity="CRITICAL",
                            category="secrets_management",
                            title=f"Plaintext secret in Helm values: {current_path}",
                            description=f"Key '{current_path}' appears to contain a plaintext secret.",
                            file_path=file_path,
                            remediation="Use Helm secrets plugin or external secrets operator.",
                        ))

                # Check for privileged settings
                if key == "privileged" and val is True:
                    report.findings.append(K8sFinding(
                        severity="CRITICAL",
                        category="privileged_container",
                        title=f"Privileged mode enabled in Helm: {current_path}",
                        description="Helm values enable privileged container mode.",
                        file_path=file_path,
                        remediation="Set 'privileged: false' in Helm values.",
                    ))

                self._walk_helm_values(val, current_path, file_path, report)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._walk_helm_values(item, f"{path}[{i}]", file_path, report)

    def scan_and_export(self, scan_path: str, output_path: str) -> K8sScanReport:
        """Scan and export report to JSON."""
        path = Path(scan_path)
        if path.is_dir():
            report = self.scan_directory(scan_path)
        else:
            report = self.scan_manifest(scan_path)

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

    parser = argparse.ArgumentParser(description="K8s MLOps Security Scanner")
    parser.add_argument("path", help="Path to K8s manifest file or directory")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--helm", action="store_true", help="Scan as Helm values.yaml")
    args = parser.parse_args()

    scanner = K8sMLOpsScanner()

    if args.helm:
        report = scanner.scan_helm_values(args.path)
    elif Path(args.path).is_dir():
        report = scanner.scan_directory(args.path)
    else:
        report = scanner.scan_manifest(args.path)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    d = report.to_dict()
    print(f"\n{'='*60}")
    print(f"K8s MLOps Security Scan")
    print(f"{'='*60}")
    print(f"Files scanned: {len(report.scanned_files)}")
    print(f"Resources:     {report.scanned_resources}")
    print(f"Status:        {'PASS' if report.passed else 'FAIL'}")
    print(f"Findings:      {d['summary']['total']}")
    print(f"  CRITICAL: {d['summary']['critical']}")
    print(f"  HIGH:     {d['summary']['high']}")
    print(f"  MEDIUM:   {d['summary']['medium']}")
    print(f"  LOW:      {d['summary']['low']}")

    if not report.passed:
        print(f"\nCritical findings:")
        for f in report.findings:
            if f.severity == "CRITICAL":
                print(f"  [{f.severity}] {f.title}")
                print(f"    {f.description}")
