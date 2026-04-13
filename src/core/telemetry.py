"""
Telemetry and Monitoring System
Collects system metrics, attack execution data, and provides observability
"""

import psutil
import time
import json
import logging
import socket
import threading
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import sqlite3
import json
from urllib.request import Request, urlopen
from urllib.error import URLError

# --- NUMPY SAFE JSON SUPPORT ---
import decimal

try:
    import numpy as np
except Exception:
    np = None


class NumpyJSONEncoder(json.JSONEncoder):
    """JSON encoder that safely converts numpy + other non-native types"""

    def default(self, obj):
        # numpy scalars (float32, int64, etc.)
        if np is not None and isinstance(obj, np.generic):
            return obj.item()

        # numpy arrays
        if np is not None and isinstance(obj, np.ndarray):
            return obj.tolist()

        # decimals
        if isinstance(obj, decimal.Decimal):
            return float(obj)

        # datetime
        if isinstance(obj, datetime):
            return obj.isoformat()

        return super().default(obj)


def dumps_safe(obj, **kwargs):
    return json.dumps(obj, ensure_ascii=False, cls=NumpyJSONEncoder, **kwargs)


@dataclass
class SystemMetrics:
    """System resource metrics"""
    timestamp: str
    cpu_usage_percent: float
    memory_usage_mb: float
    memory_percent: float
    disk_usage_percent: float
    
    # GPU metrics (if available)
    gpu_usage_percent: Optional[float] = None
    gpu_memory_mb: Optional[float] = None
    gpu_model: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TestExecutionMetrics:
    """Metrics for a test execution session"""
    test_id: str
    start_time: str
    end_time: Optional[str]
    duration_seconds: Optional[float]
    
    total_attacks: int
    completed_attacks: int
    failed_attacks: int
    
    refused_count: int
    partial_count: int
    full_compliance_count: int
    
    total_tokens_used: int
    total_latency_ms: int
    avg_latency_ms: float
    
    models_tested: list[str]
    categories_tested: list[str]


class GPUMonitor:
    """Monitor GPU metrics using pynvml"""
    
    def __init__(self):
        self.available = False
        self.handles = []
        
        try:
            import pynvml
            pynvml.nvmlInit()
            device_count = pynvml.nvmlDeviceGetCount()
            self.handles = [pynvml.nvmlDeviceGetHandleByIndex(i) for i in range(device_count)]
            self.available = True
            self.pynvml = pynvml
        except Exception:
            self.available = False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get GPU metrics"""
        if not self.available or not self.handles:
            return {
                "gpu_usage_percent": None,
                "gpu_memory_mb": None,
                "gpu_model": None
            }
        
        # Get metrics from first GPU
        handle = self.handles[0]
        
        try:
            util = self.pynvml.nvmlDeviceGetUtilizationRates(handle)
            memory = self.pynvml.nvmlDeviceGetMemoryInfo(handle)
            name = self.pynvml.nvmlDeviceGetName(handle)
            
            return {
                "gpu_usage_percent": util.gpu,
                "gpu_memory_mb": memory.used / (1024 * 1024),
                "gpu_model": name.decode('utf-8') if isinstance(name, bytes) else name
            }
        except Exception:
            return {
                "gpu_usage_percent": None,
                "gpu_memory_mb": None,
                "gpu_model": None
            }


class TelemetryService:
    """
    Central telemetry service for collecting and storing metrics.
    
    Performance note: system metrics are sampled every `sample_interval` attacks
    to avoid the 100ms+ overhead of psutil.cpu_percent() on every single call.
    """
    
    SAMPLE_INTERVAL = 10  # Capture system metrics every N attacks
    
    def __init__(self, log_dir: str = "/tmp/llm_security_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.gpu_monitor = GPUMonitor()
        self.test_sessions: Dict[str, TestExecutionMetrics] = {}
        
        # Metrics storage
        self.metrics_file = self.log_dir / "metrics.jsonl"
        self.results_file = self.log_dir / "results.jsonl"
        
        # Cached system metrics for sampled intervals
        self._cached_system_metrics: Optional[SystemMetrics] = None
        self._attack_counter: int = 0
    
    def capture_system_metrics(self) -> SystemMetrics:
        """Capture current system metrics"""
        
        # CPU and Memory
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # GPU metrics
        gpu_metrics = self.gpu_monitor.get_metrics()
        
        return SystemMetrics(
            timestamp=datetime.now().isoformat(),
            cpu_usage_percent=cpu_percent,
            memory_usage_mb=memory.used / (1024 * 1024),
            memory_percent=memory.percent,
            disk_usage_percent=disk.percent,
            **gpu_metrics
        )
    
    def log_system_metrics(self) -> None:
        """Log system metrics to file"""
        metrics = self.capture_system_metrics()
        
        with open(self.metrics_file, 'a', encoding='utf-8') as f:
            f.write(dumps_safe(metrics.to_dict()) + '\n')
    
    def start_test_session(
        self,
        test_id: str,
        models: list[str],
        categories: list[str]
    ) -> None:
        """Start tracking a test session"""
        
        self.test_sessions[test_id] = TestExecutionMetrics(
            test_id=test_id,
            start_time=datetime.now().isoformat(),
            end_time=None,
            duration_seconds=None,
            total_attacks=0,
            completed_attacks=0,
            failed_attacks=0,
            refused_count=0,
            partial_count=0,
            full_compliance_count=0,
            total_tokens_used=0,
            total_latency_ms=0,
            avg_latency_ms=0,
            models_tested=models,
            categories_tested=categories
        )
    
    def log_attack_result(self, test_id: str, result_dict: Dict[str, Any]) -> None:
        """Log an attack result with sampled system metrics."""
        
        self._attack_counter += 1
        
        # Sample system metrics every N attacks instead of every single one
        if self._attack_counter % self.SAMPLE_INTERVAL == 1 or self._cached_system_metrics is None:
            self._cached_system_metrics = self.capture_system_metrics()

        enhanced_result = {
            **result_dict,
            "system_resources": self._cached_system_metrics.to_dict()
        }
        
        # Write to results file
        with open(self.results_file, 'a', encoding='utf-8') as f:
            f.write(dumps_safe(enhanced_result) + '\n')
        
        # Update session metrics
        if test_id in self.test_sessions:
            session = self.test_sessions[test_id]
            session.total_attacks += 1      # FIX: was never incremented before
            session.completed_attacks += 1
            
            if result_dict.get('output', {}).get('tokens_used'):
                session.total_tokens_used += result_dict['output']['tokens_used']
            
            if result_dict.get('output', {}).get('latency_ms'):
                session.total_latency_ms += result_dict['output']['latency_ms']
            
            # Update classification counts
            classification = result_dict.get('evaluation', {}).get('classification')
            if classification == 'REFUSED':
                session.refused_count += 1
            elif classification == 'PARTIAL_COMPLIANCE':
                session.partial_count += 1
            elif classification == 'FULL_COMPLIANCE':
                session.full_compliance_count += 1
    
    def end_test_session(self, test_id: str) -> TestExecutionMetrics:
        """End a test session and return metrics"""
        
        if test_id not in self.test_sessions:
            raise ValueError(f"Test session {test_id} not found")
        
        session = self.test_sessions[test_id]
        end_time = datetime.now()
        start_time = datetime.fromisoformat(session.start_time)
        
        session.end_time = end_time.isoformat()
        session.duration_seconds = (end_time - start_time).total_seconds()
        
        if session.completed_attacks > 0:
            session.avg_latency_ms = session.total_latency_ms / session.completed_attacks
        
        return session
    
    def get_session_metrics(self, test_id: str) -> Optional[TestExecutionMetrics]:
        """Get metrics for a test session"""
        return self.test_sessions.get(test_id)
    
    def export_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus format"""
        
        metrics_lines = []
        
        # System metrics
        sys_metrics = self.capture_system_metrics()
        metrics_lines.append(f'# HELP llm_security_cpu_usage CPU usage percentage')
        metrics_lines.append(f'# TYPE llm_security_cpu_usage gauge')
        metrics_lines.append(f'llm_security_cpu_usage {sys_metrics.cpu_usage_percent}')
        
        metrics_lines.append(f'# HELP llm_security_memory_usage Memory usage in MB')
        metrics_lines.append(f'# TYPE llm_security_memory_usage gauge')
        metrics_lines.append(f'llm_security_memory_usage {sys_metrics.memory_usage_mb}')
        
        if sys_metrics.gpu_usage_percent is not None:
            metrics_lines.append(f'# HELP llm_security_gpu_usage GPU usage percentage')
            metrics_lines.append(f'# TYPE llm_security_gpu_usage gauge')
            metrics_lines.append(f'llm_security_gpu_usage {sys_metrics.gpu_usage_percent}')
        
        # Test session metrics
        for test_id, session in self.test_sessions.items():
            metrics_lines.append(f'# HELP llm_security_attacks_total Total attacks executed')
            metrics_lines.append(f'# TYPE llm_security_attacks_total counter')
            metrics_lines.append(f'llm_security_attacks_total{{test_id="{test_id}"}} {session.completed_attacks}')
            
            metrics_lines.append(f'# HELP llm_security_refused_total Refused attacks')
            metrics_lines.append(f'# TYPE llm_security_refused_total counter')
            metrics_lines.append(f'llm_security_refused_total{{test_id="{test_id}"}} {session.refused_count}')
            
            metrics_lines.append(f'# HELP llm_security_compliance_total Full compliance attacks')
            metrics_lines.append(f'# TYPE llm_security_compliance_total counter')
            metrics_lines.append(f'llm_security_compliance_total{{test_id="{test_id}"}} {session.full_compliance_count}')
        
        return '\n'.join(metrics_lines)
    
    def get_compliance_summary(self, test_id: str) -> Dict[str, Any]:
        """Get compliance summary for a test session"""
        
        session = self.test_sessions.get(test_id)
        if not session:
            return {}
        
        total = session.completed_attacks
        if total == 0:
            return {
                "test_id": test_id,
                "total_attacks": 0,
                "refusal_rate": 0.0,
                "compliance_rate": 0.0,
                "partial_rate": 0.0
            }
        
        return {
            "test_id": test_id,
            "total_attacks": total,
            "refusal_rate": session.refused_count / total,
            "compliance_rate": session.full_compliance_count / total,
            "partial_rate": session.partial_count / total,
            "avg_latency_ms": session.avg_latency_ms,
            "total_tokens": session.total_tokens_used
        }
class SQLiteTelemetryStore:
    """Lightweight SQLite database for longitudinal vulnerability tracking"""
    
    def __init__(self, db_path: str = "security_metrics.db"):
        self.db_path = db_path
        self._init_db()
        
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Create Test Sessions Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS test_sessions (
                    test_id TEXT PRIMARY KEY,
                    timestamp DATETIME,
                    total_attacks INTEGER,
                    critical_failures INTEGER,
                    models_tested TEXT
                )
            ''')
            # Create Attack Results Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    test_id TEXT,
                    attack_id TEXT,
                    category TEXT,
                    model_id TEXT,
                    classification TEXT,
                    threat_level TEXT,
                    semantic_score REAL,
                    FOREIGN KEY(test_id) REFERENCES test_sessions(test_id)
                )
            ''')
            # Create Delta Reports Table (for comparison_reporter.py)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS delta_reports (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    baseline_id     TEXT NOT NULL,
                    current_id      TEXT NOT NULL,
                    generated_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
                    regressions     INTEGER DEFAULT 0,
                    improvements    INTEGER DEFAULT 0,
                    unchanged       INTEGER DEFAULT 0,
                    net_new         INTEGER DEFAULT 0,
                    delta_json      TEXT,
                    FOREIGN KEY(baseline_id) REFERENCES test_sessions(test_id),
                    FOREIGN KEY(current_id)  REFERENCES test_sessions(test_id)
                )
            ''')
            conn.commit()

    def insert_session(self, test_id: str, total_attacks: int, critical_failures: int, models: List[str]):
        """Logs the overall session metrics"""
        with sqlite3.connect(self.db_path) as conn:
            conn.cursor().execute(
                "INSERT INTO test_sessions VALUES (?, ?, ?, ?, ?)",
                (test_id, datetime.now().isoformat(), total_attacks, critical_failures, dumps_safe(models))
            )
            conn.commit()

    def insert_result(self, test_id: str, result_dict: Dict[str, Any], model_id: str):
        """Logs individual attack results for granular tracking"""
        with sqlite3.connect(self.db_path) as conn:
            eval_data = result_dict.get('evaluation', {})

            semantic_score = eval_data.get('semantic_score')

            # --- NumPy / Decimal Safety ---
            if np is not None and isinstance(semantic_score, np.generic):
                semantic_score = float(semantic_score)

            if isinstance(semantic_score, decimal.Decimal):
                semantic_score = float(semantic_score)

            conn.cursor().execute(
                """INSERT INTO attack_results 
                (test_id, attack_id, category, model_id, classification, threat_level, semantic_score) 
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    test_id,
                    result_dict.get('attack_id'),
                    result_dict.get('category'),
                    model_id,
                    eval_data.get('classification'),
                    eval_data.get('threat_level'),
                    semantic_score
                )
            )
            conn.commit()
            
    def get_historical_trend(self, model_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Get the failure rate trend for a specific model over the last N test sessions."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT t.timestamp, t.total_attacks, t.critical_failures
                FROM test_sessions t
                WHERE t.models_tested LIKE ?
                ORDER BY t.timestamp DESC LIMIT ?
            ''', (f'%"{model_id}"%', limit))
            
            rows = cursor.fetchall()
            return [dict(row) for row in reversed(rows)] # Return chronological order

    def _ensure_asr_table(self, conn: sqlite3.Connection) -> None:
        """Create the ASR tracking table if it doesn't exist."""
        conn.execute('''
            CREATE TABLE IF NOT EXISTS asr_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                test_id         TEXT NOT NULL,
                model_id        TEXT NOT NULL,
                category        TEXT NOT NULL,
                timestamp       DATETIME NOT NULL,
                total_attacks   INTEGER NOT NULL,
                refused         INTEGER NOT NULL DEFAULT 0,
                partial         INTEGER NOT NULL DEFAULT 0,
                full_compliance INTEGER NOT NULL DEFAULT 0,
                asr             REAL NOT NULL,
                FOREIGN KEY(test_id) REFERENCES test_sessions(test_id)
            )
        ''')
        conn.commit()

    def record_asr(
        self,
        test_id: str,
        model_id: str,
        category: str,
        total: int,
        refused: int,
        partial: int,
        full_compliance: int,
    ) -> None:
        """
        Record Attack Success Rate for a model+category combination.

        ASR = (partial + full_compliance) / total
        This enables longitudinal tracking of model safety across test runs.

        Based on Anthropic's "Red Teaming Language Models to Reduce Harms"
        recommendation for category-level ASR tracking over time.
        """
        if total == 0:
            return
        asr = (partial + full_compliance) / total

        with sqlite3.connect(self.db_path) as conn:
            self._ensure_asr_table(conn)
            conn.execute(
                """INSERT INTO asr_history
                   (test_id, model_id, category, timestamp,
                    total_attacks, refused, partial, full_compliance, asr)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    test_id, model_id, category,
                    datetime.now().isoformat(),
                    total, refused, partial, full_compliance,
                    round(asr, 4),
                ),
            )
            conn.commit()

    def record_asr_from_results(
        self,
        test_id: str,
        model_id: str,
        results: List[Dict[str, Any]],
    ) -> None:
        """
        Compute and record per-category ASR from a list of attack result dicts.

        Each result dict should have:
          - 'category': str
          - 'evaluation': {'classification': 'REFUSED'|'PARTIAL_COMPLIANCE'|'FULL_COMPLIANCE'}
        """
        # Group by category
        by_category: Dict[str, Dict[str, int]] = {}
        for r in results:
            cat = r.get("category", "UNKNOWN")
            cls = r.get("evaluation", {}).get("classification", "")
            if cat not in by_category:
                by_category[cat] = {"total": 0, "refused": 0, "partial": 0, "full": 0}
            by_category[cat]["total"] += 1
            if cls == "REFUSED":
                by_category[cat]["refused"] += 1
            elif cls == "PARTIAL_COMPLIANCE":
                by_category[cat]["partial"] += 1
            elif cls == "FULL_COMPLIANCE":
                by_category[cat]["full"] += 1

        for cat, counts in by_category.items():
            self.record_asr(
                test_id, model_id, cat,
                counts["total"], counts["refused"],
                counts["partial"], counts["full"],
            )

    def get_asr_trend(
        self,
        model_id: str,
        category: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Get ASR trend over time for a model, optionally filtered by category.

        Returns list of dicts sorted chronologically:
            [{"test_id", "model_id", "category", "timestamp", "asr", "total_attacks", ...}]
        """
        with sqlite3.connect(self.db_path) as conn:
            self._ensure_asr_table(conn)
            conn.row_factory = sqlite3.Row

            if category:
                rows = conn.execute(
                    """SELECT * FROM asr_history
                       WHERE model_id = ? AND category = ?
                       ORDER BY timestamp DESC LIMIT ?""",
                    (model_id, category, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM asr_history
                       WHERE model_id = ?
                       ORDER BY timestamp DESC LIMIT ?""",
                    (model_id, limit),
                ).fetchall()

            return [dict(r) for r in reversed(rows)]

    def get_asr_summary(self, test_id: str) -> Dict[str, Any]:
        """
        Get aggregated ASR summary for a specific test run.

        Returns:
            {
                "overall_asr": float,
                "per_category": {category: {"asr": float, "total": int, ...}},
                "worst_categories": [(category, asr)],
                "best_categories": [(category, asr)],
            }
        """
        with sqlite3.connect(self.db_path) as conn:
            self._ensure_asr_table(conn)
            conn.row_factory = sqlite3.Row

            rows = conn.execute(
                "SELECT * FROM asr_history WHERE test_id = ?", (test_id,)
            ).fetchall()

            if not rows:
                return {"overall_asr": 0.0, "per_category": {}, "worst_categories": [], "best_categories": []}

            per_cat: Dict[str, Dict[str, Any]] = {}
            total_attacks = 0
            total_non_refused = 0

            for r in rows:
                cat = r["category"]
                per_cat[cat] = {
                    "asr": r["asr"],
                    "total": r["total_attacks"],
                    "refused": r["refused"],
                    "partial": r["partial"],
                    "full_compliance": r["full_compliance"],
                }
                total_attacks += r["total_attacks"]
                total_non_refused += r["partial"] + r["full_compliance"]

            overall_asr = total_non_refused / total_attacks if total_attacks > 0 else 0.0

            sorted_cats = sorted(per_cat.items(), key=lambda x: x[1]["asr"], reverse=True)
            worst = [(c, d["asr"]) for c, d in sorted_cats[:5]]
            best = [(c, d["asr"]) for c, d in sorted_cats[-5:]]

            return {
                "overall_asr": round(overall_asr, 4),
                "per_category": per_cat,
                "worst_categories": worst,
                "best_categories": best,
            }

    def detect_asr_regression(
        self,
        model_id: str,
        category: str,
        current_asr: float,
        threshold: float = 0.1,
    ) -> Dict[str, Any]:
        """
        Detect if ASR has regressed (worsened) compared to historical average.

        A regression means the model is MORE vulnerable now than before.

        Args:
            model_id: The model being tested.
            category: Attack category.
            current_asr: Current test run's ASR.
            threshold: Minimum ASR increase to flag as regression.

        Returns:
            {
                "is_regression": bool,
                "current_asr": float,
                "historical_avg_asr": float,
                "delta": float,
                "data_points": int,
            }
        """
        trend = self.get_asr_trend(model_id, category, limit=10)
        if len(trend) < 2:
            return {
                "is_regression": False,
                "current_asr": current_asr,
                "historical_avg_asr": 0.0,
                "delta": 0.0,
                "data_points": len(trend),
            }

        # Exclude current run from historical average
        historical = [t["asr"] for t in trend[:-1]] if trend else []
        if not historical:
            historical_avg = 0.0
        else:
            historical_avg = sum(historical) / len(historical)

        delta = current_asr - historical_avg

        return {
            "is_regression": delta >= threshold,
            "current_asr": round(current_asr, 4),
            "historical_avg_asr": round(historical_avg, 4),
            "delta": round(delta, 4),
            "data_points": len(historical),
        }

    def run_full_regression_check(
        self,
        test_id: str,
        model_id: str,
        threshold: float = 0.1,
    ) -> "ASRRegressionReport":
        """
        Run regression detection across ALL categories for a test run.

        Returns an ASRRegressionReport with per-category results,
        overall status, and alerting payload.
        """
        summary = self.get_asr_summary(test_id)
        regressions = []
        stable = []
        improved = []

        for cat, data in summary.get("per_category", {}).items():
            result = self.detect_asr_regression(model_id, cat, data["asr"], threshold)
            entry = {
                "category": cat,
                "current_asr": data["asr"],
                "historical_avg": result["historical_avg_asr"],
                "delta": result["delta"],
                "data_points": result["data_points"],
            }
            if result["is_regression"]:
                regressions.append(entry)
            elif result["delta"] <= -threshold and result["data_points"] >= 2:
                improved.append(entry)
            else:
                stable.append(entry)

        return ASRRegressionReport(
            test_id=test_id,
            model_id=model_id,
            timestamp=datetime.now().isoformat(),
            threshold=threshold,
            overall_asr=summary.get("overall_asr", 0.0),
            regressions=regressions,
            stable=stable,
            improved=improved,
        )


@dataclass
class ASRRegressionReport:
    """Complete ASR regression report with alerting support."""
    test_id: str
    model_id: str
    timestamp: str
    threshold: float
    overall_asr: float
    regressions: List[Dict[str, Any]]
    stable: List[Dict[str, Any]]
    improved: List[Dict[str, Any]]

    @property
    def has_regressions(self) -> bool:
        return len(self.regressions) > 0

    @property
    def worst_regression(self) -> Optional[Dict[str, Any]]:
        if not self.regressions:
            return None
        return max(self.regressions, key=lambda r: r["delta"])

    @property
    def status(self) -> str:
        if not self.regressions:
            return "PASS"
        if any(r["delta"] >= 0.2 for r in self.regressions):
            return "CRITICAL"
        return "WARNING"

    def to_alert_payload(self) -> Dict[str, Any]:
        """Generate a structured alert payload for webhook/SIEM forwarding."""
        return {
            "alert_type": "asr_regression",
            "timestamp": self.timestamp,
            "status": self.status,
            "model_id": self.model_id,
            "test_id": self.test_id,
            "overall_asr": self.overall_asr,
            "regression_count": len(self.regressions),
            "worst_category": self.worst_regression["category"] if self.worst_regression else None,
            "worst_delta": self.worst_regression["delta"] if self.worst_regression else 0,
            "regressions": self.regressions,
            "improved": self.improved,
            "summary": (
                f"{'CRITICAL' if self.status == 'CRITICAL' else 'WARNING'}: "
                f"{len(self.regressions)} categories regressed for {self.model_id}. "
                f"Worst: {self.worst_regression['category']} (+{self.worst_regression['delta']:.1%})"
            ) if self.regressions else f"PASS: No regressions for {self.model_id}",
        }

    def to_markdown(self) -> str:
        """Generate a human-readable markdown regression report."""
        lines = [
            f"# ASR Regression Report",
            f"",
            f"**Model:** {self.model_id}",
            f"**Test ID:** {self.test_id}",
            f"**Time:** {self.timestamp}",
            f"**Status:** {'PASS' if not self.has_regressions else self.status}",
            f"**Overall ASR:** {self.overall_asr:.2%}",
            f"**Threshold:** {self.threshold:.0%}",
            f"",
        ]

        if self.regressions:
            lines.append(f"## Regressions ({len(self.regressions)})")
            lines.append("")
            lines.append("| Category | Current ASR | Historical Avg | Delta |")
            lines.append("|----------|------------|---------------|-------|")
            for r in sorted(self.regressions, key=lambda x: x["delta"], reverse=True):
                lines.append(
                    f"| {r['category']} | {r['current_asr']:.2%} | "
                    f"{r['historical_avg']:.2%} | +{r['delta']:.2%} |"
                )
            lines.append("")

        if self.improved:
            lines.append(f"## Improvements ({len(self.improved)})")
            lines.append("")
            lines.append("| Category | Current ASR | Historical Avg | Delta |")
            lines.append("|----------|------------|---------------|-------|")
            for r in sorted(self.improved, key=lambda x: x["delta"]):
                lines.append(
                    f"| {r['category']} | {r['current_asr']:.2%} | "
                    f"{r['historical_avg']:.2%} | {r['delta']:.2%} |"
                )
            lines.append("")

        lines.append(f"## Stable ({len(self.stable)} categories)")
        lines.append("")

        return "\n".join(lines)

    def save(self, output_dir: str) -> str:
        """Save regression report to file."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = out / f"asr_regression_{self.model_id}_{ts}.md"
        report_path.write_text(self.to_markdown(), encoding="utf-8")
        json_path = out / f"asr_regression_{self.model_id}_{ts}.json"
        json_path.write_text(
            json.dumps(self.to_alert_payload(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return str(report_path)


# ---------------------------------------------------------------------------
# SIEM Forwarding
# TAG Enterprise AI Security Handbook 2026 — AI SecOps
# Supports: Webhook (HTTP POST), Syslog (RFC 5424), and pluggable callbacks
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

_SYSLOG_SEVERITY = {
    "CRITICAL": 2,   # Critical
    "HIGH": 3,       # Error
    "MEDIUM": 4,     # Warning
    "LOW": 6,        # Informational
    "INFO": 6,       # Informational
}


@dataclass
class SIEMForwarderConfig:
    """Configuration for SIEM event forwarding."""
    # Webhook settings
    webhook_url: Optional[str] = None
    webhook_headers: Optional[Dict[str, str]] = None
    webhook_timeout_seconds: int = 10

    # Syslog settings
    syslog_host: Optional[str] = None
    syslog_port: int = 514
    syslog_protocol: str = "UDP"  # UDP or TCP
    syslog_facility: int = 1      # user-level (LOG_USER)

    # Behavior
    async_send: bool = True       # Send in background thread
    batch_size: int = 1           # 1 = send immediately; >1 = batch
    min_severity: str = "LOW"     # Only forward events at or above this severity


class SIEMForwarder:
    """
    Forward security telemetry events to SIEM systems.

    Integrates with TelemetryService to push attack results and alerts
    to external monitoring via webhook (Splunk HEC, Elastic, Datadog, etc.)
    or syslog (QRadar, ArcSight, etc.).

    Usage:
        forwarder = SIEMForwarder(SIEMForwarderConfig(
            webhook_url="https://splunk-hec.corp.com:8088/services/collector",
            webhook_headers={"Authorization": "Splunk <token>"},
            syslog_host="qradar.corp.com",
        ))
        forwarder.forward_attack_result(result_dict)
    """

    SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def __init__(self, config: SIEMForwarderConfig):
        self.config = config
        self._batch: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._custom_callbacks: List[Callable[[Dict[str, Any]], None]] = []

    def register_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register a custom forwarding callback (e.g., for Kafka, PubSub)."""
        self._custom_callbacks.append(callback)

    def forward_attack_result(self, result: Dict[str, Any]) -> None:
        """
        Forward an attack result to configured SIEM destinations.

        Args:
            result: Attack result dict with keys like attack_id, category,
                    evaluation.classification, evaluation.threat_level, etc.
        """
        severity = result.get("evaluation", {}).get("threat_level", "INFO").upper()
        if not self._meets_severity_threshold(severity):
            return

        event = self._build_event(result, severity)

        if self.config.batch_size > 1:
            with self._lock:
                self._batch.append(event)
                if len(self._batch) >= self.config.batch_size:
                    batch = self._batch[:]
                    self._batch = []
                    self._send_batch(batch)
        else:
            self._send_batch([event])

    def flush(self) -> None:
        """Flush any batched events."""
        with self._lock:
            if self._batch:
                batch = self._batch[:]
                self._batch = []
                self._send_batch(batch)

    def _meets_severity_threshold(self, severity: str) -> bool:
        """Check if severity meets the minimum forwarding threshold."""
        try:
            event_idx = self.SEVERITY_ORDER.index(severity)
            min_idx = self.SEVERITY_ORDER.index(self.config.min_severity)
            return event_idx >= min_idx
        except ValueError:
            return True

    def _build_event(self, result: Dict[str, Any], severity: str) -> Dict[str, Any]:
        """Build a normalized SIEM event from an attack result."""
        evaluation = result.get("evaluation", {})
        return {
            "timestamp": datetime.now().isoformat() + "Z",
            "source": "llm-security-framework",
            "event_type": "ai_security_test",
            "severity": severity,
            "attack_id": result.get("attack_id", "unknown"),
            "attack_name": result.get("attack_name", ""),
            "category": result.get("category", ""),
            "classification": evaluation.get("classification", ""),
            "threat_level": evaluation.get("threat_level", ""),
            "confidence": evaluation.get("confidence", 0),
            "model_id": result.get("model_id", ""),
            "owasp_mapping": result.get("owasp_mapping", []),
            "mitre_mapping": result.get("mitre_mapping", []),
            "description": evaluation.get("reasoning", ""),
        }

    def _send_batch(self, events: List[Dict[str, Any]]) -> None:
        """Send a batch of events to all configured destinations."""
        if self.config.async_send:
            thread = threading.Thread(target=self._do_send, args=(events,), daemon=True)
            thread.start()
        else:
            self._do_send(events)

    def _do_send(self, events: List[Dict[str, Any]]) -> None:
        """Actually send events (runs in background thread if async)."""
        for event in events:
            if self.config.webhook_url:
                self._send_webhook(event)
            if self.config.syslog_host:
                self._send_syslog(event)
            for cb in self._custom_callbacks:
                try:
                    cb(event)
                except Exception as e:
                    logger.warning("SIEM callback failed: %s", e)

    def _send_webhook(self, event: Dict[str, Any]) -> None:
        """Send event via HTTP POST (Splunk HEC, Elastic, Datadog, etc.)."""
        try:
            payload = dumps_safe({"event": event}).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if self.config.webhook_headers:
                headers.update(self.config.webhook_headers)

            req = Request(
                self.config.webhook_url,
                data=payload,
                headers=headers,
                method="POST",
            )
            urlopen(req, timeout=self.config.webhook_timeout_seconds)
        except URLError as e:
            logger.warning("SIEM webhook send failed: %s", e)
        except Exception as e:
            logger.warning("SIEM webhook unexpected error: %s", e)

    def _send_syslog(self, event: Dict[str, Any]) -> None:
        """Send event via syslog (RFC 5424)."""
        try:
            severity_num = _SYSLOG_SEVERITY.get(event.get("severity", "INFO"), 6)
            priority = self.config.syslog_facility * 8 + severity_num

            # RFC 5424 format
            structured_data = (
                f'[ai-security attack_id="{event["attack_id"]}" '
                f'category="{event["category"]}" '
                f'classification="{event["classification"]}" '
                f'threat_level="{event["threat_level"]}"]'
            )
            msg = (
                f"<{priority}>1 {event['timestamp']} "
                f"llm-security-framework - - - "
                f"{structured_data} "
                f"{event['attack_id']}: {event['classification']} — {event.get('description', '')[:256]}"
            )

            msg_bytes = msg.encode("utf-8")

            if self.config.syslog_protocol.upper() == "TCP":
                with socket.create_connection(
                    (self.config.syslog_host, self.config.syslog_port), timeout=5
                ) as sock:
                    sock.sendall(msg_bytes + b"\n")
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.sendto(msg_bytes, (self.config.syslog_host, self.config.syslog_port))
                finally:
                    sock.close()

        except Exception as e:
            logger.warning("SIEM syslog send failed: %s", e)