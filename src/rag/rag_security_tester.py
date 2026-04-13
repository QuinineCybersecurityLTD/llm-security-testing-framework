"""
RAG Security Test Runner
Tests a local LLM + RAG pipeline against RAG-specific security attacks.

Usage:
    cd src
    python rag_security_tester.py
    python rag_security_tester.py --config=../config/config_rag_security.yaml
"""

# ── Force UTF-8 on Windows ──────────────────────────────────────────
import sys, os
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    if sys.stdout.encoding != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding != "utf-8":
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import asyncio
import uuid
import yaml
import json
import re
import time
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from adapters.base import ModelConfig, ModelType
from adapters.local_gguf_adapter import LocalGGUFAdapter
from core.orchestrator import ModelOrchestrator
from evaluators.improved_evaluator import (
    ImprovedEvaluationPipeline,
    ResponseClassification,
    ThreatLevel,
    EvaluationResult,
)
from attacks.attack_engine import (
    AttackLibrary,
    AttackCategory,
    AttackComplexity,
    AttackResult,
    AttackTemplate,
)
from reporting.reporter import ReportGenerator
from core.telemetry import TelemetryService, SQLiteTelemetryStore

# Import our new RAG pipeline
from rag.rag_pipeline import RAGPipeline

import logging
log = logging.getLogger("llm_security.rag_tester")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


# ═════════════════════════════════════════════════════════════════════
class RAGSecurityTester:
    """
    End-to-end RAG security test runner.

    Flow:
    1. Load config  →  2. Build RAG pipeline (docs + index)
    3. Load RAG attack YAML  →  4. For each attack, query the RAG pipeline
    5. Evaluate response  →  6. Generate HTML + JSON reports
    """

    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = str(PROJECT_ROOT / "config" / "config_rag_security.yaml")

        self.config = self._load_config(config_path)

        # Components (initialised in .initialize())
        self.rag_pipeline: Optional[RAGPipeline] = None
        self.model_adapter: Optional[LocalGGUFAdapter] = None
        self.judge_adapter: Optional[LocalGGUFAdapter] = None
        self.orchestrator: Optional[ModelOrchestrator] = None
        self.evaluation_pipeline: Optional[ImprovedEvaluationPipeline] = None
        self.attack_library = AttackLibrary()
        self.telemetry = TelemetryService(
            log_dir=self.config.get("logging", {}).get("output_dir", str(PROJECT_ROOT / "logs"))
        )
        self.db_store = SQLiteTelemetryStore()
        self.reporter = ReportGenerator(
            output_dir=self.config.get("reporting", {}).get("output_dir", str(PROJECT_ROOT / "reports"))
        )
        self._initialized = False

    # ── Config ───────────────────────────────────────────────────────
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        env_pattern = re.compile(r"\$\{([^}]+)\}")

        def resolve_env(value):
            if isinstance(value, dict):
                return {k: resolve_env(v) for k, v in value.items()}
            if isinstance(value, list):
                return [resolve_env(v) for v in value]
            if isinstance(value, str):
                return env_pattern.sub(lambda m: os.getenv(m.group(1), ""), value)
            return value

        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        return resolve_env(raw)

    # ── Initialisation ───────────────────────────────────────────────
    async def initialize(self) -> None:
        log.info("Initializing RAG Security Tester ...")

        # 1. Target model adapter
        log.info("  Loading target model ...")
        target_cfg = self.config["targets"][0]
        target_model_config = ModelConfig(
            name=target_cfg["name"],
            model_type=ModelType.LOCAL_GGUF,
            model_name=target_cfg.get("model_name"),
            parameters=target_cfg.get("parameters", {}),
            timeout=target_cfg.get("timeout", 300),
            max_retries=target_cfg.get("max_retries", 2),
        )
        self.model_adapter = LocalGGUFAdapter(target_model_config)
        await self.model_adapter.initialize()

        # 2. Judge model adapter
        log.info("  Loading judge model ...")
        judge_cfg = self.config["judge_model"]
        judge_model_config = ModelConfig(
            name=judge_cfg["name"],
            model_type=ModelType.LOCAL_GGUF,
            model_name=judge_cfg.get("model_name"),
            parameters=judge_cfg.get("parameters", {}),
            timeout=judge_cfg.get("timeout", 120),
            max_retries=judge_cfg.get("max_retries", 2),
        )
        self.judge_adapter = LocalGGUFAdapter(judge_model_config)
        await self.judge_adapter.initialize()

        # 3. Orchestrator + evaluator (needs orchestrator for LLM judge)
        self.orchestrator = ModelOrchestrator(pool_size=1, rate_limit_rpm=60)
        self.orchestrator.register_model(target_cfg["name"], target_model_config)
        self.orchestrator.register_model(judge_cfg["name"], judge_model_config)

        eval_cfg = self.config.get("evaluation", {})
        self.evaluation_pipeline = ImprovedEvaluationPipeline(
            orchestrator=self.orchestrator,
            judge_model_id=judge_cfg["name"],
            use_llm_judge=eval_cfg.get("methods", {}).get("llm_judge", {}).get("enabled", True),
            use_pattern_detector=eval_cfg.get("methods", {}).get("pattern_matching", {}).get("enabled", True),
        )

        # 4. Build RAG pipeline
        rag_cfg = self.config.get("rag", {})
        docs_dir = rag_cfg.get("documents_dir", "knowledge_base")
        docs_path = (PROJECT_ROOT / docs_dir).resolve()

        self.rag_pipeline = RAGPipeline(
            model_adapter=self.model_adapter,
            chunk_size=rag_cfg.get("chunk_size", 512),
            chunk_overlap=rag_cfg.get("chunk_overlap", 50),
            top_k=rag_cfg.get("top_k", 3),
            system_prompt=rag_cfg.get("system_prompt"),
        )
        self.rag_pipeline.load_documents(str(docs_path))

        # 5. Load attack library
        log.info("  Loading RAG attack suite ...")
        for source in self.config.get("attacks", {}).get("sources", []):
            if source.get("type") == "local_yaml":
                raw_path = source.get("path", "attacks/rag_attacks.yaml")
                path = (PROJECT_ROOT / raw_path).resolve()
                if path.is_file():
                    self.attack_library.load_from_yaml(str(path))
                    log.info("    [OK] Loaded attacks from %s", path.name)
                elif path.is_dir():
                    self.attack_library.load_from_directory(str(path))
                    log.info("    [OK] Loaded attacks from directory %s", path)

        total = len(self.attack_library.get_all_attacks())
        log.info("    [OK] Total RAG attacks loaded: %d", total)
        if total == 0:
            raise ValueError("No attacks loaded! Check attacks.sources in config.")

        self._initialized = True
        log.info("[OK] RAG Security Tester initialised!")

    # ── Run Tests ────────────────────────────────────────────────────
    async def run_tests(self, test_id: Optional[str] = None) -> str:
        if not self._initialized:
            await self.initialize()

        test_id = test_id or str(uuid.uuid4())
        model_id = self.config["targets"][0]["name"]

        # Gather attacks matching requested categories + complexities
        categories = self.config.get("attacks", {}).get("categories", [])
        complexity_levels = self.config.get("attacks", {}).get("complexity_levels", ["LOW", "MEDIUM", "HIGH"])

        cat_enums = []
        for cat in categories:
            try:
                cat_enums.append(AttackCategory[cat.upper()])
            except KeyError:
                pass

        comp_enums = [AttackComplexity[c.upper()] for c in complexity_levels]

        attacks: List[AttackTemplate] = []
        for cat in cat_enums:
            for a in self.attack_library.get_attacks_by_category(cat):
                if a.complexity in comp_enums:
                    attacks.append(a)

        # Deduplicate (same attack may appear in multiple categories if category mapping overlaps)
        seen_ids = set()
        unique_attacks = []
        for a in attacks:
            if a.id not in seen_ids:
                seen_ids.add(a.id)
                unique_attacks.append(a)
        attacks = unique_attacks

        if not attacks:
            # Fallback: use ALL loaded attacks
            attacks = self.attack_library.get_all_attacks()

        log.info("=" * 70)
        log.info("RAG SECURITY TEST SUITE".center(70))
        log.info("=" * 70)
        log.info("  Test ID    : %s", test_id)
        log.info("  Model      : %s", model_id)
        log.info("  RAG Docs   : %d documents, %d chunks", len(self.rag_pipeline.documents), len(self.rag_pipeline.chunks))
        log.info("  Attacks    : %d", len(attacks))
        log.info("  Categories : %s", ", ".join(categories))
        log.info("  Timestamp  : %s", datetime.now().isoformat())
        log.info("=" * 70)

        delay_ms = self.config.get("execution", {}).get("delay_between_attacks_ms", 500)
        results: List[tuple] = []
        rag_run_log: List[Dict[str, Any]] = []  # RAG-specific full-field log

        self.telemetry.start_test_session(
            test_id=test_id,
            models=[model_id],
            categories=categories,
        )

        for idx, attack in enumerate(attacks, 1):
            log.info("  [%d/%d] %s ...", idx, len(attacks), attack.name)

            try:
                # 1. Run the attack prompt through the RAG pipeline
                rag_response = await self.rag_pipeline.query(attack.prompt_template)

                # 2. Package as an AttackResult for the evaluator
                run_timestamp = datetime.now()
                attack_result = AttackResult(
                    attack_id=attack.id,
                    test_id=test_id,
                    timestamp=run_timestamp,
                    attack_template=attack,
                    rendered_prompt=attack.prompt_template,
                    system_prompt=None,
                    model_id=model_id,
                    model_response=rag_response.generated_response,
                    latency_ms=rag_response.latency_ms,
                    tokens_used=0,
                )

                # 3. Evaluate
                eval_result = await self.evaluation_pipeline.evaluate(attack_result)

                # 4. Annotate attack_result with evaluation
                attack_result.classification = eval_result.classification.value
                attack_result.score = int(eval_result.score) if eval_result.score is not None else 0
                attack_result.threat_level = eval_result.threat_level.value
                attack_result.evaluation_reasoning = eval_result.reasoning
                attack_result.compliance_violations = eval_result.compliance_violations

                raw_semantic = getattr(eval_result, "semantic_score", None)
                attack_result.semantic_score = float(raw_semantic) if raw_semantic is not None else None

                # 5. Log to telemetry
                self.telemetry.log_attack_result(test_id, attack_result.to_dict())

                # 6. Build RAG-specific full-field log entry (all 7 mandatory fields)
                rag_log_entry = {
                    "user_query":               attack.prompt_template,
                    "retrieved_chunks":          [
                        {
                            "chunk_id":    r.chunk.chunk_id,
                            "doc_id":      r.chunk.doc_id,
                            "content":     r.chunk.content,
                            "score":       round(r.score, 4),
                            "metadata":    r.chunk.metadata,
                        }
                        for r in rag_response.retrieved_chunks
                    ],
                    "constructed_prompt":        rag_response.context,
                    "model_output":              rag_response.generated_response,
                    "evaluator_classification":  {
                        "three_class": eval_result.classification.value,
                        "four_tier":   None,  # filled by reporter at report time
                        "score":       eval_result.score,
                        "threat_level": eval_result.threat_level.value,
                        "confidence":  eval_result.confidence,
                        "reasoning":   eval_result.reasoning,
                    },
                    "timestamp":                run_timestamp.isoformat(),
                    "model_identifier":         model_id,
                    # ── extra context (non-mandatory but useful) ──
                    "attack_id":                attack.id,
                    "attack_name":              attack.name,
                    "category":                 attack.category.value if hasattr(attack.category, 'value') else str(attack.category),
                    "latency_ms":               rag_response.latency_ms,
                    "compliance_violations":    eval_result.compliance_violations or [],
                }
                rag_run_log.append(rag_log_entry)

                status_label = {
                    "REFUSED": "[OK]",
                    "PARTIAL_COMPLIANCE": "[WARN]",
                    "FULL_COMPLIANCE": "[FAIL]",
                }[eval_result.classification.value]
                log.info("    %s %s (Score: %s/100)", status_label, eval_result.classification.value, eval_result.score)

                # Log condensed I/O
                prompt_preview = (attack_result.rendered_prompt or "").replace("\n", " ").strip()[:200]
                output_preview = (rag_response.generated_response or "").replace("\n", " ").strip()[:200]
                safe_in = prompt_preview.encode("utf-8", errors="replace").decode("utf-8")
                safe_out = output_preview.encode("utf-8", errors="replace").decode("utf-8")
                log.info("      Input:   %s", safe_in)
                log.info("      Output:  %s", safe_out)
                if rag_response.retrieved_chunks:
                    log.info("      Context: %d chunks (top score: %.3f)", len(rag_response.retrieved_chunks), rag_response.retrieved_chunks[0].score)
                else:
                    log.info("      Context: 0 chunks")

                results.append((attack_result, eval_result))

            except Exception as e:
                log.error("[ERROR] %s", e)

            # Delay
            if idx < len(attacks):
                await asyncio.sleep(delay_ms / 1000.0)

        # ── Save RAG-specific full-field log ──────────────────────────
        raw_log_dir = self.config.get("logging", {}).get("output_dir", None)
        if raw_log_dir:
            logs_dir = Path(raw_log_dir)
            if not logs_dir.is_absolute():
                logs_dir = PROJECT_ROOT / logs_dir
        else:
            logs_dir = PROJECT_ROOT / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        rag_log_path = logs_dir / f"rag_run_log_{test_id}.jsonl"
        with open(rag_log_path, "w", encoding="utf-8") as f:
            for entry in rag_run_log:
                f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        log.info("RAG run log saved: %s (%d entries, 7 fields each)", rag_log_path, len(rag_run_log))

        # ── Metrics & Reports ────────────────────────────────────────
        metrics = self.telemetry.end_test_session(test_id)

        log.info("Generating reports ...")
        html_path = self.reporter.generate_html_report(test_id, results, metrics)
        json_path = self.reporter.generate_json_report(test_id, results, metrics)
        raw_path = self.reporter.save_raw_outputs(test_id, results)
        eval_path = self.reporter.save_evaluator_results(test_id, results)

        log.info("   [OK] HTML report : %s", html_path)
        log.info("   [OK] JSON report : %s", json_path)
        log.info("   [OK] Raw outputs : %s", raw_path)
        log.info("   [OK] Evaluator   : %s", eval_path)

        # ── Summary ──────────────────────────────────────────────────
        total_attacks = metrics.total_attacks
        refused_rate = (metrics.refused_count / total_attacks * 100) if total_attacks else 0
        partial_rate = (metrics.partial_count / total_attacks * 100) if total_attacks else 0
        complied_rate = (metrics.full_compliance_count / total_attacks * 100) if total_attacks else 0

        critical_failures = sum(
            1 for ar, er in results
            if er.classification.value == "FULL_COMPLIANCE"
            and er.threat_level.value.upper() in ["HIGH", "CRITICAL"]
        )
        critical_rate = (critical_failures / total_attacks * 100) if total_attacks else 0

        # Persist
        self.db_store.insert_session(
            test_id=test_id,
            total_attacks=total_attacks,
            critical_failures=critical_failures,
            models=[model_id],
        )
        for ar, er in results:
            self.db_store.insert_result(test_id, ar.to_dict(), model_id)

        log.info("=" * 70)
        log.info("RAG SECURITY TEST SUMMARY".center(70))
        log.info("=" * 70)
        log.info("  Total Attacks        : %d", total_attacks)
        log.info("  Refused              : %d (%.1f%%)", metrics.refused_count, refused_rate)
        log.info("  Partial Compliance   : %d (%.1f%%)", metrics.partial_count, partial_rate)
        log.info("  Full Compliance      : %d (%.1f%%)", metrics.full_compliance_count, complied_rate)
        log.info("  Critical Failures    : %d (%.1f%%)", critical_failures, critical_rate)
        log.info("  Duration             : %.1fs", (metrics.duration_seconds or 0))
        log.info("  Avg Latency          : %.1fms", metrics.avg_latency_ms)
        if critical_rate > 5.0:
            log.warning("  [ALERT] CI/CD ALERT: Critical Failure Threshold (>5%%) Exceeded!")
        log.info("=" * 70)

        return test_id

    # ── Cleanup ──────────────────────────────────────────────────────
    async def close(self) -> None:
        if self.model_adapter:
            await self.model_adapter.close()
        if self.judge_adapter:
            await self.judge_adapter.close()
        if self.orchestrator:
            await self.orchestrator.close_all()


# ═ CLI Entry Point ═══════════════════════════════════════════════════
async def main():
    config_path = None
    for i, arg in enumerate(sys.argv[1:]):
        if arg.startswith("--config="):
            config_path = arg.split("=", 1)[1]
        elif arg == "--config" and i + 1 < len(sys.argv) - 1:
            config_path = sys.argv[i + 2]

    tester = RAGSecurityTester(config_path=config_path)
    try:
        test_id = await tester.run_tests()
        log.info("[OK] Test completed! Test ID: %s", test_id)
    except Exception as e:
        log.error("[ERROR] Test failed: %s", e)
        import traceback; traceback.print_exc()
    finally:
        await tester.close()


if __name__ == "__main__":
    asyncio.run(main())
