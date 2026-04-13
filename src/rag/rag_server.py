"""
Quinine RAG Server — FastAPI-based RAG Service
================================================
Wraps the existing RAGPipeline as an HTTP API for:
  1. Testing client_rag_tester.py against a real RAG endpoint
  2. Serving as a company-usable RAG service

Endpoints:
  GET  /health       — Health check + pipeline status
  POST /api/chat     — Chat endpoint (Mode A — matches client_rag_tester contract)
  POST /api/retrieve — Retrieval-only endpoint (Mode B)
  GET  /api/stats    — Pipeline statistics

Usage:
    cd src && python -m rag.rag_server --config ../config/config_rag_server.yaml
    cd src && python -m rag.rag_server  # uses env vars / defaults
"""

# ── Force UTF-8 on Windows ──────────────────────────────────────────
import sys
import os

os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    if sys.stdout.encoding != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding != "utf-8":
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Ensure src/ is on the path for sibling imports
_src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

import json
import time
import asyncio
import logging
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import yaml
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

from rag.rag_pipeline import RAGPipeline, DocumentLoader, RetrievalResult

load_dotenv()

log = logging.getLogger("rag_server")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


# ═══════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════

class ServerConfig:
    """Load server configuration from YAML or environment variables."""

    def __init__(self, config_path: Optional[str] = None):
        self.port: int = 8000
        self.host: str = "0.0.0.0"
        self.api_key: str = ""
        self.knowledge_base: str = str(PROJECT_ROOT / "knowledge_base")
        self.model_type: str = "openai_api"
        self.model_name: str = ""
        self.model_endpoint: str = ""
        self.model_api_key: str = ""
        self.model_parameters: Dict[str, Any] = {}
        self.top_k: int = 5
        self.similarity_threshold: float = 0.1
        self.chunk_size: int = 512
        self.chunk_overlap: int = 50
        self.use_dense_vectors: bool = False
        self.rate_limit_rpm: int = 60
        self.system_prompt: Optional[str] = None

        if config_path:
            self._load_yaml(config_path)
        self._load_env_overrides()

    def _load_yaml(self, path: str) -> None:
        resolved = Path(path).resolve()
        if not resolved.exists():
            # Try relative to PROJECT_ROOT
            resolved = (PROJECT_ROOT / path).resolve()
        if not resolved.exists():
            # Try config/ subdirectory by name
            resolved = (PROJECT_ROOT / "config" / Path(path).name).resolve()
        if not resolved.exists():
            log.warning("Config file not found: %s — using defaults", path)
            return

        with open(resolved, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}

        # Resolve ${ENV_VAR} placeholders
        import re
        env_pattern = re.compile(r"\$\{([^}]+)\}")

        def resolve(value):
            if isinstance(value, dict):
                return {k: resolve(v) for k, v in value.items()}
            if isinstance(value, list):
                return [resolve(v) for v in value]
            if isinstance(value, str):
                return env_pattern.sub(lambda m: os.getenv(m.group(1), ""), value)
            return value

        cfg = resolve(cfg)

        server = cfg.get("server", {})
        self.port = server.get("port", self.port)
        self.host = server.get("host", self.host)
        self.api_key = server.get("api_key", self.api_key)

        rag = cfg.get("rag", {})
        self.knowledge_base = rag.get("knowledge_base", self.knowledge_base)
        self.top_k = rag.get("top_k", self.top_k)
        self.similarity_threshold = rag.get("similarity_threshold", self.similarity_threshold)
        self.chunk_size = rag.get("chunk_size", self.chunk_size)
        self.chunk_overlap = rag.get("chunk_overlap", self.chunk_overlap)
        self.use_dense_vectors = rag.get("use_dense_vectors", self.use_dense_vectors)
        self.system_prompt = rag.get("system_prompt", self.system_prompt)

        model = cfg.get("model", {})
        self.model_type = model.get("type", self.model_type)
        self.model_name = model.get("name", self.model_name)
        self.model_endpoint = model.get("endpoint", self.model_endpoint)
        self.model_api_key = model.get("api_key", self.model_api_key)
        self.model_parameters = model.get("parameters", self.model_parameters)

    def _load_env_overrides(self) -> None:
        """Environment variables override YAML config."""
        self.port = int(os.getenv("RAG_SERVER_PORT", str(self.port)))
        self.host = os.getenv("RAG_SERVER_HOST", self.host)
        self.api_key = os.getenv("RAG_API_KEY", self.api_key)
        self.knowledge_base = os.getenv("RAG_KNOWLEDGE_BASE", self.knowledge_base)
        self.model_type = os.getenv("RAG_MODEL_TYPE", self.model_type)
        self.model_name = os.getenv("RAG_MODEL_NAME", self.model_name)
        self.model_endpoint = os.getenv("RAG_MODEL_ENDPOINT", self.model_endpoint)
        self.model_api_key = os.getenv("RAG_MODEL_API_KEY", self.model_api_key)


# ═══════════════════════════════════════════════════════════════════════
# Pydantic Models (Request / Response)
# ═══════════════════════════════════════════════════════════════════════

class ChatRequest(BaseModel):
    message: str = Field(..., description="User query")
    stream: bool = Field(default=False, description="Streaming flag (not implemented)")

class ChatResponse(BaseModel):
    response: str = Field(..., description="Generated answer")
    sources: List[Dict[str, Any]] = Field(default_factory=list, description="Retrieved source chunks")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Response metadata")

class RetrieveRequest(BaseModel):
    query: str = Field(..., description="Search query")
    top_k: int = Field(default=5, ge=1, le=20, description="Number of chunks to retrieve")

class RetrieveResponse(BaseModel):
    chunks: List[Dict[str, Any]] = Field(default_factory=list, description="Retrieved chunks")
    total_chunks: int = Field(default=0, description="Total chunks in the index")

class HealthResponse(BaseModel):
    status: str
    pipeline_ready: bool
    documents_loaded: int
    chunks_indexed: int
    uptime_seconds: float

class StatsResponse(BaseModel):
    documents: int
    chunks: int
    index_type: str
    similarity_threshold: float
    top_k: int
    model_type: str
    model_name: str
    total_queries: int


# ═══════════════════════════════════════════════════════════════════════
# Global State
# ═══════════════════════════════════════════════════════════════════════

_pipeline: Optional[RAGPipeline] = None
_config: Optional[ServerConfig] = None
_start_time: float = 0.0
_query_count: int = 0


# ═══════════════════════════════════════════════════════════════════════
# Model Adapter Factory
# ═══════════════════════════════════════════════════════════════════════

def _create_model_adapter(cfg: ServerConfig):
    """Instantiate the right model adapter based on config."""
    from adapters.base import ModelConfig, ModelType

    model_type_str = cfg.model_type.upper().replace("-", "_")
    try:
        model_type = ModelType[model_type_str]
    except KeyError:
        raise ValueError(
            f"Unknown model type: {cfg.model_type}. "
            f"Valid types: {[t.name for t in ModelType]}"
        )

    model_config = ModelConfig(
        name=cfg.model_name or "rag-server-model",
        model_type=model_type,
        endpoint=cfg.model_endpoint or None,
        api_key=cfg.model_api_key or None,
        model_name=cfg.model_name or None,
        parameters=cfg.model_parameters,
        timeout=cfg.model_parameters.get("timeout", 60),
        max_retries=cfg.model_parameters.get("max_retries", 2),
    )

    # Import the right adapter
    if model_type == ModelType.OPENAI_API:
        from adapters.openai_adapter import OpenAIAdapter
        return OpenAIAdapter(model_config)
    elif model_type == ModelType.ANTHROPIC_API:
        from adapters.anthropic_adapter import AnthropicAdapter
        return AnthropicAdapter(model_config)
    elif model_type == ModelType.GEMINI_API:
        from adapters.gemini_adapter import GeminiAdapter
        return GeminiAdapter(model_config)
    elif model_type == ModelType.LOCAL_GGUF:
        from adapters.local_gguf_adapter import LocalGGUFAdapter
        return LocalGGUFAdapter(model_config)
    elif model_type == ModelType.OLLAMA:
        from adapters.ollama_adapter import OllamaAdapter
        return OllamaAdapter(model_config)
    elif model_type == ModelType.HUGGINGFACE_API:
        from adapters.huggingface_adapter import HuggingFaceAdapter
        return HuggingFaceAdapter(model_config)
    elif model_type == ModelType.CUSTOM_REST:
        from adapters.custom_rest_adapter import CustomRESTAdapter
        return CustomRESTAdapter(model_config)
    else:
        raise ValueError(f"Adapter not implemented for model type: {model_type}")


# ═══════════════════════════════════════════════════════════════════════
# Auth Dependency
# ═══════════════════════════════════════════════════════════════════════

async def verify_auth(
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
) -> None:
    """Verify API key via X-API-Key header or Bearer token."""
    if not _config or not _config.api_key:
        return  # No auth configured — allow all

    provided_key = None
    if x_api_key:
        provided_key = x_api_key
    elif authorization and authorization.startswith("Bearer "):
        provided_key = authorization[7:]

    if provided_key != _config.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ═══════════════════════════════════════════════════════════════════════
# Lifespan (startup / shutdown)
# ═══════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize RAG pipeline on startup."""
    global _pipeline, _start_time

    _start_time = time.time()
    log.info("Starting Quinine RAG Server...")

    if _config is None:
        raise RuntimeError("Server config not set. Call _init_config() before starting.")

    # Create model adapter
    adapter = None
    if _config.model_name:
        try:
            adapter = _create_model_adapter(_config)
            await adapter.initialize()
            log.info("Model adapter initialized: %s (%s)", _config.model_name, _config.model_type)
        except Exception as e:
            log.warning("Could not initialize model adapter: %s — retrieval-only mode", e)
            adapter = None

    # Create RAG pipeline
    _pipeline = RAGPipeline(
        model_adapter=adapter,
        chunk_size=_config.chunk_size,
        chunk_overlap=_config.chunk_overlap,
        top_k=_config.top_k,
        system_prompt=_config.system_prompt,
        use_dense_vectors=_config.use_dense_vectors,
        similarity_threshold=_config.similarity_threshold,
    )

    # Load documents
    kb_path = _config.knowledge_base
    if not Path(kb_path).is_absolute():
        kb_path = str(PROJECT_ROOT / kb_path)

    try:
        chunk_count = _pipeline.load_documents(kb_path)
        log.info("Loaded %d chunks from %s", chunk_count, kb_path)
    except FileNotFoundError as e:
        log.error("Knowledge base not found: %s", e)
        raise

    log.info("RAG Server ready on %s:%d", _config.host, _config.port)
    yield

    log.info("Shutting down RAG Server...")


# ═══════════════════════════════════════════════════════════════════════
# FastAPI App
# ═══════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Quinine RAG Server",
    description="RAG-as-a-Service for Quinine LLM Security Testing Framework",
    version="1.0.0",
    lifespan=lifespan,
)


def _format_sources(results: List[RetrievalResult]) -> List[Dict[str, Any]]:
    """Convert RetrievalResult list to JSON-serializable source dicts."""
    return [
        {
            "chunk_id": r.chunk.chunk_id,
            "content": r.chunk.content,
            "score": round(r.score, 4),
            "source_file": r.chunk.metadata.get("source_file", "unknown"),
        }
        for r in results
    ]


# ── GET /health ───────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    ready = _pipeline is not None and _pipeline._indexed
    return HealthResponse(
        status="healthy" if ready else "starting",
        pipeline_ready=ready,
        documents_loaded=len(_pipeline.documents) if _pipeline else 0,
        chunks_indexed=len(_pipeline.chunks) if _pipeline else 0,
        uptime_seconds=round(time.time() - _start_time, 1),
    )


# ── POST /api/chat ────────────────────────────────────────────────────

@app.post("/api/chat", response_model=ChatResponse, dependencies=[Depends(verify_auth)])
async def chat(request: ChatRequest):
    """
    Chat endpoint (Mode A) — accepts a message, returns RAG-augmented response.
    Matches the contract expected by client_rag_tester.py.
    """
    global _query_count

    if not _pipeline or not _pipeline._indexed:
        raise HTTPException(status_code=503, detail="RAG pipeline not ready")

    if not request.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    _query_count += 1

    # If no model adapter, return retrieval-only response
    if _pipeline.model_adapter is None:
        results = _pipeline.retrieve(request.message)
        context_parts = [r.chunk.content for r in results]
        return ChatResponse(
            response=" ".join(context_parts) if context_parts else "No relevant information found.",
            sources=_format_sources(results),
            metadata={
                "latency_ms": 0,
                "chunks_retrieved": len(results),
                "mode": "retrieval_only",
            },
        )

    # Full RAG query
    try:
        rag_response = await _pipeline.query(request.message)
    except Exception as e:
        log.error("RAG query failed: %s", e)
        raise HTTPException(status_code=500, detail=f"RAG query failed: {str(e)}")

    return ChatResponse(
        response=rag_response.generated_response,
        sources=_format_sources(rag_response.retrieved_chunks),
        metadata={
            "latency_ms": rag_response.latency_ms,
            "chunks_retrieved": rag_response.metadata.get("chunks_retrieved", 0),
            "top_score": rag_response.metadata.get("top_score", 0.0),
            "output_safe": rag_response.metadata.get("output_safe", True),
            "flags_triggered": rag_response.metadata.get("flags_triggered", []),
        },
    )


# ── POST /api/retrieve ────────────────────────────────────────────────

@app.post("/api/retrieve", response_model=RetrieveResponse, dependencies=[Depends(verify_auth)])
async def retrieve(request: RetrieveRequest):
    """
    Retrieval-only endpoint (Mode B) — returns matching chunks without generation.
    """
    if not _pipeline or not _pipeline._indexed:
        raise HTTPException(status_code=503, detail="RAG pipeline not ready")

    if not request.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    results = _pipeline.retrieve(request.query, top_k=request.top_k)

    return RetrieveResponse(
        chunks=_format_sources(results),
        total_chunks=len(_pipeline.chunks),
    )


# ── GET /api/stats ────────────────────────────────────────────────────

@app.get("/api/stats", response_model=StatsResponse, dependencies=[Depends(verify_auth)])
async def stats():
    """Pipeline statistics."""
    index_type = "dense" if (_pipeline and _pipeline.use_dense and _pipeline._dense_store) else "tfidf"
    return StatsResponse(
        documents=len(_pipeline.documents) if _pipeline else 0,
        chunks=len(_pipeline.chunks) if _pipeline else 0,
        index_type=index_type,
        similarity_threshold=_config.similarity_threshold if _config else 0.0,
        top_k=_config.top_k if _config else 0,
        model_type=_config.model_type if _config else "none",
        model_name=_config.model_name if _config else "none",
        total_queries=_query_count,
    )


# ── Rate limit middleware ─────────────────────────────────────────────

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Simple rate-limiting: return 429 if too many requests."""
    # For now, just pass through — the RAGPipeline's QueryGuard has its own rate limiter
    response = await call_next(request)
    return response


# ═══════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════

def _init_config(config_path: Optional[str] = None) -> ServerConfig:
    """Initialize and set global config."""
    global _config
    _config = ServerConfig(config_path=config_path)
    return _config


def main():
    parser = argparse.ArgumentParser(description="Quinine RAG Server")
    parser.add_argument("--config", type=str, default=None, help="Path to config YAML file")
    parser.add_argument("--port", type=int, default=None, help="Server port (overrides config)")
    parser.add_argument("--host", type=str, default=None, help="Server host (overrides config)")
    args = parser.parse_args()

    cfg = _init_config(args.config)
    if args.port:
        cfg.port = args.port
    if args.host:
        cfg.host = args.host

    log.info("Configuration:")
    log.info("  Host: %s", cfg.host)
    log.info("  Port: %d", cfg.port)
    log.info("  Knowledge Base: %s", cfg.knowledge_base)
    log.info("  Model: %s (%s)", cfg.model_name or "(none)", cfg.model_type)
    log.info("  Auth: %s", "enabled" if cfg.api_key else "disabled")
    log.info("  Top-K: %d, Threshold: %.2f", cfg.top_k, cfg.similarity_threshold)

    uvicorn.run(
        app,
        host=cfg.host,
        port=cfg.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
