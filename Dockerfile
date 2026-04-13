# ══════════════════════════════════════════════════════════════════════
# LLM Security Testing Framework — Production Dockerfile
# Multi-stage build, non-root user, health checks, minimal image
# ══════════════════════════════════════════════════════════════════════

# ── Stage 1: Builder ─────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml ./
COPY src/ ./src/
COPY adapters/ ./adapters/
COPY attacks/ ./attacks/
COPY config/ ./config/

RUN pip install --no-cache-dir --prefix=/install \
    pyyaml jinja2 psutil pandas aiohttp \
    openai anthropic google-generativeai huggingface-hub \
    numpy sentence-transformers PyPDF2 python-docx

# ── Stage 2: Runtime ─────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: non-root user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY --from=builder /build/src/ ./src/
COPY --from=builder /build/adapters/ ./adapters/
COPY --from=builder /build/attacks/ ./attacks/
COPY --from=builder /build/config/ ./config/

# Create writable directories for runtime outputs
RUN mkdir -p /app/reports /app/logs && chown -R appuser:appuser /app

USER appuser

# Health check — verifies Python can import the framework
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from src.main import LLMSecurityTestFramework; print('OK')" || exit 1

# Default entrypoint
ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--help"]

# Labels
LABEL maintainer="Security Engineering Team"
LABEL description="LLM Security Testing Framework"
LABEL version="1.1.0"
