"""
Custom REST Adapter — Universal adapter for any HTTP-based LLM/RAG endpoint.

Supports clients with non-standard API formats. Configure request/response
mapping via ModelConfig.parameters to match any endpoint structure.

Usage in config:
    targets:
      - name: "client-api"
        type: "custom_rest"
        endpoint: "https://client.example.com/api/chat"
        auth:
          token: "${CLIENT_API_KEY}"
        parameters:
          request_body_template: '{"prompt": "{input}", "max_length": 2000}'
          response_field: "output.text"
          auth_header: "Authorization"
          auth_prefix: "Bearer"
          method: "POST"
"""

import json
import time
import logging
import asyncio
import aiohttp
from typing import Dict, Any, Optional, AsyncIterator

from adapters.base import (
    BaseModelAdapter,
    ModelConfig,
    ModelResponse,
    ConversationMessage,
    AdapterRequestError,
    AdapterTimeoutError,
    AdapterRateLimitError,
)

log = logging.getLogger("llm_security.adapter.custom_rest")


class CustomRESTAdapter(BaseModelAdapter):
    """
    Universal REST adapter for arbitrary LLM/RAG API endpoints.

    Maps any HTTP endpoint to the BaseAdapter interface by configuring
    request body templates and response field extraction.
    """

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self._session: Optional[aiohttp.ClientSession] = None

        # Extract configuration from parameters
        params = config.parameters or {}
        self._method = params.get("method", "POST").upper()
        self._body_template = params.get(
            "request_body_template",
            '{"message": "{input}"}'
        )
        self._response_field = params.get("response_field", "response")
        self._auth_header = params.get("auth_header", "Authorization")
        self._auth_prefix = params.get("auth_prefix", "Bearer")
        self._content_type = params.get("content_type", "application/json")

    async def initialize(self) -> None:
        """Create HTTP session with auth headers."""
        headers = {"Content-Type": self._content_type}
        if self.config.api_key:
            if self._auth_prefix:
                headers[self._auth_header] = f"{self._auth_prefix} {self.config.api_key}"
            else:
                headers[self._auth_header] = self.config.api_key

        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self._session = aiohttp.ClientSession(headers=headers, timeout=timeout)
        log.info("CustomREST adapter initialized for %s", self.config.endpoint)

    async def generate(
        self,
        prompt: str,
        context: Optional[list] = None,
        **kwargs: Any,
    ) -> ModelResponse:
        """Send prompt to the custom REST endpoint."""
        if not self._session:
            await self.initialize()

        # Build request body from template
        escaped_prompt = prompt.replace('"', '\\"').replace("\n", "\\n")
        body_str = self._body_template.replace("{input}", escaped_prompt)
        try:
            body = json.loads(body_str)
        except json.JSONDecodeError:
            body = {"message": prompt}

        endpoint = self.config.endpoint
        last_error = None

        for attempt in range(self.config.max_retries + 1):
            start = time.time()
            try:
                async with self._session.request(
                    self._method, endpoint, json=body
                ) as resp:
                    latency_ms = int((time.time() - start) * 1000)

                    if resp.status == 429:
                        retry_after = int(resp.headers.get("Retry-After", 5))
                        log.warning("Rate limited. Retrying in %ds", retry_after)
                        await asyncio.sleep(retry_after)
                        continue

                    if resp.status >= 400:
                        error_text = await resp.text()
                        raise AdapterRequestError(
                            f"HTTP {resp.status}: {error_text[:200]}"
                        )

                    raw = await resp.json(content_type=None)

                    # Extract response text
                    content = self._extract_field(raw, self._response_field)
                    if content is None:
                        content = json.dumps(raw)
                    content = str(content)

                    return ModelResponse(
                        content=content,
                        model=self.config.name,
                        finish_reason="complete",
                        tokens_used=len(content.split()),  # Rough estimate
                        latency_ms=latency_ms,
                        raw_response=raw,
                    )

            except asyncio.TimeoutError:
                last_error = AdapterTimeoutError(
                    f"Request timed out after {self.config.timeout}s"
                )
                log.warning("Timeout on attempt %d/%d", attempt + 1, self.config.max_retries + 1)
            except aiohttp.ClientError as e:
                last_error = AdapterRequestError(str(e))
                log.warning("Request error on attempt %d: %s", attempt + 1, e)

            if attempt < self.config.max_retries:
                await asyncio.sleep(2 ** attempt)

        raise last_error or AdapterRequestError("All retries exhausted")

    async def generate_stream(
        self,
        prompt: str,
        context: Optional[list] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Streaming is not universally supported; fall back to full generate."""
        response = await self.generate(prompt, context, **kwargs)
        yield response.content

    async def health_check(self) -> bool:
        """Check if the endpoint is reachable."""
        if not self._session:
            await self.initialize()
        try:
            async with self._session.get(
                self.config.endpoint,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return resp.status < 500
        except Exception:
            return False

    def _extract_field(self, data: Any, field_path: str) -> Any:
        """Extract nested field using dot notation (e.g., 'data.output.text')."""
        if not field_path or data is None:
            return data
        parts = field_path.split(".")
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list) and part.isdigit():
                idx = int(part)
                current = current[idx] if idx < len(current) else None
            else:
                return None
        return current

    async def close(self) -> None:
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
