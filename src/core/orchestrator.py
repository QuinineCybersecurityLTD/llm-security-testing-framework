"""
Model Orchestrator
Central component for managing model adapters with factory pattern,
connection pooling, rate limiting, and circuit breaker pattern
"""

import asyncio
from typing import Dict, Optional, List, Any
from dataclasses import dataclass
import time
from collections import defaultdict
from enum import Enum

from adapters.base import (
    BaseModelAdapter,
    ModelConfig,
    ModelType,
    ModelResponse,
    ConversationMessage,
    AdapterException
)
from adapters.openai_adapter import OpenAIAdapter
from adapters.anthropic_adapter import AnthropicAdapter
from adapters.gemini_adapter import GeminiAdapter
from adapters.ollama_adapter import OllamaAdapter
from adapters.promptintel_adapter import PromptintelAdapter
from adapters.huggingface_adapter import HuggingFaceAdapter
from adapters.local_gguf_adapter import LocalGGUFAdapter
from adapters.custom_rest_adapter import CustomRESTAdapter


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if recovered


@dataclass
class CircuitBreaker:
    """Circuit breaker for protecting against failing endpoints"""
    failure_threshold: int = 5
    timeout_seconds: int = 60
    half_open_max_requests: int = 3
    
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    last_failure_time: float = 0
    half_open_requests: int = 0
    
    def record_success(self) -> None:
        """Record successful request"""
        if self.state == CircuitState.HALF_OPEN:
            self.half_open_requests += 1
            if self.half_open_requests >= self.half_open_max_requests:
                # Recovered
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.half_open_requests = 0
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0
    
    def record_failure(self) -> None:
        """Record failed request"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
    
    def can_request(self) -> bool:
        """Check if requests are allowed"""
        if self.state == CircuitState.CLOSED:
            return True
        
        if self.state == CircuitState.OPEN:
            # Check if timeout has passed
            if time.time() - self.last_failure_time >= self.timeout_seconds:
                self.state = CircuitState.HALF_OPEN
                self.half_open_requests = 0
                return True
            return False
        
        # HALF_OPEN
        return True


class RateLimiter:
    """Token bucket rate limiter - Tracks RPM only"""
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.tokens = requests_per_minute
        self.last_update = time.time()
        self.lock = asyncio.Lock()
    
    async def acquire(self) -> bool:
        """Try to acquire a token, return True if successful"""
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Refill tokens based on elapsed time
            self.tokens = min(
                self.requests_per_minute,
                self.tokens + (elapsed * self.requests_per_minute / 60.0)
            )
            self.last_update = now
            
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            
            return False
    
    async def wait_for_token(self) -> None:
        """Wait until a token is available"""
        while not await self.acquire():
            await asyncio.sleep(0.1)


class TPMRateLimiter:
    """Token bucket rate limiter for both RPM and TPM (tokens per minute)"""
    
    def __init__(self, requests_per_minute: int = 60, tokens_per_minute: int = 100000):
        # RPM tracking
        self.requests_per_minute = requests_per_minute
        self.rpm_tokens = requests_per_minute
        
        # TPM tracking
        self.tokens_per_minute = tokens_per_minute
        self.tpm_tokens = tokens_per_minute
        
        self.last_update = time.time()
        self.lock = asyncio.Lock()
    
    async def acquire(self, estimated_tokens: int = 100) -> bool:
        """Try to acquire tokens for both RPM and TPM, return True if successful"""
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Refill RPM tokens based on elapsed time
            self.rpm_tokens = min(
                self.requests_per_minute,
                self.rpm_tokens + (elapsed * self.requests_per_minute / 60.0)
            )
            
            # Refill TPM tokens based on elapsed time
            self.tpm_tokens = min(
                self.tokens_per_minute,
                self.tpm_tokens + (elapsed * self.tokens_per_minute / 60.0)
            )
            
            self.last_update = now
            
            # Check both RPM and TPM limits
            if self.rpm_tokens >= 1.0 and self.tpm_tokens >= estimated_tokens:
                self.rpm_tokens -= 1.0
                self.tpm_tokens -= estimated_tokens
                return True
            
            return False
    
    async def wait_for_token(self, estimated_tokens: int = 100) -> None:
        """Wait until tokens are available for both RPM and TPM"""
        while not await self.acquire(estimated_tokens):
            await asyncio.sleep(0.1)
    
    async def record_actual_usage(self, estimated_tokens: int, actual_tokens: int) -> None:
        """
        Adjust for actual token usage after response received
        If actual < estimated, refund the difference
        If actual > estimated, deduct the difference (this shouldn't happen with conservative estimates)
        """
        async with self.lock:
            diff = estimated_tokens - actual_tokens
            if diff > 0:  # Refund unused tokens
                self.tpm_tokens = min(
                    self.tokens_per_minute,
                    self.tpm_tokens + diff
                )
            elif diff < 0:  # Rare case: exceeded estimate, deduct the difference
                self.tpm_tokens -= abs(diff)


class AdapterPool:
    """Connection pool for model adapters"""
    
    def __init__(self, max_size: int = 10):
        self.max_size = max_size
        self.adapters: List[BaseModelAdapter] = []
        self.available: asyncio.Queue = asyncio.Queue()
        self.lock = asyncio.Lock()
    
    async def acquire(self, config: ModelConfig) -> BaseModelAdapter:
        """Get an adapter from the pool or create new one"""
        try:
            # Try to get from pool (non-blocking)
            adapter = self.available.get_nowait()
            return adapter
        except asyncio.QueueEmpty:
            async with self.lock:
                if len(self.adapters) < self.max_size:
                    # Create new adapter
                    adapter = AdapterFactory.create_adapter(config)
                    await adapter.initialize()
                    self.adapters.append(adapter)
                    return adapter
                else:
                    # Pool is full, wait for one to become available
                    adapter = await self.available.get()
                    return adapter
    
    async def release(self, adapter: BaseModelAdapter) -> None:
        """Return adapter to pool"""
        await self.available.put(adapter)
    
    async def close_all(self) -> None:
        """Close all adapters in pool"""
        for adapter in self.adapters:
            await adapter.close()


class AdapterFactory:
    """Factory for creating model adapters"""
    
    _adapter_registry: Dict[ModelType, type] = {
        ModelType.OPENAI_API: OpenAIAdapter,
        ModelType.ANTHROPIC_API: AnthropicAdapter,
        ModelType.GEMINI_API: GeminiAdapter,
        ModelType.AZURE_OPENAI: OpenAIAdapter,  # Uses same adapter
        ModelType.OLLAMA: OllamaAdapter,
        ModelType.LOCAL_GGUF: LocalGGUFAdapter,
        ModelType.PROMPTINTEL_API: PromptintelAdapter,
        ModelType.HUGGINGFACE_API: HuggingFaceAdapter,
        ModelType.CUSTOM_REST: CustomRESTAdapter,
    }
    
    @classmethod
    def create_adapter(cls, config: ModelConfig) -> BaseModelAdapter:
        """Create an adapter instance based on model type"""
        adapter_class = cls._adapter_registry.get(config.model_type)
        
        if not adapter_class:
            raise ValueError(f"Unsupported model type: {config.model_type}")
        
        return adapter_class(config)
    
    @classmethod
    def register_adapter(cls, model_type: ModelType, adapter_class: type) -> None:
        """Register a custom adapter"""
        cls._adapter_registry[model_type] = adapter_class


class ModelOrchestrator:
    """
    Central orchestrator for managing LLM interactions
    Provides connection pooling, rate limiting, and circuit breaker
    """
    
    def __init__(
        self,
        pool_size: int = 10,
        rate_limit_rpm: int = 60,
        tokens_per_minute: int = 100000,
        enable_circuit_breaker: bool = True
    ):
        self.pools: Dict[str, AdapterPool] = {}
        self.rate_limiters: Dict[str, TPMRateLimiter] = {}
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.configs: Dict[str, ModelConfig] = {}
        
        self.pool_size = pool_size
        self.rate_limit_rpm = rate_limit_rpm
        self.tokens_per_minute = tokens_per_minute
        self.enable_circuit_breaker = enable_circuit_breaker
        
        # Metrics
        self.request_count: Dict[str, int] = defaultdict(int)
        self.error_count: Dict[str, int] = defaultdict(int)
        self.total_latency: Dict[str, float] = defaultdict(float)
        self.total_tokens: Dict[str, int] = defaultdict(int)  # Track total tokens used
    
    def register_model(self, model_id: str, config: ModelConfig) -> None:
        """Register a model configuration"""
        self.configs[model_id] = config
        self.pools[model_id] = AdapterPool(max_size=self.pool_size)
        self.rate_limiters[model_id] = TPMRateLimiter(
            requests_per_minute=self.rate_limit_rpm,
            tokens_per_minute=self.tokens_per_minute
        )
        
        if self.enable_circuit_breaker:
            self.circuit_breakers[model_id] = CircuitBreaker()
    
    async def generate(
        self,
        model_id: str,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> ModelResponse:
        """
        Generate response from specified model.
        Handles rate limiting (RPM + TPM), circuit breaker, connection pooling,
        and automatic retry with exponential backoff.
        """
        
        if model_id not in self.configs:
            raise ValueError(f"Model '{model_id}' not registered")
        
        # Check circuit breaker
        if self.enable_circuit_breaker:
            circuit = self.circuit_breakers[model_id]
            if not circuit.can_request():
                raise AdapterException(f"Circuit breaker OPEN for model '{model_id}'")
        
        # Estimate tokens for rate limiting (conservative estimate: ~4 chars = 1 token)
        prompt_tokens = len(prompt) // 4
        system_tokens = (len(system_prompt) // 4) if system_prompt else 0
        history_tokens = sum(len(msg.content) // 4 for msg in (conversation_history or []))
        max_tokens = kwargs.get('max_tokens', 1000)
        estimated_total_tokens = prompt_tokens + system_tokens + history_tokens + max_tokens
        
        # Retry with exponential backoff
        max_retries = self.configs[model_id].max_retries
        last_exception = None
        
        for attempt in range(max_retries + 1):
            # Apply rate limiting (waits for both RPM and TPM availability)
            await self.rate_limiters[model_id].wait_for_token(estimated_tokens=estimated_total_tokens)
            
            # Get adapter from pool
            config = self.configs[model_id]
            adapter = await self.pools[model_id].acquire(config)
            
            try:
                start_time = time.time()
                response = await adapter.generate(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    conversation_history=conversation_history,
                    **kwargs
                )
                
                # Record actual token usage and refund overestimation
                actual_tokens = response.tokens_used
                await self.rate_limiters[model_id].record_actual_usage(
                    estimated_tokens=estimated_total_tokens,
                    actual_tokens=actual_tokens
                )
                
                # Update metrics
                self.request_count[model_id] += 1
                self.total_latency[model_id] += response.latency_ms
                self.total_tokens[model_id] += actual_tokens
                
                # Record success in circuit breaker
                if self.enable_circuit_breaker:
                    self.circuit_breakers[model_id].record_success()
                
                return response
                
            except Exception as e:
                last_exception = e
                self.error_count[model_id] += 1
                
                # Refund all tokens on failure
                await self.rate_limiters[model_id].record_actual_usage(
                    estimated_tokens=estimated_total_tokens,
                    actual_tokens=0
                )
                
                # Record failure in circuit breaker
                if self.enable_circuit_breaker:
                    self.circuit_breakers[model_id].record_failure()
                
                # Retry with exponential backoff (unless last attempt)
                if attempt < max_retries:
                    backoff = min(2 ** attempt * 0.5, 30.0)  # 0.5s, 1s, 2s, 4s ... max 30s
                    await asyncio.sleep(backoff)
                
            finally:
                # Return adapter to pool
                await self.pools[model_id].release(adapter)
        
        # All retries exhausted
        raise last_exception
    
    async def generate_batch(
        self,
        model_id: str,
        prompts: List[str],
        system_prompt: Optional[str] = None,
        max_concurrent: int = 5,
        **kwargs
    ) -> List[ModelResponse]:
        """
        Generate responses for multiple prompts concurrently
        """
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def _generate_with_semaphore(prompt: str) -> ModelResponse:
            async with semaphore:
                return await self.generate(
                    model_id=model_id,
                    prompt=prompt,
                    system_prompt=system_prompt,
                    **kwargs
                )
        
        tasks = [_generate_with_semaphore(prompt) for prompt in prompts]
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_metrics(self, model_id: str) -> Dict[str, Any]:
        """Get performance metrics for a model"""
        total_requests = self.request_count[model_id]
        
        return {
            "model_id": model_id,
            "total_requests": total_requests,
            "errors": self.error_count[model_id],
            "error_rate": self.error_count[model_id] / total_requests if total_requests > 0 else 0,
            "avg_latency_ms": self.total_latency[model_id] / total_requests if total_requests > 0 else 0,
            "circuit_breaker_state": self.circuit_breakers[model_id].state.value if self.enable_circuit_breaker else None
        }
    
    async def health_check_all(self) -> Dict[str, bool]:
        """Check health of all registered models"""
        results = {}
        
        for model_id, config in self.configs.items():
            try:
                adapter = await self.pools[model_id].acquire(config)
                is_healthy = await adapter.health_check()
                await self.pools[model_id].release(adapter)
                results[model_id] = is_healthy
            except Exception:
                results[model_id] = False
        
        return results
    
    async def close_all(self) -> None:
        """Close all adapter pools"""
        for pool in self.pools.values():
            await pool.close_all()