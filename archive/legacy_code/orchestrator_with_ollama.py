"""
Model Orchestrator - Updated with Ollama Support
Central component for managing model adapters with factory pattern
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
from adapters.ollama_adapter import OllamaAdapter  # NEW!


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


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
            if time.time() - self.last_failure_time >= self.timeout_seconds:
                self.state = CircuitState.HALF_OPEN
                self.half_open_requests = 0
                return True
            return False
        
        return True


class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.tokens = requests_per_minute
        self.last_update = time.time()
        self.lock = asyncio.Lock()
    
    async def acquire(self) -> bool:
        """Try to acquire a token"""
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            
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


class AdapterPool:
    """Connection pool for model adapters"""
    
    def __init__(self, max_size: int = 10):
        self.max_size = max_size
        self.adapters: List[BaseModelAdapter] = []
        self.available: asyncio.Queue = asyncio.Queue()
        self.lock = asyncio.Lock()
    
    async def acquire(self, config: ModelConfig) -> BaseModelAdapter:
        """Get an adapter from the pool"""
        try:
            adapter = self.available.get_nowait()
            return adapter
        except asyncio.QueueEmpty:
            async with self.lock:
                if len(self.adapters) < self.max_size:
                    adapter = AdapterFactory.create_adapter(config)
                    await adapter.initialize()
                    self.adapters.append(adapter)
                    return adapter
                else:
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
        ModelType.AZURE_OPENAI: OpenAIAdapter,
        ModelType.OLLAMA: OllamaAdapter,  # NEW!
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
    """Central orchestrator for managing LLM interactions"""
    
    def __init__(
        self,
        pool_size: int = 10,
        rate_limit_rpm: int = 60,
        enable_circuit_breaker: bool = True
    ):
        self.pools: Dict[str, AdapterPool] = {}
        self.rate_limiters: Dict[str, RateLimiter] = {}
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.configs: Dict[str, ModelConfig] = {}
        
        self.pool_size = pool_size
        self.rate_limit_rpm = rate_limit_rpm
        self.enable_circuit_breaker = enable_circuit_breaker
        
        self.request_count: Dict[str, int] = defaultdict(int)
        self.error_count: Dict[str, int] = defaultdict(int)
        self.total_latency: Dict[str, float] = defaultdict(float)
    
    def register_model(self, model_id: str, config: ModelConfig) -> None:
        """Register a model configuration"""
        self.configs[model_id] = config
        self.pools[model_id] = AdapterPool(max_size=self.pool_size)
        self.rate_limiters[model_id] = RateLimiter(requests_per_minute=self.rate_limit_rpm)
        
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
        """Generate response from specified model"""
        
        if model_id not in self.configs:
            raise ValueError(f"Model '{model_id}' not registered")
        
        if self.enable_circuit_breaker:
            circuit = self.circuit_breakers[model_id]
            if not circuit.can_request():
                raise AdapterException(f"Circuit breaker OPEN for model '{model_id}'")
        
        await self.rate_limiters[model_id].wait_for_token()
        
        config = self.configs[model_id]
        adapter = await self.pools[model_id].acquire(config)
        
        try:
            response = await adapter.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                conversation_history=conversation_history,
                **kwargs
            )
            
            self.request_count[model_id] += 1
            self.total_latency[model_id] += response.latency_ms
            
            if self.enable_circuit_breaker:
                self.circuit_breakers[model_id].record_success()
            
            return response
            
        except Exception as e:
            self.error_count[model_id] += 1
            
            if self.enable_circuit_breaker:
                self.circuit_breakers[model_id].record_failure()
            
            raise
        
        finally:
            await self.pools[model_id].release(adapter)
    
    async def generate_batch(
        self,
        model_id: str,
        prompts: List[str],
        system_prompt: Optional[str] = None,
        max_concurrent: int = 5,
        **kwargs
    ) -> List[ModelResponse]:
        """Generate responses for multiple prompts"""
        
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
        """Get performance metrics"""
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
