"""
Anthropic API Adapter
Implements BaseModelAdapter for Anthropic Claude models
"""

import time
import asyncio
from typing import Optional, List, AsyncIterator
import aiohttp
from adapters.base import (
    BaseModelAdapter,
    ModelResponse,
    ConversationMessage,
    AdapterInitializationError,
    AdapterRequestError,
    AdapterTimeoutError
)


class AnthropicAdapter(BaseModelAdapter):
    """Adapter for Anthropic API"""
    
    DEFAULT_ENDPOINT = "https://api.anthropic.com/v1/messages"
    API_VERSION = "2023-06-01"
    
    async def initialize(self) -> None:
        """Initialize the HTTP client session"""
        if self.config.api_key and self.config.api_key.startswith("${") and self.config.api_key.endswith("}"):
            import os
            env_var = self.config.api_key[2:-1]
            self.config.api_key = os.environ.get(env_var)
            
        if not self.config.api_key:
            raise AdapterInitializationError("Anthropic API key is required")
        
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self._client = aiohttp.ClientSession(
            headers={
                "x-api-key": self.config.api_key,
                "anthropic-version": self.API_VERSION,
                "Content-Type": "application/json"
            },
            timeout=timeout
        )
        self._initialized = True
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> ModelResponse:
        """Generate response from Anthropic API"""
        
        if not self.is_initialized:
            await self.initialize()
        
        # Build messages array (Anthropic format)
        messages = []
        
        if conversation_history:
            messages.extend([
                {"role": msg.role, "content": msg.content}
                for msg in conversation_history
                if msg.role != "system"  # System handled separately
            ])
        
        messages.append({"role": "user", "content": prompt})
        
        # Merge parameters
        params = self._merge_parameters(kwargs)
        
        # Build request payload
        payload = {
            "model": self.config.model_name or "claude-sonnet-4-20250514",
            "messages": messages,
            "max_tokens": params.get("max_tokens", 2000),
            "temperature": params.get("temperature", 0.7),
            "top_p": params.get("top_p", 1.0),
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        # Execute request with retries
        endpoint = self.config.endpoint or self.DEFAULT_ENDPOINT
        
        for attempt in range(self.config.max_retries):
            try:
                start_time = time.time()
                
                async with self._client.post(endpoint, json=payload) as response:
                    latency_ms = int((time.time() - start_time) * 1000)
                    
                    if response.status == 429:
                        # Rate limit - exponential backoff
                        wait_time = 2 ** attempt
                        await asyncio.sleep(wait_time)
                        continue
                    
                    response_data = await response.json()
                    
                    if response.status != 200:
                        error_msg = response_data.get("error", {}).get("message", "Unknown error")
                        raise AdapterRequestError(f"Anthropic API error: {error_msg}")
                    
                    # Parse response (Anthropic format)
                    content_text = ""
                    for content_block in response_data["content"]:
                        if content_block["type"] == "text":
                            content_text += content_block["text"]
                    
                    return ModelResponse(
                        content=content_text,
                        model=response_data["model"],
                        finish_reason=response_data["stop_reason"],
                        tokens_used=response_data["usage"]["input_tokens"] + response_data["usage"]["output_tokens"],
                        latency_ms=latency_ms,
                        raw_response=response_data,
                        metadata={
                            "input_tokens": response_data["usage"]["input_tokens"],
                            "output_tokens": response_data["usage"]["output_tokens"],
                            "stop_sequence": response_data.get("stop_sequence")
                        }
                    )
                    
            except asyncio.TimeoutError:
                if attempt == self.config.max_retries - 1:
                    raise AdapterTimeoutError(f"Request timed out after {self.config.timeout}s")
                await asyncio.sleep(2 ** attempt)
            
            except aiohttp.ClientError as e:
                if attempt == self.config.max_retries - 1:
                    raise AdapterRequestError(f"HTTP client error: {str(e)}")
                await asyncio.sleep(2 ** attempt)
        
        raise AdapterRequestError("Max retries exceeded")
    
    async def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """Generate streaming response from Anthropic API"""
        
        if not self.is_initialized:
            await self.initialize()
        
        # Build messages
        messages = []
        if conversation_history:
            messages.extend([
                {"role": msg.role, "content": msg.content}
                for msg in conversation_history
                if msg.role != "system"
            ])
        
        messages.append({"role": "user", "content": prompt})
        
        params = self._merge_parameters(kwargs)
        
        payload = {
            "model": self.config.model_name or "claude-sonnet-4-20250514",
            "messages": messages,
            "max_tokens": params.get("max_tokens", 1000),
            "stream": True
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        endpoint = self.config.endpoint or self.DEFAULT_ENDPOINT
        
        async with self._client.post(endpoint, json=payload) as response:
            if response.status != 200:
                error_data = await response.json()
                error_msg = error_data.get("error", {}).get("message", "Unknown error")
                raise AdapterRequestError(f"Anthropic API error: {error_msg}")
            
            async for line in response.content:
                line = line.decode('utf-8').strip()
                if line.startswith("data: "):
                    data = line[6:]
                    
                    import json
                    try:
                        chunk = json.loads(data)
                        
                        if chunk["type"] == "content_block_delta":
                            delta = chunk.get("delta", {})
                            if delta.get("type") == "text_delta":
                                yield delta["text"]
                    except json.JSONDecodeError:
                        continue
    
    async def health_check(self) -> bool:
        """Check if Anthropic API is accessible"""
        try:
            # Simple lightweight request
            test_payload = {
                "model": self.config.model_name or "claude-sonnet-4-20250514",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 10
            }
            async with self._client.post(self.DEFAULT_ENDPOINT, json=test_payload) as response:
                return response.status == 200
        except Exception:
            return False
    
    async def close(self) -> None:
        """Close the HTTP client session"""
        if self._client:
            await self._client.close()
