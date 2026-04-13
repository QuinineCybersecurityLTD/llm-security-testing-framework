"""
OpenAI API Adapter - IMPROVED VERSION
Implements BaseModelAdapter for OpenAI and Azure OpenAI services
with better rate limiting and error handling
"""

import time
import asyncio
from typing import Optional, List, AsyncIterator, Dict, Any
import aiohttp
from adapters.base import (
    BaseModelAdapter,
    ModelResponse,
    ConversationMessage,
    AdapterInitializationError,
    AdapterRequestError,
    AdapterTimeoutError,
    AdapterRateLimitError
)


class OpenAIAdapter(BaseModelAdapter):
    """Adapter for OpenAI API (and Azure OpenAI)"""
    
    # FIXED: Correct endpoint for chat completions
    DEFAULT_ENDPOINT = "https://api.openai.com/v1/chat/completions"
    
    async def initialize(self) -> None:
        """Initialize the HTTP client session"""
        if self.config.api_key and self.config.api_key.startswith("${") and self.config.api_key.endswith("}"):
            import os
            env_var = self.config.api_key[2:-1]
            self.config.api_key = os.environ.get(env_var)
            
        if not self.config.api_key:
            raise AdapterInitializationError("OpenAI API key is required")
        
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self._client = aiohttp.ClientSession(
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
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
        """Generate response from OpenAI API"""
        
        if not self.is_initialized:
            await self.initialize()
        
        # Build messages array
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        if conversation_history:
            messages.extend([
                {"role": msg.role, "content": msg.content}
                for msg in conversation_history
            ])
        
        messages.append({"role": "user", "content": prompt})
        
        # Merge parameters
        params = self._merge_parameters(kwargs)
        
        # Build request payload
        payload = {
            "model": self.config.model_name or "gpt-4",
            "messages": messages,
            "temperature": params.get("temperature", 0.7),
            "max_tokens": params.get("max_tokens", 2000),
            "top_p": params.get("top_p", 1.0),
            "frequency_penalty": params.get("frequency_penalty", 0.0),
            "presence_penalty": params.get("presence_penalty", 0.0),
        }
        
        # Execute request with retries
        endpoint = self.config.endpoint or self.DEFAULT_ENDPOINT
        last_error: Optional[Exception] = None
        
        for attempt in range(self.config.max_retries):
            try:
                start_time = time.time()
                
                async with self._client.post(endpoint, json=payload) as response:
                    latency_ms = int((time.time() - start_time) * 1000)
                    
                    # Handle rate limiting (429)
                    if response.status == 429:
                        try:
                            response_data = await response.json()
                        except Exception:
                            response_data = {}
                        
                        error = response_data.get("error", {})
                        error_msg = error.get("message", "OpenAI API rate limited (HTTP 429)")
                        error_code = error.get("code") or error.get("type")
                        
                        # Check if it's quota exhaustion (not recoverable)
                        if error_code in {"insufficient_quota", "billing_hard_limit_reached"}:
                            raise AdapterRequestError(
                                f"❌ QUOTA EXHAUSTED: {error_msg}\n"
                                f"Please check your OpenAI billing at https://platform.openai.com/account/billing"
                            )
                        
                        # It's a rate limit - wait and retry
                        retry_after_header = response.headers.get("Retry-After")
                        try:
                            retry_after = float(retry_after_header) if retry_after_header else None
                        except ValueError:
                            retry_after = None
                        
                        # Use exponential backoff or server-provided retry time
                        wait_time = retry_after if retry_after is not None else (2 ** attempt)
                        
                        print(f"\n   ⏳ Rate limited. Waiting {wait_time:.1f}s before retry {attempt + 1}/{self.config.max_retries}...")
                        
                        last_error = AdapterRateLimitError(error_msg)
                        await asyncio.sleep(wait_time)
                        continue
                    
                    # Parse response
                    response_data = await response.json()
                    
                    # Handle other errors
                    if response.status != 200:
                        error_msg = response_data.get("error", {}).get("message", "Unknown error")
                        raise AdapterRequestError(f"OpenAI API error: {error_msg}")
                    
                    # Success - parse response
                    choice = response_data["choices"][0]
                    
                    return ModelResponse(
                        content=choice["message"]["content"],
                        model=response_data["model"],
                        finish_reason=choice["finish_reason"],
                        tokens_used=response_data["usage"]["total_tokens"],
                        latency_ms=latency_ms,
                        raw_response=response_data,
                        metadata={
                            "prompt_tokens": response_data["usage"]["prompt_tokens"],
                            "completion_tokens": response_data["usage"]["completion_tokens"]
                        }
                    )
                    
            except asyncio.TimeoutError:
                last_error = AdapterTimeoutError(f"Request timed out after {self.config.timeout}s")
                if attempt == self.config.max_retries - 1:
                    raise last_error
                
                wait_time = 2 ** attempt
                print(f"\n   ⏳ Timeout. Waiting {wait_time}s before retry {attempt + 1}/{self.config.max_retries}...")
                await asyncio.sleep(wait_time)
            
            except aiohttp.ClientError as e:
                last_error = AdapterRequestError(f"HTTP client error: {str(e)}")
                if attempt == self.config.max_retries - 1:
                    raise last_error
                
                wait_time = 2 ** attempt
                print(f"\n   ⏳ Client error. Waiting {wait_time}s before retry {attempt + 1}/{self.config.max_retries}...")
                await asyncio.sleep(wait_time)
            
            except AdapterRequestError:
                # Don't retry on quota/auth errors
                raise
        
        # All retries exhausted
        if last_error:
            raise AdapterRequestError(f"Max retries ({self.config.max_retries}) exceeded: {last_error}")
        raise AdapterRequestError(f"Max retries ({self.config.max_retries}) exceeded")
    
    async def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """Generate streaming response from OpenAI API"""
        
        if not self.is_initialized:
            await self.initialize()
        
        # Build messages (same as generate)
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        if conversation_history:
            messages.extend([
                {"role": msg.role, "content": msg.content}
                for msg in conversation_history
            ])
        
        messages.append({"role": "user", "content": prompt})
        
        params = self._merge_parameters(kwargs)
        
        payload = {
            "model": self.config.model_name or "gpt-4",
            "messages": messages,
            "temperature": params.get("temperature", 0.7),
            "max_tokens": params.get("max_tokens", 2000),
            "stream": True
        }
        
        endpoint = self.config.endpoint or self.DEFAULT_ENDPOINT
        
        async with self._client.post(endpoint, json=payload) as response:
            if response.status != 200:
                error_data = await response.json()
                error_msg = error_data.get("error", {}).get("message", "Unknown error")
                raise AdapterRequestError(f"OpenAI API error: {error_msg}")
            
            async for line in response.content:
                line = line.decode('utf-8').strip()
                if line.startswith("data: "):
                    data = line[6:]
                    if data == "[DONE]":
                        break
                    
                    import json
                    chunk = json.loads(data)
                    
                    if "choices" in chunk and len(chunk["choices"]) > 0:
                        delta = chunk["choices"][0].get("delta", {})
                        if "content" in delta:
                            yield delta["content"]
    
    async def health_check(self) -> bool:
        """Check if OpenAI API is accessible"""
        try:
            # Simple models list request
            endpoint = "https://api.openai.com/v1/models"
            async with self._client.get(endpoint) as response:
                return response.status == 200
        except Exception:
            return False
    
    async def close(self) -> None:
        """Close the HTTP client session"""
        if self._client:
            await self._client.close()