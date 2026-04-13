"""
Ollama Adapter - FREE Local LLM Support
Implements BaseModelAdapter for Ollama (local models)
"""

import time
import asyncio
from typing import Optional, List, AsyncIterator, Dict, Any
import aiohttp
import json
from adapters.base import (
    BaseModelAdapter,
    ModelResponse,
    ConversationMessage,
    AdapterInitializationError,
    AdapterRequestError,
    AdapterTimeoutError
)


class OllamaAdapter(BaseModelAdapter):
    """Adapter for Ollama local models"""
    
    DEFAULT_ENDPOINT = "http://localhost:11434"
    
    async def initialize(self) -> None:
        """Initialize the HTTP client session"""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self._client = aiohttp.ClientSession(
            headers={"Content-Type": "application/json"},
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
        """Generate response from Ollama"""
        
        if not self.is_initialized:
            await self.initialize()
        
        # Build messages array (Ollama supports chat format)
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
            "model": self.config.model_name or "llama3.2",
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": params.get("temperature", 0.7),
                "num_predict": params.get("max_tokens", 1500),
                "top_p": params.get("top_p", 0.9),
            }
        }
        
        # Execute request
        endpoint = f"{self.config.endpoint or self.DEFAULT_ENDPOINT}/api/chat"
        
        for attempt in range(self.config.max_retries):
            try:
                start_time = time.time()
                
                async with self._client.post(endpoint, json=payload) as response:
                    latency_ms = int((time.time() - start_time) * 1000)
                    
                    if response.status != 200:
                        error_text = await response.text()
                        raise AdapterRequestError(f"Ollama error: {error_text}")
                    
                    response_data = await response.json()
                    
                    # Parse Ollama response
                    content = response_data.get("message", {}).get("content", "")
                    
                    # Estimate token count (rough approximation)
                    tokens_used = len(prompt.split()) + len(content.split())
                    
                    return ModelResponse(
                        content=content,
                        model=response_data.get("model", self.config.model_name),
                        finish_reason=response_data.get("done_reason", "stop"),
                        tokens_used=tokens_used,
                        latency_ms=latency_ms,
                        raw_response=response_data,
                        metadata={
                            "total_duration": response_data.get("total_duration"),
                            "load_duration": response_data.get("load_duration"),
                            "prompt_eval_count": response_data.get("prompt_eval_count"),
                            "eval_count": response_data.get("eval_count"),
                        }
                    )
                    
            except asyncio.TimeoutError:
                if attempt == self.config.max_retries - 1:
                    raise AdapterTimeoutError(f"Request timed out after {self.config.timeout}s")
                print(f"   ⏳ Timeout. Retrying {attempt + 1}/{self.config.max_retries}...")
                await asyncio.sleep(2 ** attempt)
            
            except aiohttp.ClientError as e:
                if attempt == self.config.max_retries - 1:
                    raise AdapterRequestError(f"HTTP client error: {str(e)}")
                print(f"   ⏳ Client error. Retrying {attempt + 1}/{self.config.max_retries}...")
                await asyncio.sleep(2 ** attempt)
        
        raise AdapterRequestError(f"Max retries ({self.config.max_retries}) exceeded")
    
    async def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """Generate streaming response from Ollama"""
        
        if not self.is_initialized:
            await self.initialize()
        
        # Build messages
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
            "model": self.config.model_name or "llama3.2",
            "messages": messages,
            "stream": True,
            "options": {
                "temperature": params.get("temperature", 0.7),
                "num_predict": params.get("max_tokens", 1500),
            }
        }
        
        endpoint = f"{self.config.endpoint or self.DEFAULT_ENDPOINT}/api/chat"
        
        async with self._client.post(endpoint, json=payload) as response:
            if response.status != 200:
                error_text = await response.text()
                raise AdapterRequestError(f"Ollama error: {error_text}")
            
            async for line in response.content:
                if line:
                    try:
                        chunk = json.loads(line)
                        if "message" in chunk:
                            content = chunk["message"].get("content", "")
                            if content:
                                yield content
                    except json.JSONDecodeError:
                        continue
    
    async def health_check(self) -> bool:
        """Check if Ollama is accessible"""
        try:
            endpoint = f"{self.config.endpoint or self.DEFAULT_ENDPOINT}/api/tags"
            async with self._client.get(endpoint) as response:
                return response.status == 200
        except Exception:
            return False
    
    async def close(self) -> None:
        """Close the HTTP client session"""
        if self._client:
            await self._client.close()
