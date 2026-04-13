"""
Promptintel API Adapter
Implements BaseModelAdapter for Promptintel's secure prompt library
Uses the Promptintel API to fetch vetted prompts for security testing
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


class PromptintelAdapter(BaseModelAdapter):
    """Adapter for Promptintel API - Secure Prompt Management"""
    
    DEFAULT_ENDPOINT = "https://api.promptintel.novahunting.ai/api/v1"
    
    async def initialize(self) -> None:
        """Initialize the HTTP client session"""
        if self.config.api_key and self.config.api_key.startswith("${") and self.config.api_key.endswith("}"):
            import os
            env_var = self.config.api_key[2:-1]
            self.config.api_key = os.environ.get(env_var)
            
        if not self.config.api_key:
            raise AdapterInitializationError("Promptintel API key is required")
        
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self._client = aiohttp.ClientSession(
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.api_key}"
            },
            timeout=timeout
        )
        
        # Verify connection with health check
        is_healthy = await self.health_check()
        if not is_healthy:
            await self._client.close()
            raise AdapterInitializationError("Promptintel API health check failed")
        
        self._initialized = True
    
    async def health_check(self) -> bool:
        """Check if Promptintel API is accessible and healthy"""
        if not self._client:
            try:
                timeout = aiohttp.ClientTimeout(total=5)
                self._client = aiohttp.ClientSession(
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self.config.api_key}"
                    },
                    timeout=timeout
                )
            except Exception as e:
                raise AdapterInitializationError(f"Failed to create HTTP client: {e}")
        
        endpoint = f"{self.config.endpoint or self.DEFAULT_ENDPOINT}/health"
        
        try:
            async with self._client.get(endpoint) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("status") == "healthy" or data.get("ok") == True
                return False
        except Exception as e:
            raise AdapterRequestError(f"Health check failed: {e}")
    
    async def fetch_prompt(self, prompt_id: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Fetch a prompt from Promptintel API
        
        Args:
            prompt_id: Optional specific prompt ID to fetch
            **kwargs: Additional filters (category, difficulty, etc.)
        
        Returns:
            Prompt data from Promptintel
        """
        if not self.is_initialized:
            await self.initialize()
        
        endpoint = f"{self.config.endpoint or self.DEFAULT_ENDPOINT}/prompts"
        
        # Build query parameters
        params = {
            "limit": kwargs.get("limit", 1),
            "category": kwargs.get("category", "security"),
            "difficulty": kwargs.get("difficulty", "medium"),
        }
        
        if prompt_id:
            params["id"] = prompt_id
        
        for attempt in range(self.config.max_retries):
            try:
                start_time = time.time()
                
                async with self._client.get(endpoint, params=params) as response:
                    latency_ms = int((time.time() - start_time) * 1000)
                    
                    if response.status == 401:
                        raise AdapterRequestError("Invalid or expired Promptintel API key")
                    elif response.status == 429:
                        retry_after = int(response.headers.get("Retry-After", 60))
                        raise AdapterRateLimitError(f"Rate limited. Retry after {retry_after}s")
                    elif response.status != 200:
                        error_text = await response.text()
                        raise AdapterRequestError(f"Promptintel error: {error_text}")
                    
                    data = await response.json()
                    
                    return {
                        "prompts": data.get("data", data.get("prompts", [])),
                        "latency_ms": latency_ms,
                        "raw_response": data
                    }
                    
            except (AdapterRateLimitError, AdapterRequestError):
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise
            except asyncio.TimeoutError:
                raise AdapterTimeoutError(f"Promptintel API timeout after {self.config.timeout}s")
            except Exception as e:
                if attempt == self.config.max_retries - 1:
                    raise AdapterRequestError(f"Promptintel request failed: {e}")
                await asyncio.sleep(2 ** attempt)
        
        raise AdapterRequestError("Failed to fetch prompt from Promptintel after all retries")
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> ModelResponse:
        """
        Generate a response using Promptintel prompts
        For Promptintel, this returns the prompt metadata rather than a generation
        (Promptintel is a prompt library, not a language model)
        
        Args:
            prompt: Query or prompt ID
            system_prompt: Optional system context
            conversation_history: Ignored for Promptintel
            **kwargs: Query parameters for prompt search
        
        Returns:
            ModelResponse with prompt library data
        """
        if not self.is_initialized:
            await self.initialize()
        
        try:
            prompt_data = await self.fetch_prompt(
                prompt_id=prompt if prompt else None,
                category=kwargs.get("category", "security"),
                difficulty=kwargs.get("difficulty", "medium"),
                limit=kwargs.get("limit", 1)
            )
            
            # Extract prompt content
            prompts = prompt_data.get("prompts", [])
            if not prompts:
                content = f"No prompts found for query: {prompt}"
            else:
                # Return first prompt content
                first_prompt = prompts[0]
                content = first_prompt.get("text", first_prompt.get("content", str(first_prompt)))
            
            return ModelResponse(
                content=content,
                model=self.config.model_name or "promptintel",
                finish_reason="success",
                tokens_used=len(prompt.split()),
                latency_ms=prompt_data.get("latency_ms", 0),
                raw_response=prompt_data.get("raw_response", {}),
                metadata={
                    "source": "promptintel",
                    "total_prompts": len(prompts),
                    "query_parameters": {
                        "category": kwargs.get("category"),
                        "difficulty": kwargs.get("difficulty")
                    }
                }
            )
        
        except (AdapterRequestError, AdapterTimeoutError, AdapterRateLimitError) as e:
            raise
        except Exception as e:
            raise AdapterRequestError(f"Failed to generate prompt: {e}")
    
    async def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Streaming is not supported for Promptintel
        This is a prompt library, not a generative model
        """
        raise NotImplementedError(
            "Streaming is not supported for Promptintel. "
            "Use generate() method instead to fetch prompts."
        )
    
    async def close(self) -> None:
        """Clean up HTTP session"""
        if self._client:
            await self._client.close()
            self._client = None
            self._initialized = False
    
    def __repr__(self) -> str:
        return f"PromptintelAdapter(api_key={'***' if self.config.api_key else 'None'})"
