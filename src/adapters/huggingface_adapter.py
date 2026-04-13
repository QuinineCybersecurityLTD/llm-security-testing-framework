"""
HuggingFace Inference API Adapter
Implements BaseModelAdapter for HuggingFace models using the OpenAI compatible endpoint.
"""

import time
import os
import asyncio
from typing import Optional, List, AsyncIterator, Dict, Any
from openai import AsyncOpenAI

from adapters.base import (
    BaseModelAdapter,
    ModelResponse,
    ConversationMessage,
    AdapterInitializationError,
    AdapterRequestError,
    AdapterTimeoutError,
    AdapterRateLimitError
)


class HuggingFaceAdapter(BaseModelAdapter):
    """Adapter for HuggingFace Inference API via OpenAI compatible endpoint"""
    
    DEFAULT_ENDPOINT = "https://router.huggingface.co/v1"
    
    async def initialize(self) -> None:
        """Initialize the client session"""
        # Resolve API key: config → HUGGINGFACE_API_KEY → HF_API_KEY
        if self.config.api_key and self.config.api_key.startswith("${") and self.config.api_key.endswith("}"):
            env_var = self.config.api_key[2:-1]
            self.config.api_key = os.environ.get(env_var)
            
        if not self.config.api_key:
            self.config.api_key = (
                os.environ.get("HUGGINGFACE_API_KEY")
                or os.environ.get("HF_API_KEY")
            )
        if not self.config.api_key:
            raise AdapterInitializationError(
                "HuggingFace API key is required. Set HUGGINGFACE_API_KEY environment variable or pass it in config."
            )
        
        try:
            self._client = AsyncOpenAI(
                base_url=self.DEFAULT_ENDPOINT,
                api_key=self.config.api_key,
                timeout=self.config.timeout,
                max_retries=self.config.max_retries
            )
            self._initialized = True
        except Exception as e:
            raise AdapterInitializationError(f"Failed to initialize HuggingFace client: {str(e)}")
            
    def _build_messages(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None
    ) -> List[Dict[str, str]]:
        """Build messages format for chat completions"""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
            
        if conversation_history:
            for msg in conversation_history:
                # Map model role to assistant for OpenAI compatibility
                role = "assistant" if msg.role == "model" else msg.role
                messages.append({"role": role, "content": msg.content})
                
        messages.append({"role": "user", "content": prompt})
        return messages
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> ModelResponse:
        """Generate response from HuggingFace router"""
        
        if not self.is_initialized:
            await self.initialize()
        
        messages = self._build_messages(prompt, system_prompt, conversation_history)
        
        # Merge parameters
        params = self._merge_parameters(kwargs)
        
        # Build request parameters
        model_id = self.config.model_name or "MiniMaxAI/MiniMax-M2.5:fireworks-ai"
        
        # Filter kwargs to only those supported by OpenAI chat completions
        request_params = {
            "model": model_id,
            "messages": messages,
            "temperature": params.get("temperature", 0.7),
            "top_p": params.get("top_p", 0.95),
            "stream": False,  # Ensure complete output before returning
        }
        
        if "max_tokens" in params:
            request_params["max_tokens"] = params["max_tokens"]
        elif "max_new_tokens" in params:
             request_params["max_tokens"] = params["max_new_tokens"]
        else:
            request_params["max_tokens"] = 1500
            
        # Build extra headers for HuggingFace-specific options
        extra_headers = {}
        if params.get("wait_for_model", False):
            extra_headers["x-wait-for-model"] = "true"
        
        try:
            start_time = time.time()
            
            completion = await self._client.chat.completions.create(
                **request_params,
                extra_headers=extra_headers if extra_headers else None
            )
            
            latency_ms = int((time.time() - start_time) * 1000)
            
            # Map finish reason
            finish_reason = completion.choices[0].finish_reason if completion.choices else "unknown"
            content = completion.choices[0].message.content if completion.choices else ""
            
            tokens_used = 0
            if hasattr(completion, "usage") and completion.usage:
                tokens_used = completion.usage.total_tokens
            
            return ModelResponse(
                content=content,
                model=model_id,
                finish_reason=finish_reason,
                tokens_used=tokens_used,
                latency_ms=latency_ms,
                raw_response=completion.model_dump() if hasattr(completion, "model_dump") else {},
                metadata={}
            )
            
        except Exception as e:
            error_msg = str(e)
            if "rate limit" in error_msg.lower() or "429" in error_msg:
                raise AdapterRateLimitError(f"HuggingFace rate limited: {error_msg}")
            if "timeout" in error_msg.lower():
                raise AdapterTimeoutError(f"HuggingFace request timed out: {error_msg}")
            raise AdapterRequestError(f"HuggingFace request failed: {error_msg}")
    
    async def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """Generate streaming response from HuggingFace API"""
        
        if not self.is_initialized:
            await self.initialize()
            
        messages = self._build_messages(prompt, system_prompt, conversation_history)
        params = self._merge_parameters(kwargs)
        model_id = self.config.model_name or "MiniMaxAI/MiniMax-M2.5:fireworks-ai"
        
        request_params = {
            "model": model_id,
            "messages": messages,
            "temperature": params.get("temperature", 0.7),
            "top_p": params.get("top_p", 0.95),
            "stream": True
        }
        
        if "max_tokens" in params:
            request_params["max_tokens"] = params["max_tokens"]
        elif "max_new_tokens" in params:
             request_params["max_tokens"] = params["max_new_tokens"]
        else:
            request_params["max_tokens"] = 1500
        
        try:
            stream = await self._client.chat.completions.create(**request_params)
            
            async for chunk in stream:
                if chunk.choices and len(chunk.choices) > 0:
                    delta_content = chunk.choices[0].delta.content
                    if delta_content is not None:
                        yield delta_content
                        
        except Exception as e:
            error_msg = str(e)
            if "rate limit" in error_msg.lower() or "429" in error_msg:
                raise AdapterRateLimitError(f"HuggingFace rate limited: {error_msg}")
            if "timeout" in error_msg.lower():
                raise AdapterTimeoutError(f"HuggingFace request timed out: {error_msg}")
            raise AdapterRequestError(f"HuggingFace streaming failed: {error_msg}")
    
    async def health_check(self) -> bool:
        """Check if HuggingFace API is accessible"""
        try:
            if not self.is_initialized:
                await self.initialize()
            
            model_id = self.config.model_name or "MiniMaxAI/MiniMax-M2.5:fireworks-ai"
            
            # Simple test request with max_tokens=1
            await self._client.chat.completions.create(
                model=model_id,
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=1
            )
            return True
            
        except Exception as e:
            print(f"Health check failed: {e}")
            return False
    
    async def close(self) -> None:
        """Close the client session"""
        if hasattr(self, '_client') and self._client:
            if hasattr(self._client, 'close'):
                await self._client.close()
            self._client = None
