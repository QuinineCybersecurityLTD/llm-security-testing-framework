"""
Google Gemini API Adapter
Implements BaseModelAdapter for Google's Gemini models
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


class GeminiAdapter(BaseModelAdapter):
    """Adapter for Google Gemini API"""
    
    DEFAULT_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta"
    
    async def initialize(self) -> None:
        """Initialize the HTTP client session"""
        if self.config.api_key and self.config.api_key.startswith("${") and self.config.api_key.endswith("}"):
            import os
            env_var = self.config.api_key[2:-1]
            self.config.api_key = os.environ.get(env_var)
            
        if not self.config.api_key:
            raise AdapterInitializationError("Gemini API key is required")
        
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self._client = aiohttp.ClientSession(
            headers={"Content-Type": "application/json"},
            timeout=timeout
        )
        self._initialized = True
    
    def _build_messages(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None
    ) -> List[Dict[str, Any]]:
        """Build Gemini messages format (system prompt handled separately via systemInstruction)"""
        contents = []
        
        # Add conversation history
        if conversation_history:
            for msg in conversation_history:
                role = "user" if msg.role == "user" else "model"
                contents.append({
                    "role": role,
                    "parts": [{"text": msg.content}]
                })
        
        # Add current prompt (system prompt is NOT embedded here — it goes in systemInstruction)
        contents.append({
            "role": "user",
            "parts": [{"text": prompt}]
        })
        
        return contents
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> ModelResponse:
        """Generate response from Gemini API"""
        
        if not self.is_initialized:
            await self.initialize()
        
        # Build contents
        contents = self._build_messages(prompt, system_prompt, conversation_history)
        
        # Merge parameters
        params = self._merge_parameters(kwargs)
        
        # Build request payload
        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": params.get("temperature", 0.7),
                "maxOutputTokens": params.get("max_tokens", 2000),
                "topP": params.get("top_p", 0.95),
                "topK": params.get("top_k", 40),
            }
        }
        
        # Use Gemini's native systemInstruction field for system prompts
        if system_prompt:
            payload["systemInstruction"] = {
                "parts": [{"text": system_prompt}]
            }
        
        # Add safety settings if provided
        if params.get("safety_settings"):
            payload["safetySettings"] = params["safety_settings"]
        
        # Build endpoint URL
        model_name = self.config.model_name or "gemini-1.5-flash"
        endpoint = f"{self.config.endpoint or self.DEFAULT_ENDPOINT}/models/{model_name}:generateContent"
        
        # Add API key as query parameter
        url = f"{endpoint}?key={self.config.api_key}"
        
        # Execute request with retries
        last_error: Optional[Exception] = None
        
        for attempt in range(self.config.max_retries):
            try:
                start_time = time.time()
                
                async with self._client.post(url, json=payload) as response:
                    latency_ms = int((time.time() - start_time) * 1000)
                    
                    response_data = await response.json()
                    
                    # Handle rate limiting (429)
                    if response.status == 429:
                        error_msg = response_data.get("error", {}).get("message", "Rate limited")
                        
                        # Check if quota exhausted
                        if "quota" in error_msg.lower():
                            raise AdapterRequestError(
                                f"❌ GEMINI QUOTA EXHAUSTED: {error_msg}\n"
                                f"Check your quota at: https://aistudio.google.com/"
                            )
                        
                        # Rate limit - wait and retry
                        wait_time = 2 ** attempt
                        print(f"\n   ⏳ Rate limited. Waiting {wait_time}s before retry {attempt + 1}/{self.config.max_retries}...")
                        
                        last_error = AdapterRateLimitError(error_msg)
                        await asyncio.sleep(wait_time)
                        continue
                    
                    # Handle other errors
                    if response.status != 200:
                        error = response_data.get("error", {})
                        error_msg = error.get("message", "Unknown error")
                        error_code = error.get("code")
                        
                        raise AdapterRequestError(
                            f"Gemini API error ({error_code}): {error_msg}"
                        )
                    
                    # Parse successful response
                    if "candidates" not in response_data or not response_data["candidates"]:
                        # Check for safety blocks
                        prompt_feedback = response_data.get("promptFeedback", {})
                        block_reason = prompt_feedback.get("blockReason")
                        
                        if block_reason:
                            raise AdapterRequestError(
                                f"Content blocked by Gemini safety filters: {block_reason}"
                            )
                        
                        raise AdapterRequestError("No response generated by Gemini")
                    
                    candidate = response_data["candidates"][0]
                    content = candidate.get("content", {})
                    
                    # Extract text from parts
                    text_parts = []
                    for part in content.get("parts", []):
                        if "text" in part:
                            text_parts.append(part["text"])
                    
                    response_text = "".join(text_parts)
                    
                    # Get token counts
                    usage_metadata = response_data.get("usageMetadata", {})
                    prompt_tokens = usage_metadata.get("promptTokenCount", 0)
                    completion_tokens = usage_metadata.get("candidatesTokenCount", 0)
                    total_tokens = usage_metadata.get("totalTokenCount", prompt_tokens + completion_tokens)
                    
                    # Get finish reason
                    finish_reason = candidate.get("finishReason", "STOP")
                    
                    return ModelResponse(
                        content=response_text,
                        model=model_name,
                        finish_reason=finish_reason,
                        tokens_used=total_tokens,
                        latency_ms=latency_ms,
                        raw_response=response_data,
                        metadata={
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "safety_ratings": candidate.get("safetyRatings", []),
                            "citation_metadata": candidate.get("citationMetadata", {}),
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
                # Don't retry on quota/safety errors
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
        """Generate streaming response from Gemini API"""
        
        if not self.is_initialized:
            await self.initialize()
        
        # Build contents
        contents = self._build_messages(prompt, system_prompt, conversation_history)
        
        params = self._merge_parameters(kwargs)
        
        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": params.get("temperature", 0.7),
                "maxOutputTokens": params.get("max_tokens", 1000),
                "topP": params.get("top_p", 0.95),
            }
        }
        
        # Build streaming endpoint
        model_name = self.config.model_name or "gemini-1.5-flash"
        endpoint = f"{self.config.endpoint or self.DEFAULT_ENDPOINT}/models/{model_name}:streamGenerateContent"
        url = f"{endpoint}?key={self.config.api_key}&alt=sse"
        
        async with self._client.post(url, json=payload) as response:
            if response.status != 200:
                error_data = await response.json()
                error_msg = error_data.get("error", {}).get("message", "Unknown error")
                raise AdapterRequestError(f"Gemini API error: {error_msg}")
            
            async for line in response.content:
                line = line.decode('utf-8').strip()
                
                if line.startswith("data: "):
                    data = line[6:]
                    
                    if data == "[DONE]":
                        break
                    
                    try:
                        import json
                        chunk = json.loads(data)
                        
                        if "candidates" in chunk and chunk["candidates"]:
                            candidate = chunk["candidates"][0]
                            content = candidate.get("content", {})
                            
                            for part in content.get("parts", []):
                                if "text" in part:
                                    yield part["text"]
                    except json.JSONDecodeError:
                        continue
    
    async def health_check(self) -> bool:
        """Check if Gemini API is accessible"""
        try:
            # Simple list models request
            url = f"{self.config.endpoint or self.DEFAULT_ENDPOINT}/models?key={self.config.api_key}"
            async with self._client.get(url) as response:
                return response.status == 200
        except Exception:
            return False
    
    async def close(self) -> None:
        """Close the HTTP client session"""
        if self._client:
            await self._client.close()
