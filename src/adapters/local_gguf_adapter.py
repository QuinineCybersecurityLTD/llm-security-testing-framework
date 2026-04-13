"""
Local GGUF Model Adapter
Implements BaseModelAdapter for locally-hosted GGUF models using llama-cpp-python
Supports Mistral, Llama, and other GGUF-compatible models
"""

import time
import asyncio
from typing import Optional, List, Dict, Any, AsyncIterator
from pathlib import Path

from adapters.base import (
    BaseModelAdapter,
    ModelResponse,
    ConversationMessage,
    AdapterInitializationError,
    AdapterRequestError,
    AdapterTimeoutError
)

try:
    from llama_cpp import Llama
except ImportError:
    raise ImportError(
        "llama-cpp-python is required for local GGUF models. "
        "Install with: pip install llama-cpp-python"
    )


class LocalGGUFAdapter(BaseModelAdapter):
    """Adapter for locally-hosted GGUF models (Mistral, Llama, etc.)"""
    
    async def initialize(self) -> None:
        """Load the GGUF model from disk"""
        
        if not self.config.model_name:
            raise AdapterInitializationError(
                "model_name is required for LocalGGUFAdapter (path to GGUF file)"
            )
        
        model_path = Path(self.config.model_name)
        
        if not model_path.exists():
            raise AdapterInitializationError(
                f"GGUF model file not found: {model_path}"
            )
        
        try:
            print(f"   Loading GGUF model from: {model_path}")
            
            # Load the model with optimal settings
            self._model = Llama(
                model_path=str(model_path),
                n_gpu_layers=-1,  # Use GPU if available
                n_ctx=2048,  # Context window
                verbose=False
            )
            self._initialized = True
            print(f"   ✅ Model loaded successfully")
            
        except Exception as e:
            raise AdapterInitializationError(
                f"Failed to load GGUF model: {str(e)}\n"
                f"Make sure the file path is correct and the file is a valid GGUF model."
            )
    
    def _build_prompt(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None
    ) -> str:
        """
        Build conversation prompt using auto-detected or configured chat template.
        Supports all model families: Mistral, Llama 3, ChatML (Phi/Qwen/Yi),
        Gemma, Vicuna, Alpaca, and more.
        """
        from adapters.chat_templates import format_prompt
        
        template_override = self.config.parameters.get("chat_template")
        return format_prompt(
            model_name=self.config.model_name or "",
            prompt=prompt,
            system_prompt=system_prompt,
            history=conversation_history,
            template_override=template_override,
        )
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> ModelResponse:
        """Generate response from local GGUF model"""
        
        if not self.is_initialized:
            await self.initialize()
        
        # Build the full prompt
        full_prompt = self._build_prompt(prompt, system_prompt, conversation_history)
        
        # Merge parameters
        params = self._merge_parameters(kwargs)
        
        try:
            start_time = time.time()
            
            # Run model inference (synchronous, so wrap in thread to avoid blocking)
            loop = asyncio.get_event_loop()
            
            def run_inference():
                return self._model.create_completion(
                    full_prompt,
                    max_tokens=params.get("max_tokens", 1500),
                    temperature=params.get("temperature", 0.7),
                    top_p=params.get("top_p", 0.95),
                )
            
            response_data = await loop.run_in_executor(None, run_inference)
            
            latency_ms = int((time.time() - start_time) * 1000)
            
            # Extract generated text
            generated_text = response_data["choices"][0]["text"].strip()
            
            # Clean up spurious content
            if "</s>" in generated_text:
                generated_text = generated_text.split("</s>")[0].strip()
            
            return ModelResponse(
                content=generated_text,
                model=self.config.name or "local-gguf",
                finish_reason=response_data.get("finish_reason", "length"),
                tokens_used=response_data.get("usage", {}).get("completion_tokens", 0),
                latency_ms=latency_ms,
                raw_response=response_data,
                metadata={
                    "model_path": str(self.config.model_name),
                    "local": True
                }
            )
            
        except asyncio.TimeoutError:
            raise AdapterTimeoutError(f"Generation timed out after {self.config.timeout}s")
        except Exception as e:
            raise AdapterRequestError(f"Generation failed: {str(e)}")
    
    async def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Stream response tokens from local GGUF model
        Note: For local models, this still processes the full response
        """
        response = await self.generate(prompt, system_prompt, conversation_history, **kwargs)
        
        # Yield the entire response as one chunk (streaming not fully supported in llama-cpp-python)
        yield response.content
    
    async def health_check(self) -> bool:
        """Check if the GGUF model is loaded and healthy"""
        try:
            if not self.is_initialized:
                return False
            
            # Check if model is loaded
            if not hasattr(self, '_model') or self._model is None:
                return False
            
            # Try a simple inference to verify health
            try:
                response = await self.generate(
                    "test",
                    **{"max_tokens": 10, "temperature": 0.1}
                )
                return bool(response.content)
            except Exception:
                return False
        except Exception:
            return False
    
    async def close(self) -> None:
        """Clean up resources"""
        if hasattr(self, '_model') and self._model:
            # llama-cpp-python cleanup
            pass
        self._initialized = False
