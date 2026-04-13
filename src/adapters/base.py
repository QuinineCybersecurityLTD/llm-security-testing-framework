"""
Base Model Adapter Interface
Defines the contract for all LLM model adapters
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, AsyncIterator
from dataclasses import dataclass
from enum import Enum
import asyncio


class ModelType(Enum):
    """Supported model types"""
    OPENAI_API = "openai_api"
    ANTHROPIC_API = "anthropic_api"
    GEMINI_API = "gemini_api"
    COHERE_API = "cohere_api"
    HUGGINGFACE_LOCAL = "huggingface_local"
    HUGGINGFACE_API = "huggingface_api"
    OLLAMA = "ollama"
    LOCAL_GGUF = "local_gguf"
    BEDROCK = "aws_bedrock"
    AZURE_OPENAI = "azure_openai"
    VERTEX_AI = "gcp_vertex"
    LANGCHAIN = "langchain"
    LLAMAINDEX = "llamaindex"
    CUSTOM_REST = "custom_rest"
    PROMPTINTEL_API = "promptintel_api"


@dataclass
class ModelConfig:
    """Configuration for a model instance"""
    name: str
    model_type: ModelType
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    model_name: Optional[str] = None
    parameters: Dict[str, Any] = None
    timeout: int = 30
    max_retries: int = 3
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}


@dataclass
class ModelResponse:
    """Standardized model response"""
    content: str
    model: str
    finish_reason: str
    tokens_used: int
    latency_ms: int
    raw_response: Dict[str, Any]
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ConversationMessage:
    """Single message in a conversation"""
    role: str  # system, user, assistant
    content: str
    metadata: Optional[Dict[str, Any]] = None


class BaseModelAdapter(ABC):
    """
    Abstract base class for all model adapters
    Implements the Adapter pattern for universal model access
    """
    
    def __init__(self, config: ModelConfig):
        self.config = config
        self._client = None
        self._initialized = False
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the adapter and establish connections"""
        pass
    
    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> ModelResponse:
        """
        Generate a response from the model
        
        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt
            conversation_history: Optional conversation context
            **kwargs: Additional model-specific parameters
            
        Returns:
            ModelResponse with standardized fields
        """
        pass
    
    @abstractmethod
    async def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[ConversationMessage]] = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Generate a streaming response from the model
        
        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt
            conversation_history: Optional conversation context
            **kwargs: Additional model-specific parameters
            
        Yields:
            Response chunks as they arrive
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the model is accessible and healthy"""
        pass
    
    async def close(self) -> None:
        """Clean up resources"""
        if self._client:
            # Base implementation - override if needed
            pass
    
    @property
    def is_initialized(self) -> bool:
        """Check if adapter is initialized"""
        return self._initialized
    
    def _merge_parameters(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Merge config parameters with runtime parameters"""
        params = self.config.parameters.copy()
        params.update(kwargs)
        return params
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(model={self.config.model_name}, type={self.config.model_type.value})"


class AdapterException(Exception):
    """Base exception for adapter errors"""
    pass


class AdapterInitializationError(AdapterException):
    """Raised when adapter fails to initialize"""
    pass


class AdapterRequestError(AdapterException):
    """Raised when a request to the model fails"""
    pass


class AdapterTimeoutError(AdapterException):
    """Raised when a request times out"""
    pass


class AdapterRateLimitError(AdapterException):
    """Raised when rate limit is exceeded"""
    pass
