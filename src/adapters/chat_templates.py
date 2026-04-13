"""
Chat Template Engine
Universal prompt formatter for all LLM model families.
Supports auto-detection from model name and explicit override via config.

Usage:
    from adapters.chat_templates import format_prompt
    
    # Auto-detect template from model name
    prompt = format_prompt("mistral-7b-instruct", "Hello!", system_prompt="You are helpful.")
    
    # Explicit override
    prompt = format_prompt("my-custom-model", "Hello!", template_override="chatml")
"""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass
import re


@dataclass
class ChatMessage:
    """A single message in a conversation"""
    role: str  # "system", "user", "assistant"
    content: str


# ═══════════════════════════════════════════════════════════════════
# TEMPLATE DEFINITIONS
# Each template defines how to format a prompt for a model family.
# Add new model families by adding a new entry here — no other code
# changes needed.
# ═══════════════════════════════════════════════════════════════════

CHAT_TEMPLATES: Dict[str, Dict[str, str]] = {
    "mistral": {
        "description": "Mistral Instruct format",
        "bos": "<s>",
        "inst_open": "[INST]",
        "inst_close": "[/INST]",
        "eos": "</s>",
    },
    "llama3": {
        "description": "Llama 3 / Llama 3.1 / Llama 3.2 format",
        "bos": "<|begin_of_text|>",
        "header_open": "<|start_header_id|>",
        "header_close": "<|end_header_id|>",
        "eot": "<|eot_id|>",
    },
    "llama2": {
        "description": "Llama 2 Chat format",
        "bos": "<s>",
        "inst_open": "[INST]",
        "inst_close": "[/INST]",
        "sys_open": "<<SYS>>",
        "sys_close": "<</SYS>>",
        "eos": "</s>",
    },
    "chatml": {
        "description": "ChatML format (Phi, Qwen, Yi, OpenHermes, Nous-Hermes)",
        "im_start": "<|im_start|>",
        "im_end": "<|im_end|>",
    },
    "gemma": {
        "description": "Google Gemma format",
        "start_turn": "<start_of_turn>",
        "end_turn": "<end_of_turn>",
    },
    "vicuna": {
        "description": "Vicuna / ShareGPT format",
        "user_prefix": "USER:",
        "assistant_prefix": "ASSISTANT:",
        "system_prefix": "SYSTEM:",
    },
    "alpaca": {
        "description": "Alpaca / Stanford format",
        "instruction": "### Instruction:",
        "response": "### Response:",
        "input_tag": "### Input:",
    },
    "command_r": {
        "description": "Cohere Command R / R+ format",
        "bos": "<BOS_TOKEN>",
        "start_turn": "<|START_OF_TURN_TOKEN|>",
        "end_turn": "<|END_OF_TURN_TOKEN|>",
        "system": "<|SYSTEM_TOKEN|>",
        "user": "<|USER_TOKEN|>",
        "chatbot": "<|CHATBOT_TOKEN|>",
    },
    "raw": {
        "description": "No template — simple concatenation. Use for base (non-instruct) models.",
    },
}

# ═══════════════════════════════════════════════════════════════════
# AUTO-DETECTION RULES
# Maps model name patterns to template names.
# Order matters: first match wins.
# ═══════════════════════════════════════════════════════════════════

_DETECTION_RULES: List[tuple] = [
    # CodeLlama (must come before llama3/llama2 — contains 'llama' substring)
    (re.compile(r"codellama", re.IGNORECASE), "llama2"),
    
    # Llama 3.x (must come before llama2 check; uses word boundary to avoid codellama-34b)
    (re.compile(r"(?:^|[\-_\.\s])llama[\-_\.]?3", re.IGNORECASE), "llama3"),
    (re.compile(r"meta[\-_]llama[\-_]3", re.IGNORECASE), "llama3"),
    
    # Llama 2
    (re.compile(r"llama[\-_\.]?2", re.IGNORECASE), "llama2"),
    
    # ChatML family (dolphin can contain 'mistral' in name, so check first)
    (re.compile(r"dolphin", re.IGNORECASE), "chatml"),
    
    # Mistral / Mixtral
    (re.compile(r"mistral", re.IGNORECASE), "mistral"),
    (re.compile(r"mixtral", re.IGNORECASE), "mistral"),
    
    # ChatML family
    (re.compile(r"phi[\-_]?[234]", re.IGNORECASE), "chatml"),
    (re.compile(r"qwen", re.IGNORECASE), "chatml"),
    (re.compile(r"yi[\-_]", re.IGNORECASE), "chatml"),
    (re.compile(r"openhermes", re.IGNORECASE), "chatml"),
    (re.compile(r"nous[\-_]hermes", re.IGNORECASE), "chatml"),
    (re.compile(r"dolphin", re.IGNORECASE), "chatml"),
    (re.compile(r"neural[\-_]?chat", re.IGNORECASE), "chatml"),
    
    # Gemma
    (re.compile(r"gemma", re.IGNORECASE), "gemma"),
    
    # Vicuna
    (re.compile(r"vicuna", re.IGNORECASE), "vicuna"),
    
    # Alpaca
    (re.compile(r"alpaca", re.IGNORECASE), "alpaca"),
    
    # Cohere Command R
    (re.compile(r"command[\-_]?r", re.IGNORECASE), "command_r"),
    
    # Catch-all for instruct models → ChatML as safe default
    (re.compile(r"instruct", re.IGNORECASE), "chatml"),
]


def detect_template(model_name: str) -> str:
    """
    Auto-detect the best chat template for a given model name.
    
    Returns the template key (e.g., "mistral", "llama3", "chatml").
    Falls back to "chatml" if no match — ChatML is the safest universal default
    as it's widely supported and unambiguous.
    """
    if not model_name:
        return "chatml"
    
    for pattern, template_key in _DETECTION_RULES:
        if pattern.search(model_name):
            return template_key
    
    # Default fallback
    return "chatml"


def format_prompt(
    model_name: str,
    prompt: str,
    system_prompt: Optional[str] = None,
    history: Optional[List[Any]] = None,
    template_override: Optional[str] = None,
) -> str:
    """
    Format a prompt using the correct chat template for the model.
    
    Args:
        model_name: Name/ID of the model (used for auto-detection)
        prompt: The user's current message
        system_prompt: Optional system instruction
        history: Optional conversation history (list of objects with .role and .content)
        template_override: Explicit template name (skips auto-detection)
    
    Returns:
        Formatted prompt string ready for the model
    """
    # Determine which template to use
    template_key = template_override or detect_template(model_name)
    
    if template_key not in CHAT_TEMPLATES:
        raise ValueError(
            f"Unknown chat template '{template_key}'. "
            f"Available: {list(CHAT_TEMPLATES.keys())}"
        )
    
    # Normalize history into ChatMessage objects
    messages: List[ChatMessage] = []
    if history:
        for msg in history:
            if hasattr(msg, 'role') and hasattr(msg, 'content'):
                messages.append(ChatMessage(role=msg.role, content=msg.content))
            elif isinstance(msg, dict):
                messages.append(ChatMessage(role=msg["role"], content=msg["content"]))
    
    # Dispatch to formatter
    formatter = _FORMATTERS.get(template_key, _format_chatml)
    return formatter(prompt, system_prompt, messages)


# ═══════════════════════════════════════════════════════════════════
# TEMPLATE FORMATTERS
# One function per template family. Each takes (prompt, system, history)
# and returns a formatted string.
# ═══════════════════════════════════════════════════════════════════

def _format_mistral(prompt: str, system: Optional[str], history: List[ChatMessage]) -> str:
    """Format for Mistral Instruct"""
    # Do NOT include <s> here — llama-cpp-python adds BOS automatically
    parts = []
    
    # System prompt goes inside the first [INST] block for Mistral
    first_inst_content = ""
    if system:
        first_inst_content = f"{system}\n\n"
    
    if history:
        for i, msg in enumerate(history):
            if msg.role == "user":
                content = msg.content
                if i == 0 and first_inst_content:
                    content = first_inst_content + content
                    first_inst_content = ""
                parts.append(f"[INST] {content} [/INST]")
            elif msg.role == "assistant":
                parts.append(f" {msg.content}</s>")
    
    # Current user prompt
    if first_inst_content:
        parts.append(f"[INST] {first_inst_content}{prompt} [/INST]")
    else:
        parts.append(f"[INST] {prompt} [/INST]")
    
    return "".join(parts)


def _format_llama3(prompt: str, system: Optional[str], history: List[ChatMessage]) -> str:
    """Format for Llama 3 / 3.1 / 3.2"""
    parts = ["<|begin_of_text|>"]
    
    if system:
        parts.append(
            f"<|start_header_id|>system<|end_header_id|>\n\n{system}<|eot_id|>"
        )
    
    for msg in history:
        parts.append(
            f"<|start_header_id|>{msg.role}<|end_header_id|>\n\n{msg.content}<|eot_id|>"
        )
    
    parts.append(
        f"<|start_header_id|>user<|end_header_id|>\n\n{prompt}<|eot_id|>"
    )
    parts.append("<|start_header_id|>assistant<|end_header_id|>\n\n")
    
    return "".join(parts)


def _format_llama2(prompt: str, system: Optional[str], history: List[ChatMessage]) -> str:
    """Format for Llama 2 Chat"""
    # Do NOT include <s> here — llama-cpp-python adds BOS automatically
    parts = []
    
    # First user message includes system prompt
    first_user_content = ""
    if system:
        first_user_content = f"<<SYS>>\n{system}\n<</SYS>>\n\n"
    
    if history:
        for i, msg in enumerate(history):
            if msg.role == "user":
                content = msg.content
                if i == 0:
                    content = first_user_content + content
                    first_user_content = ""
                parts.append(f"[INST] {content} [/INST]")
            elif msg.role == "assistant":
                parts.append(f" {msg.content} </s><s>")
    
    # Current prompt
    current = first_user_content + prompt if first_user_content else prompt
    parts.append(f"[INST] {current} [/INST]")
    
    return "".join(parts)


def _format_chatml(prompt: str, system: Optional[str], history: List[ChatMessage]) -> str:
    """Format for ChatML (Phi, Qwen, Yi, OpenHermes, NeuralChat)"""
    parts = []
    
    if system:
        parts.append(f"<|im_start|>system\n{system}<|im_end|>")
    
    for msg in history:
        parts.append(f"<|im_start|>{msg.role}\n{msg.content}<|im_end|>")
    
    parts.append(f"<|im_start|>user\n{prompt}<|im_end|>")
    parts.append("<|im_start|>assistant\n")
    
    return "\n".join(parts)


def _format_gemma(prompt: str, system: Optional[str], history: List[ChatMessage]) -> str:
    """Format for Google Gemma"""
    parts = []
    
    # Gemma doesn't have a native system role — prepend to first user message
    first_user_prefix = ""
    if system:
        first_user_prefix = f"{system}\n\n"
    
    if history:
        for i, msg in enumerate(history):
            if msg.role == "user":
                content = msg.content
                if i == 0 and first_user_prefix:
                    content = first_user_prefix + content
                    first_user_prefix = ""
                parts.append(f"<start_of_turn>user\n{content}<end_of_turn>")
            elif msg.role == "assistant":
                parts.append(f"<start_of_turn>model\n{msg.content}<end_of_turn>")
    
    # Current prompt
    if first_user_prefix:
        parts.append(f"<start_of_turn>user\n{first_user_prefix}{prompt}<end_of_turn>")
    else:
        parts.append(f"<start_of_turn>user\n{prompt}<end_of_turn>")
    
    parts.append("<start_of_turn>model\n")
    
    return "\n".join(parts)


def _format_vicuna(prompt: str, system: Optional[str], history: List[ChatMessage]) -> str:
    """Format for Vicuna / ShareGPT"""
    parts = []
    
    if system:
        parts.append(f"SYSTEM: {system}")
        parts.append("")
    
    for msg in history:
        if msg.role == "user":
            parts.append(f"USER: {msg.content}")
        elif msg.role == "assistant":
            parts.append(f"ASSISTANT: {msg.content}")
    
    parts.append(f"USER: {prompt}")
    parts.append("ASSISTANT:")
    
    return "\n".join(parts)


def _format_alpaca(prompt: str, system: Optional[str], history: List[ChatMessage]) -> str:
    """Format for Alpaca / Stanford"""
    parts = []
    
    if system:
        parts.append(f"### Instruction:\n{system}")
        parts.append("")
    
    # Alpaca doesn't natively support multi-turn — flatten history into context
    if history:
        context_parts = []
        for msg in history:
            prefix = "User" if msg.role == "user" else "Assistant"
            context_parts.append(f"{prefix}: {msg.content}")
        parts.append(f"### Input:\n" + "\n".join(context_parts))
        parts.append("")
    
    parts.append(f"### Instruction:\n{prompt}")
    parts.append("")
    parts.append("### Response:")
    
    return "\n".join(parts)


def _format_command_r(prompt: str, system: Optional[str], history: List[ChatMessage]) -> str:
    """Format for Cohere Command R / R+"""
    parts = ["<BOS_TOKEN>"]
    
    if system:
        parts.append(
            f"<|START_OF_TURN_TOKEN|><|SYSTEM_TOKEN|>{system}<|END_OF_TURN_TOKEN|>"
        )
    
    for msg in history:
        if msg.role == "user":
            parts.append(
                f"<|START_OF_TURN_TOKEN|><|USER_TOKEN|>{msg.content}<|END_OF_TURN_TOKEN|>"
            )
        elif msg.role == "assistant":
            parts.append(
                f"<|START_OF_TURN_TOKEN|><|CHATBOT_TOKEN|>{msg.content}<|END_OF_TURN_TOKEN|>"
            )
    
    parts.append(
        f"<|START_OF_TURN_TOKEN|><|USER_TOKEN|>{prompt}<|END_OF_TURN_TOKEN|>"
    )
    parts.append("<|START_OF_TURN_TOKEN|><|CHATBOT_TOKEN|>")
    
    return "".join(parts)


def _format_raw(prompt: str, system: Optional[str], history: List[ChatMessage]) -> str:
    """Raw format — simple concatenation for base (non-instruct) models"""
    parts = []
    
    if system:
        parts.append(system)
        parts.append("")
    
    for msg in history:
        parts.append(msg.content)
    
    parts.append(prompt)
    
    return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════
# FORMATTER REGISTRY
# ═══════════════════════════════════════════════════════════════════

_FORMATTERS = {
    "mistral": _format_mistral,
    "llama3": _format_llama3,
    "llama2": _format_llama2,
    "chatml": _format_chatml,
    "gemma": _format_gemma,
    "vicuna": _format_vicuna,
    "alpaca": _format_alpaca,
    "command_r": _format_command_r,
    "raw": _format_raw,
}


def get_available_templates() -> Dict[str, str]:
    """Return available templates with their descriptions"""
    return {
        key: tmpl.get("description", "")
        for key, tmpl in CHAT_TEMPLATES.items()
    }
