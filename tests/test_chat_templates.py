"""
Test Suite — Chat Template Engine
Unit tests for adapters/chat_templates.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from adapters.chat_templates import (
    detect_template,
    format_prompt,
    get_available_templates,
    ChatMessage,
)


# ═══════════════════════════════════════════════════════════════════
# AUTO-DETECTION TESTS
# ═══════════════════════════════════════════════════════════════════

class TestDetectTemplate:
    """Test auto-detection of chat template from model name"""

    def test_mistral_detection(self):
        assert detect_template("mistral-7b-instruct-v0.3") == "mistral"
        assert detect_template("Mistral-7B-Instruct") == "mistral"
        assert detect_template("mixtral-8x7b") == "mistral"

    def test_llama3_detection(self):
        assert detect_template("meta-llama-3-8b-instruct") == "llama3"
        assert detect_template("llama3.1-70b") == "llama3"
        assert detect_template("Meta-Llama-3.2-1B") == "llama3"

    def test_llama2_detection(self):
        assert detect_template("llama-2-13b-chat") == "llama2"
        assert detect_template("codellama-34b-instruct") == "llama2"

    def test_chatml_family_detection(self):
        assert detect_template("phi-3-mini-4k-instruct") == "chatml"
        assert detect_template("Qwen2-7B-Instruct") == "chatml"
        assert detect_template("yi-34b-chat") == "chatml"
        assert detect_template("openhermes-2.5") == "chatml"
        assert detect_template("nous-hermes-2") == "chatml"
        assert detect_template("dolphin-2.8-mistral-7b") == "chatml"

    def test_gemma_detection(self):
        assert detect_template("gemma-2-9b-it") == "gemma"
        assert detect_template("Gemma-7B") == "gemma"

    def test_vicuna_detection(self):
        assert detect_template("vicuna-13b-v1.5") == "vicuna"

    def test_alpaca_detection(self):
        assert detect_template("alpaca-7b") == "alpaca"

    def test_command_r_detection(self):
        assert detect_template("command-r-plus") == "command_r"
        assert detect_template("command_r-08-2024") == "command_r"

    def test_instruct_fallback(self):
        """Models with 'instruct' in the name should fall back to ChatML"""
        assert detect_template("some-custom-instruct-model") == "chatml"

    def test_unknown_default(self):
        """Unknown models default to ChatML"""
        assert detect_template("completely-unknown-model-v9") == "chatml"
        assert detect_template("") == "chatml"

    def test_llama3_before_llama2(self):
        """Llama 3 detection must take priority over Llama 2"""
        assert detect_template("llama3-70b") == "llama3"
        assert detect_template("llama-3.1-8b") == "llama3"


# ═══════════════════════════════════════════════════════════════════
# FORMATTER TESTS
# ═══════════════════════════════════════════════════════════════════

class TestFormatPrompt:
    """Test prompt formatting for each template family"""

    def test_mistral_basic(self):
        result = format_prompt("mistral-7b", "Hello")
        assert "[INST]" in result
        assert "Hello" in result
        assert result.startswith("<s>")

    def test_mistral_with_system(self):
        result = format_prompt("mistral-7b", "Hello", system_prompt="Be helpful")
        assert "Be helpful" in result
        assert "[INST]" in result

    def test_llama3_basic(self):
        result = format_prompt("llama-3-8b", "Hello")
        assert "<|begin_of_text|>" in result
        assert "<|start_header_id|>user<|end_header_id|>" in result
        assert "Hello" in result
        assert "<|start_header_id|>assistant<|end_header_id|>" in result

    def test_llama3_with_system(self):
        result = format_prompt("llama-3-8b", "Hello", system_prompt="System")
        assert "<|start_header_id|>system<|end_header_id|>" in result
        assert "System" in result

    def test_chatml_basic(self):
        result = format_prompt("phi-3", "Hello")
        assert "<|im_start|>user" in result
        assert "Hello" in result
        assert "<|im_start|>assistant" in result

    def test_chatml_with_system(self):
        result = format_prompt("phi-3", "Hello", system_prompt="Be safe")
        assert "<|im_start|>system" in result
        assert "Be safe" in result

    def test_gemma_basic(self):
        result = format_prompt("gemma-2-9b", "Hello")
        assert "<start_of_turn>user" in result
        assert "<start_of_turn>model" in result

    def test_vicuna_basic(self):
        result = format_prompt("vicuna-13b", "Hello")
        assert "USER: Hello" in result
        assert "ASSISTANT:" in result

    def test_alpaca_basic(self):
        result = format_prompt("alpaca-7b", "Hello")
        assert "### Instruction:" in result
        assert "### Response:" in result

    def test_command_r_basic(self):
        result = format_prompt("command-r-plus", "Hello")
        assert "<BOS_TOKEN>" in result
        assert "<|USER_TOKEN|>" in result
        assert "<|CHATBOT_TOKEN|>" in result

    def test_raw_format(self):
        result = format_prompt("some-model", "Hello", template_override="raw")
        assert result == "Hello"

    def test_raw_with_system(self):
        result = format_prompt("any", "Hello", system_prompt="System", template_override="raw")
        assert "System" in result
        assert "Hello" in result

    def test_explicit_override(self):
        """Template override should take priority over auto-detection"""
        result = format_prompt("mistral-7b", "Hello", template_override="chatml")
        assert "<|im_start|>" in result
        assert "[INST]" not in result

    def test_history_support(self):
        """Test multi-turn conversation handling"""
        history = [
            ChatMessage(role="user", content="First question"),
            ChatMessage(role="assistant", content="First answer"),
        ]
        result = format_prompt("phi-3", "Follow-up", history=history)
        assert "First question" in result
        assert "First answer" in result
        assert "Follow-up" in result

    def test_dict_history(self):
        """Test history as list of dicts"""
        history = [
            {"role": "user", "content": "Q1"},
            {"role": "assistant", "content": "A1"},
        ]
        result = format_prompt("phi-3", "Q2", history=history)
        assert "Q1" in result
        assert "A1" in result
        assert "Q2" in result

    def test_invalid_template_raises(self):
        with pytest.raises(ValueError, match="Unknown chat template"):
            format_prompt("model", "Hello", template_override="nonexistent_template")


# ═══════════════════════════════════════════════════════════════════
# UTILITY TESTS
# ═══════════════════════════════════════════════════════════════════

class TestGetAvailableTemplates:
    def test_returns_all_templates(self):
        templates = get_available_templates()
        assert "mistral" in templates
        assert "llama3" in templates
        assert "chatml" in templates
        assert "gemma" in templates
        assert "raw" in templates
        assert len(templates) >= 9

    def test_descriptions_are_strings(self):
        for key, desc in get_available_templates().items():
            assert isinstance(desc, str), f"Template '{key}' has non-string description"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
