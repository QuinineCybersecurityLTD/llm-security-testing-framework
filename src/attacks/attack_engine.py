"""
Attack Engine
Manages attack template loading, execution, and multi-turn attack sequences
"""

import asyncio
import logging
import uuid
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json
import yaml

log = logging.getLogger("llm_security.attack_engine")
from jinja2.sandbox import SandboxedEnvironment

# Sandboxed Jinja2 environment — prevents template injection in attack prompts
_jinja_env = SandboxedEnvironment()
from pathlib import Path

from adapters.base import ConversationMessage
from core.orchestrator import ModelOrchestrator


class AttackCategory(Enum):
    """OWASP LLM Top 10 + additional categories"""
    PROMPT_INJECTION = "LLM-01"
    INSECURE_OUTPUT_HANDLING = "LLM-02"
    TRAINING_DATA_POISONING = "LLM-03"
    MODEL_DOS = "LLM-04"
    SUPPLY_CHAIN = "LLM-05"
    SENSITIVE_INFO_DISCLOSURE = "LLM-06"
    INSECURE_PLUGIN_DESIGN = "LLM-07"
    EXCESSIVE_AGENCY = "LLM-08"
    OVERRELIANCE = "LLM-09"
    MODEL_THEFT = "LLM-10"
    
    # Additional categories
    JAILBREAK = "JAILBREAK"
    PII_LEAKAGE = "PII-LEAKAGE"
    HALLUCINATION = "HALLUCINATION"
    BIAS_FAIRNESS = "BIAS-FAIRNESS"
    ADVERSARIAL_INPUT = "ADVERSARIAL"
    
    # Extended taxonomy (beyond OWASP Top 10)
    SSRF_VIA_LLM = "SSRF-VIA-LLM"
    MULTIMODAL_INJECTION = "MULTIMODAL-INJECTION"
    AGENT_TOOL_SECURITY = "AGENT-TOOL-SECURITY"
    SUPPLY_CHAIN_EXTENDED = "SUPPLY-CHAIN-EXT"
    PRIVACY_COMPLIANCE = "PRIVACY-COMPLIANCE"
    CROSS_SESSION_LEAKAGE = "CROSS-SESSION"
    SIDE_CHANNEL_EXTRACTION = "SIDE-CHANNEL"

    # Advanced attack categories (v3.0)
    ENCODING_BYPASS = "ENCODING-BYPASS"
    MULTILINGUAL = "MULTILINGUAL"
    MANY_SHOT = "MANY-SHOT"
    MULTI_TURN_ATTACK = "MULTI-TURN"
    HALLUCINATION_ATTACK = "HALLUCINATION-ATTACK"


class AttackComplexity(Enum):
    """Attack complexity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class AttackTemplate:
    """Single attack template definition"""
    id: str
    name: str
    description: str
    category: AttackCategory
    complexity: AttackComplexity
    
    # Attack content
    prompt_template: str
    system_prompt_override: Optional[str] = None
    
    # Multi-turn support
    is_multi_turn: bool = False
    turn_templates: List[str] = field(default_factory=list)
    
    # Template variables
    variables: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    source: str = "custom"
    tags: List[str] = field(default_factory=list)
    owasp_mapping: List[str] = field(default_factory=list)
    mitre_atlas_mapping: List[str] = field(default_factory=list)
    
    # Expected behavior
    expected_refusal: bool = True
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    
    def render_prompt(self, context: Optional[Dict[str, Any]] = None) -> str:
        """Render the prompt template with variables"""
        variables = {**self.variables, **(context or {})}
        template = _jinja_env.from_string(self.prompt_template)
        return template.render(**variables)
    
    def render_turn(self, turn_index: int, context: Optional[Dict[str, Any]] = None) -> str:
        """Render a specific turn in multi-turn attack"""
        if not self.is_multi_turn or turn_index >= len(self.turn_templates):
            raise ValueError(f"Invalid turn index {turn_index}")
        
        variables = {**self.variables, **(context or {})}
        template = _jinja_env.from_string(self.turn_templates[turn_index])
        return template.render(**variables)


@dataclass
class AttackResult:
    """Result of a single attack execution"""
    attack_id: str
    test_id: str
    timestamp: datetime
    
    # Attack details
    attack_template: AttackTemplate
    rendered_prompt: str
    system_prompt: Optional[str]
    
    # Model details
    model_id: str
    model_response: str
    
    # Performance metrics
    latency_ms: int
    tokens_used: int
    
    # Multi-turn data
    is_multi_turn: bool = False
    turn_number: int = 1
    conversation_history: List[Dict[str, str]] = field(default_factory=list)
    
    # Evaluation (populated later)
    classification: Optional[str] = None
    score: Optional[int] = None
    threat_level: Optional[str] = None
    evaluation_reasoning: Optional[str] = None
    semantic_score: Optional[float] = None
    # Compliance
    compliance_violations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging"""
        return {
            "attack_id": self.attack_id,
            "test_id": self.test_id,
            "timestamp": self.timestamp.isoformat(),
            "attack_details": {
                "name": self.attack_template.name,
                "category": self.attack_template.category.value,
                "complexity": self.attack_template.complexity.value,
                "source": self.attack_template.source,
                "owasp_mapping": self.attack_template.owasp_mapping
            },
            "input": {
                "prompt": self.rendered_prompt,
                "system_prompt": self.system_prompt,
                "is_multi_turn": self.is_multi_turn,
                "turn_number": self.turn_number
            },
            "output": {
                "response": self.model_response,
                "tokens_used": self.tokens_used,
                "latency_ms": self.latency_ms
            },
            "evaluation": {
                "classification": self.classification,
                "score": self.score,
                "threat_level": self.threat_level,
                "reasoning": self.evaluation_reasoning,
                "semantic_score": self.semantic_score
            },
            "compliance_violations": self.compliance_violations
        }


class AttackLibrary:
    """Repository for attack templates"""
    
    def __init__(self):
        self.attacks: Dict[str, AttackTemplate] = {}
        self.attacks_by_category: Dict[AttackCategory, List[AttackTemplate]] = {}
    
    def load_from_yaml(self, file_path: str) -> None:
        """Load attacks from a YAML file, supporting multiple schema versions."""
        import yaml
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            
        if data is None:
            return
            
        raw_attacks = []
        
        # Recursive helper to find actual attack configurations buried in the YAML
        def extract_attacks(node):
            if isinstance(node, list):
                for item in node:
                    extract_attacks(item)
            elif isinstance(node, dict):
                # If it has a prompt or turn_templates, it's an attack block
                if 'prompt' in node or 'prompt_template' in node or 'turn_templates' in node:
                    raw_attacks.append(node)
                else:
                    # Otherwise, keep digging deeper
                    for key, value in node.items():
                        extract_attacks(value)

        # Trigger the extraction
        extract_attacks(data)

        for item in raw_attacks:
            try:
                # Map Day 2 Test Pack keys (V2) to internal AttackTemplate keys (V1)
                attack_id = item.get('id') or item.get('test_id')
                name = item.get('name') or item.get('test_name')
                prompt_template = item.get('prompt_template') or item.get('prompt')

                # Multi-turn fallback: use first turn as prompt if no top-level prompt
                turn_templates_raw = item.get('turn_templates', [])
                if not prompt_template and turn_templates_raw:
                    prompt_template = turn_templates_raw[0]

                # Silently skip invalid blocks to avoid console spam
                if not attack_id or not name or not prompt_template:
                    continue
                
                # Handle Enums safely
                try:
                    category_val = str(item.get('category', 'PROMPT_INJECTION')).upper().replace(" ", "_")
                    # Map YAML category strings to AttackCategory enum
                    _CATEGORY_MAP = {
                        "HALLUCINATION": AttackCategory.HALLUCINATION,
                        "MISINFORMATION": AttackCategory.HALLUCINATION,
                        "JAILBREAK": AttackCategory.JAILBREAK,
                        "PII_LEAKAGE": AttackCategory.PII_LEAKAGE,
                        "LEAKAGE": AttackCategory.PII_LEAKAGE,
                        "SENSITIVE_INFO_DISCLOSURE": AttackCategory.SENSITIVE_INFO_DISCLOSURE,
                        "PROMPT_INJECTION": AttackCategory.PROMPT_INJECTION,
                        "EXCESSIVE_AGENCY": AttackCategory.EXCESSIVE_AGENCY,
                        "SSRF_VIA_LLM": AttackCategory.SSRF_VIA_LLM,
                        "MULTIMODAL_INJECTION": AttackCategory.MULTIMODAL_INJECTION,
                        "AGENT_TOOL_SECURITY": AttackCategory.AGENT_TOOL_SECURITY,
                        "SUPPLY_CHAIN_EXTENDED": AttackCategory.SUPPLY_CHAIN_EXTENDED,
                        "PRIVACY_COMPLIANCE": AttackCategory.PRIVACY_COMPLIANCE,
                        "CROSS_SESSION_LEAKAGE": AttackCategory.CROSS_SESSION_LEAKAGE,
                        "SIDE_CHANNEL_EXTRACTION": AttackCategory.SIDE_CHANNEL_EXTRACTION,
                        "DENSE_VECTOR_ATTACK": AttackCategory.ADVERSARIAL_INPUT,
                        "RERANKING_ATTACK": AttackCategory.ADVERSARIAL_INPUT,
                        # Advanced attack categories (v3.0)
                        "ENCODING_BYPASS": AttackCategory.ENCODING_BYPASS,
                        "ENCODING": AttackCategory.ENCODING_BYPASS,
                        "MULTILINGUAL": AttackCategory.MULTILINGUAL,
                        "MANY_SHOT": AttackCategory.MANY_SHOT,
                        "MULTI_TURN": AttackCategory.MULTI_TURN_ATTACK,
                        "MULTI_TURN_ATTACK": AttackCategory.MULTI_TURN_ATTACK,
                        "HALLUCINATION_ATTACK": AttackCategory.HALLUCINATION_ATTACK,
                        # OWASP short codes from YAML
                        "LLM-01": AttackCategory.PROMPT_INJECTION,
                        "LLM-02": AttackCategory.INSECURE_OUTPUT_HANDLING,
                        "LLM-03": AttackCategory.TRAINING_DATA_POISONING,
                        "LLM-04": AttackCategory.MODEL_DOS,
                        "LLM-05": AttackCategory.SUPPLY_CHAIN,
                        "LLM-06": AttackCategory.SENSITIVE_INFO_DISCLOSURE,
                        "LLM-07": AttackCategory.INSECURE_PLUGIN_DESIGN,
                        "LLM-08": AttackCategory.EXCESSIVE_AGENCY,
                        "LLM-09": AttackCategory.OVERRELIANCE,
                        "LLM-10": AttackCategory.MODEL_THEFT,
                        "BIAS-FAIRNESS": AttackCategory.BIAS_FAIRNESS,
                        "ADVERSARIAL": AttackCategory.ADVERSARIAL_INPUT,
                    }
                    category_enum = None
                    for key, val in _CATEGORY_MAP.items():
                        if key in category_val:
                            category_enum = val
                            break
                    if category_enum is None:
                        category_enum = AttackCategory.PROMPT_INJECTION
                except (KeyError, ValueError):
                    category_enum = AttackCategory.PROMPT_INJECTION

                # Multi-turn support
                is_multi_turn = bool(item.get('is_multi_turn', False))
                turn_templates = item.get('turn_templates', [])

                # For multi-turn attacks, use first turn as prompt if no top-level prompt
                if is_multi_turn and turn_templates and not prompt_template:
                    prompt_template = turn_templates[0]

                template = AttackTemplate(
                    id=attack_id,
                    name=name,
                    description=item.get('description', ''),
                    category=category_enum,
                    complexity=AttackComplexity(item.get('complexity', 'low').lower()),
                    prompt_template=prompt_template,
                    is_multi_turn=is_multi_turn,
                    turn_templates=turn_templates,
                    tags=item.get('tags', []),
                    owasp_mapping=item.get('owasp_mapping', []),
                    mitre_atlas_mapping=item.get('mitre_atlas_mapping', []),
                    expected_refusal=item.get('expected_refusal', True),
                    source=item.get('source', 'yaml'),
                )
                self.add_attack(template)
                
            except Exception as e:
                log.warning("Failed to parse attack %s: %s", item.get('id', item.get('test_id', '<unknown>')), e)    
    
    def load_from_directory(self, directory: str) -> None:
        """Load all YAML files from directory"""
        path = Path(directory)
        for yaml_file in path.glob('**/*.yaml'):
            self.load_from_yaml(str(yaml_file))
    
    def _parse_attack_dict(self, data: Dict[str, Any]) -> AttackTemplate:
        """Parse attack dictionary into AttackTemplate"""
        is_multi_turn = data.get('is_multi_turn', False)
        turn_templates = data.get('turn_templates', [])
        prompt_template = data.get('prompt_template')

        if prompt_template is None and is_multi_turn and turn_templates:
            # Multi-turn attacks may omit prompt_template; use turn 1 as canonical prompt.
            prompt_template = turn_templates[0]

        if prompt_template is None:
            attack_ref = data.get('id') or data.get('name') or '<unknown>'
            raise ValueError(
                f"Attack '{attack_ref}' is missing required field 'prompt_template' "
                "and has no usable 'turn_templates' fallback."
            )

        return AttackTemplate(
            id=data.get('id', str(uuid.uuid4())),
            name=data['name'],
            description=data['description'],
            category=AttackCategory[data['category'].upper()],
            complexity=AttackComplexity[data.get('complexity', 'MEDIUM').upper()],
            prompt_template=prompt_template,
            system_prompt_override=data.get('system_prompt_override'),
            is_multi_turn=is_multi_turn,
            turn_templates=turn_templates,
            variables=data.get('variables', {}),
            source=data.get('source', 'custom'),
            tags=data.get('tags', []),
            owasp_mapping=data.get('owasp_mapping', []),
            mitre_atlas_mapping=data.get('mitre_atlas_mapping', []),
            expected_refusal=data.get('expected_refusal', True),
            success_indicators=data.get('success_indicators', []),
            failure_indicators=data.get('failure_indicators', [])
        )
    
    def add_attack(self, attack: AttackTemplate) -> None:
        """Add attack to library"""
        self.attacks[attack.id] = attack
        
        if attack.category not in self.attacks_by_category:
            self.attacks_by_category[attack.category] = []
        self.attacks_by_category[attack.category].append(attack)
    
    def get_attack(self, attack_id: str) -> Optional[AttackTemplate]:
        """Get attack by ID"""
        return self.attacks.get(attack_id)
    
    def get_attacks_by_category(self, category: AttackCategory) -> List[AttackTemplate]:
        """Get all attacks in a category"""
        return self.attacks_by_category.get(category, [])
    
    def get_all_attacks(self) -> List[AttackTemplate]:
        """Get all attacks"""
        return list(self.attacks.values())
    
    def filter_attacks(
        self,
        categories: Optional[List[AttackCategory]] = None,
        complexity: Optional[AttackComplexity] = None,
        tags: Optional[List[str]] = None
    ) -> List[AttackTemplate]:
        """Filter attacks by criteria"""
        attacks = self.get_all_attacks()
        
        if categories:
            attacks = [a for a in attacks if a.category in categories]
        
        if complexity:
            attacks = [a for a in attacks if a.complexity == complexity]
        
        if tags:
            attacks = [a for a in attacks if any(tag in a.tags for tag in tags)]
        
        return attacks


class AttackEngine:
    """
    Core engine for executing attacks against LLM models
    Handles single-turn and multi-turn attack sequences
    """
    
    def __init__(
        self,
        orchestrator: ModelOrchestrator,
        attack_library: AttackLibrary
    ):
        self.orchestrator = orchestrator
        self.attack_library = attack_library
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
    
    async def execute_attack(
        self,
        attack_id: str,
        model_id: str,
        test_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> AttackResult:
        """Execute a single attack against a model"""
        
        attack = self.attack_library.get_attack(attack_id)
        if not attack:
            raise ValueError(f"Attack '{attack_id}' not found")
        
        test_id = test_id or str(uuid.uuid4())
        
        # Render prompt
        rendered_prompt = attack.render_prompt(context)
        system_prompt = attack.system_prompt_override
        
        # Execute
        response = await self.orchestrator.generate(
            model_id=model_id,
            prompt=rendered_prompt,
            system_prompt=system_prompt
        )
        
        # Create result
        result = AttackResult(
            attack_id=attack_id,
            test_id=test_id,
            timestamp=datetime.now(),
            attack_template=attack,
            rendered_prompt=rendered_prompt,
            system_prompt=system_prompt,
            model_id=model_id,
            model_response=response.content,
            latency_ms=response.latency_ms,
            tokens_used=response.tokens_used
        )
        
        return result
    
    async def execute_multi_turn_attack(
        self,
        attack_id: str,
        model_id: str,
        test_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        early_stop_on_refusal: bool = True,
    ) -> List[AttackResult]:
        """Execute a multi-turn attack sequence with adaptive early-stop.

        If *early_stop_on_refusal* is True and the model cleanly refuses a
        turn, remaining turns are skipped.  The last AttackResult will have
        ``early_stopped=True`` in its conversation_history metadata.
        """

        attack = self.attack_library.get_attack(attack_id)
        if not attack or not attack.is_multi_turn:
            raise ValueError(f"Attack '{attack_id}' is not a multi-turn attack")

        test_id = test_id or str(uuid.uuid4())
        results = []
        conversation_history: List[Dict[str, str]] = []

        _REFUSAL_PHRASES = [
            "i cannot", "i can't", "i won't", "i will not",
            "i must decline", "i'm not able", "not appropriate",
            "against my guidelines", "i don't feel comfortable",
            "i'm unable to", "i apologize, but",
        ]

        for turn_idx in range(len(attack.turn_templates)):
            rendered_prompt = attack.render_turn(turn_idx, context)

            conv_messages = [
                ConversationMessage(role=msg["role"], content=msg["content"])
                for msg in conversation_history
            ] or None

            response = await self.orchestrator.generate(
                model_id=model_id,
                prompt=rendered_prompt,
                system_prompt=attack.system_prompt_override,
                conversation_history=conv_messages,
            )

            conversation_history.append({"role": "user", "content": rendered_prompt})
            conversation_history.append({"role": "assistant", "content": response.content})

            result = AttackResult(
                attack_id=attack_id,
                test_id=test_id,
                timestamp=datetime.now(),
                attack_template=attack,
                rendered_prompt=rendered_prompt,
                system_prompt=attack.system_prompt_override,
                model_id=model_id,
                model_response=response.content,
                latency_ms=response.latency_ms,
                tokens_used=response.tokens_used,
                is_multi_turn=True,
                turn_number=turn_idx + 1,
                conversation_history=conversation_history.copy(),
            )
            results.append(result)

            # Adaptive early-stop: if model refused, skip remaining turns
            if early_stop_on_refusal and turn_idx > 0:
                resp_lower = response.content.lower()
                if any(p in resp_lower for p in _REFUSAL_PHRASES):
                    log.info(
                        "Early-stop: model refused at turn %d/%d for %s",
                        turn_idx + 1, len(attack.turn_templates), attack_id,
                    )
                    break

        return results
    
    async def execute_attack_batch(
        self,
        attack_ids: List[str],
        model_id: str,
        test_id: Optional[str] = None,
        max_concurrent: int = 5
    ) -> List[AttackResult]:
        """Execute multiple attacks concurrently, routing multi-turn correctly."""

        test_id = test_id or str(uuid.uuid4())
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _execute_with_semaphore(attack_id: str):
            async with semaphore:
                attack = self.attack_library.get_attack(attack_id)
                if attack and attack.is_multi_turn:
                    return await self.execute_multi_turn_attack(
                        attack_id, model_id, test_id
                    )
                return await self.execute_attack(attack_id, model_id, test_id)

        tasks = [_execute_with_semaphore(aid) for aid in attack_ids]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Flatten: multi-turn returns List[AttackResult], single returns AttackResult
        results = []
        for r in raw_results:
            if isinstance(r, list):
                results.extend(r)
            elif isinstance(r, AttackResult):
                results.append(r)
        return results
    
    async def execute_category(
        self,
        category: AttackCategory,
        model_id: str,
        test_id: Optional[str] = None
    ) -> List[AttackResult]:
        """Execute all attacks in a category"""
        
        attacks = self.attack_library.get_attacks_by_category(category)
        attack_ids = [a.id for a in attacks]
        
        return await self.execute_attack_batch(attack_ids, model_id, test_id)
