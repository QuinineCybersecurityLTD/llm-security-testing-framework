"""Behavioral analysis modules — evaluation awareness, agentic sabotage, CoT deception."""
from .evaluation_awareness import EvaluationAwarenessDetector, EvaluationAwarenessReport
from .agentic_sabotage import AgenticSabotageDetector, SabotageReport
from .cot_deception import CoTDeceptionAnalyzer, CoTDeceptionReport
from .reward_hacking import RewardHackingDetector, RewardHackingReport

__all__ = [
    "EvaluationAwarenessDetector", "EvaluationAwarenessReport",
    "AgenticSabotageDetector", "SabotageReport",
    "CoTDeceptionAnalyzer", "CoTDeceptionReport",
    "RewardHackingDetector", "RewardHackingReport",
]
