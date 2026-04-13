"""
Shared pytest fixtures and configuration.
"""
import sys
from pathlib import Path

# Ensure src/ is importable
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))
