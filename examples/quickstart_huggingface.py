#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HuggingFace Mistral Quickstart - Optimized for Security Testing
Fast, unlimited requests, perfect for aggressive attack testing

Usage:
    python quickstart_huggingface.py
    
Set your API key first:
    $env:HF_API_KEY = "hf_xxxxx"
"""

import asyncio
import sys
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from main import LLMSecurityTestFramework

async def main():
    """Run security tests using HuggingFace Mistral"""
    
    print("=" * 70)
    print("🚀 HuggingFace Mistral LLM Security Testing Framework")
    print("=" * 70)
    print()
    
    # Check API key
    api_key = os.getenv("HF_API_KEY")
    if not api_key:
        print("❌ HF_API_KEY not set!")
        print()
        print("Quick Setup:")
        print("  1. Get token: https://huggingface.co/settings/tokens")
        print("  2. Set in PowerShell:")
        print('     $env:HF_API_KEY = "hf_your_token"')
        print()
        print("Then run this script again.")
        return
    
    print("✅ HuggingFace API Key detected")
    print()
    
    config_path = str(Path(__file__).parent.parent / "config" / "config_huggingface.yaml")
    
    if not Path(config_path).exists():
        print(f"❌ Config file not found: {config_path}")
        return
    
    try:
        # Initialize framework with HuggingFace config
        print("📋 Loading HuggingFace configuration...")
        framework = LLMSecurityTestFramework(config_path)
        
        print("🔧 Initializing attack engine...")
        await framework.initialize()
        
        print()
        print("=" * 70)
        print("🎯 Attack Configuration")
        print("=" * 70)
        print(f"  Model: mistralai/Mistral-7B-Instruct-v0.2")
        print(f"  Target: {len(framework.config.get('targets', []))} model(s)")
        print(f"  Pool Size: {framework.config.get('execution', {}).get('pool_size', 5)} concurrent")
        print(f"  Max Concurrency: {framework.config.get('execution', {}).get('max_concurrent_attacks', 5)} attacks")
        print(f"  Timeout: 60s (includes model loading)")
        print()
        
        print("=" * 70)
        print("🔍 Running Attack Suite...")
        print("=" * 70)
        
        # Run attacks against all configured models
        test_ids = await framework.run_all_models(
            categories=None,  # Use all categories from config
            complexity_levels=None  # Use all complexity levels from config
        )
        
        print()
        print("✅ Tests completed successfully!")
        for i, test_id in enumerate(test_ids, 1):
            print(f"📄 Test {i} Report ID: {test_id}")
        print()
        print("=" * 70)
        print("📊 Reports Location")
        print("=" * 70)
        print("   Reports saved to: ./reports/")
        print()
        
        # Clean up resources
        await framework.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
