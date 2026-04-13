#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Google Gemini Quickstart - Free & Reliable
Uses Google's free Gemini API for security testing

Usage:
    python quickstart_gemini.py
    
Get your API key:
    1. Visit: https://ai.google.dev/pricing
    2. Click "Get API Key" 
    3. Create a new Google project
    4. Copy your API key and set it:
    $env:GEMINI_API_KEY = "your_key_here"
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
    """Run security tests using Google Gemini"""
    
    print("=" * 70)
    print("🚀 Google Gemini LLM Security Testing Framework")
    print("=" * 70)
    print()
    
    # Check API key
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("❌ GEMINI_API_KEY not set!")
        print()
        print("Quick Setup:")
        print("  1. Visit: https://ai.google.dev/pricing")
        print("  2. Click 'Get API Key'")
        print("  3. Create a new Google Cloud project (free)")
        print("  4. Set in PowerShell:")
        print('     $env:GEMINI_API_KEY = "your_key_here"')
        print()
        print("Then run this script again.")
        return
    
    print("✅ Google Gemini API Key detected")
    print()
    
    config_path = str(Path(__file__).parent.parent / "config" / "config_gemini.yaml")
    
    if not Path(config_path).exists():
        print(f"❌ Config file not found: {config_path}")
        return
    
    try:
        # Initialize framework with Gemini config
        print("📋 Loading Google Gemini configuration...")
        framework = LLMSecurityTestFramework(config_path)
        
        print("🔧 Initializing attack engine...")
        await framework.initialize()
        
        print()
        print("=" * 70)
        print("🎯 Attack Configuration")
        print("=" * 70)
        print(f"  Provider: Google Gemini (Free tier)")
        print(f"  Targets: {len(framework.config.get('targets', []))} model(s)")
        print(f"  Pool Size: {framework.config.get('execution', {}).get('pool_size', 5)} concurrent")
        print(f"  Max Concurrency: {framework.config.get('execution', {}).get('max_concurrent_attacks', 5)} attacks")
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
