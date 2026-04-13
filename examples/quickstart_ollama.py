#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ollama Local Model Quickstart - Free & Unlimited
Runs security tests against locally hosted Llama2 model

Prerequisites:
    1. Download Ollama: https://ollama.ai
    2. Start Ollama server: ollama serve
    3. Pull model: ollama pull llama2
    4. Run this script

Usage:
    python quickstart_ollama.py
"""

import asyncio
import sys
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
import os
from pathlib import Path
import time
import urllib.request

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from main import LLMSecurityTestFramework

async def check_ollama_connectivity():
    """Check if Ollama server is running"""
    print("🔍 Checking Ollama server connectivity...")
    
    for attempt in range(5):
        try:
            urllib.request.urlopen("http://localhost:11434", timeout=2)
            print("✅ Ollama server is running on http://localhost:11434")
            return True
        except Exception:
            if attempt < 4:
                print(f"   ⏳ Ollama not accessible yet... (attempt {attempt + 1}/5)")
                await asyncio.sleep(2)
            else:
                print("❌ Ollama server is not running!")
                print()
                print("To start Ollama:")
                print("  1. Open a new PowerShell terminal")
                print("  2. Run: ollama serve")
                print("  3. Wait for the server to start")
                print("  4. Then run this script again")
                return False

async def main():
    """Run security tests using local Ollama Mistral model"""
    
    print("=" * 70)
    print("🚀 Local Ollama gpt-oss - LLM Security Testing Framework")
    print("=" * 70)
    print()
    
    # Check Ollama connectivity
    if not await check_ollama_connectivity():
        return 1
    
    print()
    
    config_path = str(Path(__file__).parent.parent / "config" / "config_ollama.yaml")
    
    if not Path(config_path).exists():
        print(f"❌ Config file not found: {config_path}")
        return
    
    try:
        # Initialize framework with Ollama config
        print("📋 Loading Ollama configuration...")
        framework = LLMSecurityTestFramework(config_path)
        
        print("🔧 Initializing attack engine...")
        await framework.initialize()
        
        print()
        print("=" * 70)
        print("🎯 Attack Configuration")
        print("=" * 70)
        print(f"  Server: http://localhost:11434")
        print(f"  Targets: {len(framework.config.get('targets', []))} model(s)")
        print(f"  Pool Size: {framework.config.get('execution', {}).get('pool_size', 5)} concurrent")
        print(f"  Max Concurrency: {framework.config.get('execution', {}).get('max_concurrent_attacks', 5)} attacks")
        print(f"  Speed: Fast (no API latency)")
        print(f"  Cost: Free & Unlimited ✨")
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
        print("📊 Reports & Results")
        print("=" * 70)
        print("   📁 HTML Reports: ./reports/report_*.html")
        print("   📁 JSON Reports: ./reports/report_*.json")
        print("   📁 Logs: ./logs/")
        print()
        
        # Clean up resources
        await framework.close()
        
        print("🎉 All set! Open the HTML reports in your browser for detailed results.")
        print()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
