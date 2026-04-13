#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick Start Script for Prompt Intel + Local Model Testing
Simplest way to get started with security testing your local model
"""

import asyncio
import os
import sys
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# NOTE: orchestrator_promptintel_local is legacy code, moved to archive/legacy_code/
# For new testing, use main.py with a promptintel config instead
sys.path.insert(0, str(Path(__file__).parent.parent / "archive" / "legacy_code"))
from orchestrator_promptintel_local import PromptIntelLocalTester


def check_prerequisites():
    """Check if all prerequisites are met"""
    print("🔍 Checking prerequisites...")
    
    issues = []
    
    # Check Prompt Intel API key
    api_key = os.getenv('PROMPTINTEL_API_KEY')
    if not api_key:
        issues.append(
            "⚠️  PROMPTINTEL_API_KEY environment variable not set\n"
            "   → Set it with: $env:PROMPTINTEL_API_KEY = 'your-key-here'\n"
            "   → Or update config/config_promptintel_local.yaml"
        )
    else:
        print("   ✅ Prompt Intel API key found")
    
    # Check config file
    config_path = Path(__file__).parent.parent / "config" / "config_promptintel_local.yaml"
    if not config_path.exists():
        issues.append(f"❌ Config file not found: {config_path}")
    else:
        print("   ✅ Config file found")
    
    # Check local model file
    config_path = Path(__file__).parent.parent / "config" / "config_promptintel_local.yaml"
    if config_path.exists():
        import yaml
        with open(config_path) as f:
            config = yaml.safe_load(f)
        model_path = config.get('target_model', {}).get('model_name')
        if model_path and not Path(model_path).exists():
            issues.append(
                f"❌ Local model not found at: {model_path}\n"
                f"   → Update the path in config/config_promptintel_local.yaml"
            )
        elif model_path:
            print("   ✅ Local model file found")
    
    if issues:
        print("\n❌ Issues found:")
        for issue in issues:
            print(f"\n{issue}")
        return False
    
    print("\n✅ All prerequisites met!")
    return True


async def main():
    """Main entry point"""
    print("=" * 70)
    print("🚀 Prompt Intel + Local Model Security Testing")
    print("=" * 70)
    print()
    
    # Check prerequisites
    if not check_prerequisites():
        print("\n⚠️  Please fix the issues above and try again.")
        return
    
    print("\n" + "=" * 70)
    print("Starting test suite...")
    print("=" * 70)
    print()
    
    try:
        # Initialize tester
        tester = PromptIntelLocalTester()
        
        # Run test suite
        test_id = await tester.run_test_suite()
        
        print("\n" + "=" * 70)
        print("✅ Test Completed Successfully!")
        print("=" * 70)
        print(f"\nTest ID: {test_id}")
        print("\n📁 Output files:")
        print(f"   - Reports: ./reports/report_{test_id}.*")
        print(f"   - Raw Results: ./logs/test_{test_id}_results.json")
        print("\n📖 View the HTML report for detailed analysis")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        print("\nFor help, check: docs/PROMPTINTEL_LOCAL_SETUP.md")
        sys.exit(1)
    finally:
        if 'tester' in locals():
            await tester.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
