#!/usr/bin/env python3
"""
Quick Start Script for LLM Security Testing Framework
Helps users set up and run their first test
"""

import os
import sys
import subprocess
from pathlib import Path


def print_header(text):
    """Print formatted header"""
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60 + "\n")


def check_python_version():
    """Verify Python version"""
    if sys.version_info < (3, 9):
        print("❌ Python 3.9+ required")
        sys.exit(1)
    print("✅ Python version OK")


def check_dependencies():
    """Check if dependencies are installed"""
    try:
        import aiohttp
        import yaml
        import jinja2
        print("✅ Core dependencies installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        return False


def prompt_for_provider():
    """Ask user which provider they want to use"""
    print("\nWhich provider would you like to test with?")
    print("1. Google Gemini (FREE - Recommended for beginners)")
    print("2. Ollama (FREE - Local models on your machine)")
    print("3. Other (OpenAI, Anthropic, etc.)")
    
    choice = input("\nEnter 1, 2, or 3: ").strip()
    return choice


def setup_gemini():
    """Setup for Gemini"""
    print_header("Google Gemini Setup")
    print("""
1. Visit: https://ai.google.dev/pricing
2. Click "Get API Key"
3. Create a new Google Cloud project
4. Generate and copy your API key
5. Paste it below
    """)
    
    api_key = input("Enter your Gemini API key: ").strip()
    
    if api_key:
        os.environ["GEMINI_API_KEY"] = api_key
        print("✅ API key set")
        return "config/config_gemini.yaml"
    else:
        print("❌ No API key provided")
        return None


def setup_ollama():
    """Setup for Ollama"""
    print_header("Ollama Local Setup")
    print("""
1. Download Ollama from: https://ollama.ai
2. Install and run: ollama serve
3. In another terminal, pull a model:
   - ollama pull llama2
   - ollama pull mistral
   - ollama pull neural-chat
4. Run the framework
    """)
    
    # Check if Ollama is running
    try:
        response = subprocess.run(
            ["curl", "-s", "http://localhost:11434/api/tags"],
            capture_output=True,
            timeout=5
        )
        if response.returncode == 0:
            print("✅ Ollama is running")
            return "config/config_ollama.yaml"
        else:
            print("❌ Ollama is not running")
            print("   Start it with: ollama serve")
            return None
    except Exception as e:
        print(f"⚠️  Cannot verify Ollama: {e}")
        print("   Make sure Ollama is running and accessible at http://localhost:11434")
        return "config/config_ollama.yaml"


def setup_other():
    """Setup for other providers"""
    print_header("Other Providers Setup")
    print("""
Available configurations:
- config/config.yaml for OpenAI/Anthropic
- See docs/API_KEYS.md for detailed setup

For now, let's use Gemini as it's easiest to get started:
    """)
    return setup_gemini()


def run_test(config_path):
    """Run the test framework"""
    print_header("Running Security Test")
    print(f"Using config: {config_path}\n")
    
    try:
        result = subprocess.run(
            [sys.executable, "src/main.py", "--config", config_path],
            cwd=Path(__file__).parent
        )
        
        if result.returncode == 0:
            print("\n✅ Test completed successfully!")
            print("\nReports generated in:")
            print("  - reports/report_*.html")
            print("  - reports/report_*.json")
            return True
        else:
            print("\n❌ Test failed")
            return False
    except Exception as e:
        print(f"\n❌ Error running test: {e}")
        return False


def main():
    """Main quick start flow"""
    print_header("LLM Security Testing Framework - Quick Start")
    
    # Check environment
    print("Checking environment...")
    check_python_version()
    
    if not check_dependencies():
        print("\nInstalling dependencies...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        if not check_dependencies():
            print("❌ Failed to install dependencies")
            sys.exit(1)
    
    # Choose provider
    choice = prompt_for_provider()
    
    if choice == "1":
        config_path = setup_gemini()
    elif choice == "2":
        config_path = setup_ollama()
    else:
        config_path = setup_other()
    
    if not config_path:
        print("\n❌ Setup failed")
        sys.exit(1)
    
    # Run test
    if run_test(config_path):
        print("\n📚 For more details, see:")
        print("  - docs/SETUP.md - Complete setup guide")
        print("  - docs/API_KEYS.md - API key setup")
        print("  - docs/IMPLEMENTATION_GUIDE.md - Technical details")
    else:
        print("\n🆘 Need help? Check docs/SETUP.md")


if __name__ == "__main__":
    main()
