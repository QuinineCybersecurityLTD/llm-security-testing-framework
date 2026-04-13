# 🚀 Quick Start Guide - Ollama Local Setup

## Overview
You're about to run LLM security tests against your local Mistral model running on Ollama. This is completely free, unlimited, and offline-capable!

## Prerequisites ✅
- [x] Ollama downloaded and installed
- [x] Mistral model pulled: `ollama pull mistral`

## Step-by-Step Instructions

### Step 1: Start Ollama Server

Open a **new PowerShell terminal** and run:

```powershell
ollama serve
```

You should see output like:
```
2024/02/13 10:30:00 "GET /api/tags HTTP/1.1" 200 345
Listening on 127.0.0.1:11434
```

⚠️ **Keep this terminal open!** The Ollama server must stay running.

### Step 2: Run Security Tests

In a **different PowerShell terminal**, navigate to the project and run:

```powershell
cd "C:\Users\acer\Desktop\Intership@quinine\Official Work-week 4\llm-security-testing-framework"
python quickstart_ollama.py
```

### Step 3: View Results

After tests complete, open the generated reports:

```powershell
# Open the HTML report in your browser
start ".\reports\report_*.html"
```

---

## What Gets Tested?

The framework tests for:
- ✅ **Prompt Injection** - Can the model be tricked with malicious prompts?
- ✅ **Jailbreaks** - Can safety guidelines be bypassed?
- ✅ **PII Leakage** - Does it leak sensitive information?
- ✅ **Hallucinations** - Does it make up false information?

## Advanced Options

### Modify Test Config

Edit `config/config_ollama.yaml` to change:
- Attack categories to test
- Number of concurrent tests
- Model to use (llama2, mistral, neural-chat, etc.)
- Complexity levels (LOW, MEDIUM, HIGH)

### Use Different Models

Before running tests, pull another model:

```powershell
ollama pull llama2    # Llama 2
ollama pull neural-chat  # Neural Chat (good for evaluation)
ollama pull yi         # Yi model
```

Then update `config/config_ollama.yaml`:

```yaml
targets:
  - name: "my-model"
    type: "ollama"
    model_name: "neural-chat"  # Change this
    endpoint: "http://localhost:11434"
```

### Troubleshooting

**Q: "Ollama server is not running"**
- Make sure the `ollama serve` terminal is open and showing the listening message

**Q: "Model not found"**
- Run: `ollama pull mistral` (or your desired model)
- List available models: `ollama list`

**Q: Tests running slowly**
- Normal - Ollama loads the model into memory first time
- Subsequent requests are much faster
- For faster evaluation, use `neural-chat` as the judge model

**Q: Out of memory errors**
- Reduce model size in config or use `neural-chat` (3.3B) instead of `mistral` (7B)

---

## Example Output

```
======================================================================
🚀 Local Ollama Mistral - LLM Security Testing Framework
======================================================================

🔍 Checking Ollama server connectivity...
✅ Ollama server is running on http://localhost:11434

📋 Loading Ollama configuration...
🔧 Initializing attack engine...

======================================================================
🎯 Attack Configuration
======================================================================
  Provider: Ollama (Local)
  Model: Mistral 7B
  Server: http://localhost:11434
  Cost: Free & Unlimited ✨

======================================================================
🔍 Running Attack Suite...
======================================================================

   Testing prompt_injection_001: Direct Prompt Injection...
   ✅ Test passed
   
   Testing jailbreak_002: Role Play Jailbreak...
   ✅ Test passed

✅ Tests completed successfully!
📄 Test 1 Report ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890

======================================================================
📊 Reports & Results
======================================================================
   📁 HTML Reports: ./reports/report_*.html
   📁 JSON Reports: ./reports/report_*.json

🎉 All set! Open the HTML reports in your browser for detailed results.
```

---

## Next Steps

1. ✅ Start Ollama: `ollama serve`
2. ✅ Run tests: `python quickstart_ollama.py`
3. ✅ Review reports in `./reports/`
4. 📈 Analyze results and find vulnerabilities
5. 🛡️ Implement fixes based on findings

---

**Happy Testing! 🎯**
