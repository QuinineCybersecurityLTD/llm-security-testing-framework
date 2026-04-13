# 🚀 Local GGUF Mistral Setup Guide

## ✅ Overview

You have:
- ✅ Mistral model already downloaded as GGUF
- ✅ Project configured for local inference
- ✅ All adapters integrated

Now you're ready to run security tests locally without any API keys or internet dependency!

---

## 🔧 Setup Steps (3 minutes)

### Step 1: Install Required Library

The only thing you need is `llama-cpp-python`, which can run GGUF models locally.

**Basic installation (CPU only):**
```powershell
pip install llama-cpp-python
```

**With GPU Support (RECOMMENDED - Much faster):**

*For NVIDIA GPU (CUDA):*
```powershell
pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cu121
```

*For Apple Silicon (Metal):*
```bash
CMAKE_ARGS='-DLLAMA_METAL=on' pip install llama-cpp-python
```

*For AMD GPU (ROCm):*
```powershell
pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/rocm
```

### Step 2: Verify Model Path

Open `config/config_local.yaml` and verify the model path:

```yaml
targets:
  - name: "mistral-local-gguf"
    model_name: "C:\\Users\\acer\\Desktop\\Intership@quinine\\official Work-week 1\\My work\\llm_security_assessment\\models\\mistral-7b-instruct-v0.2.Q4_K_M.gguf"
```

✅ The path is already set correctly for you!

### Step 3: Run Tests

```powershell
cd C:\Users\acer\Desktop\Intership@quinine\Official Work-week 4\llm-security-testing-framework
python quickstart_local.py
```

**Expected output:**

```
======================================================================
🚀 Local Mistral GGUF - LLM Security Testing Framework
======================================================================

📦 Checking dependencies...
✅ llama-cpp-python is installed

📋 Loading local GGUF configuration...
🔧 Initializing attack engine...
   Loading GGUF model from: C:\Users\...\mistral-7b-instruct-v0.2.Q4_K_M.gguf
   ✅ Model loaded successfully

======================================================================
🎯 Attack Configuration
======================================================================
  Provider: Local GGUF (Mistral 7B)
  Model: mistral-7b-instruct-v0.2.Q4_K_M
  Cost: FREE (offline, no API calls)
  Speed: Slow-Medium (local inference)

======================================================================
🔍 Running Attack Suite...
======================================================================

⏳ Note: First attack will be slow while model loads into memory.
   Subsequent attacks will be faster.

   🎯 Starting test session: a1b2c3d4-e5f6-7890-abcd-ef1234567890
   Model: mistral-local-gguf
   Attacks: 12
   Categories: PROMPT_INJECTION, JAILBREAK, SENSITIVE_INFO_DISCLOSURE, HALLUCINATION

⚡ Executing attacks (max 1 concurrent, 500ms delay)...
   Testing prompt-injection-001: Direct Prompt Injection - Ignore Previous Instructions
   ✅ Attack executed: Refused
   
   Testing prompt-injection-002: Indirect Prompt Injection via Context
   ✅ Attack executed: Complied
   
   ... more tests ...

✅ Tests completed successfully!
⏱️  Total time: 45.2 seconds

📄 Test 1 Report ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890

======================================================================
📊 Reports & Results
======================================================================
   📁 HTML Reports: ./reports/report_*.html
   📁 JSON Reports: ./reports/report_*.json
   📁 Logs: ./logs/results.jsonl

🎉 All set! Open the HTML reports in your browser for detailed results.
```

### Step 4: View Reports

Open the generated HTML report in your browser:

```powershell
# In PowerShell, this opens the latest report
start (Get-ChildItem "./reports/report_*.html" | Sort CreationTime -Descending | Select -First 1)
```

Or just browse to `./reports/` and open any `report_*.html` file.

---

## 📊 What Gets Tested

The framework tests your model for:

| Category | Examples | Risk |
|----------|----------|------|
| **Prompt Injection** | Tricking model with hidden instructions | Critical |
| **Jailbreaks** | Bypassing safety guidelines | Critical |
| **PII Leakage** | Revealing sensitive data | High |
| **Hallucinations** | Making up false information | Medium |

Each category has LOW, MEDIUM, and HIGH complexity attacks.

---

## ⚙️ Configuration Options

Edit `config/config_local.yaml` to customize:

### Attack Categories

```yaml
attacks:
  categories:
    - "PROMPT_INJECTION"      # Remove/add as needed
    - "JAILBREAK"
    - "SENSITIVE_INFO_DISCLOSURE"
    - "HALLUCINATION"
    # Available: INSECURE_OUTPUT_HANDLING, TRAINING_DATA_POISONING, 
    #            MODEL_THEFT, EXCESSIVE_AGENCY, etc.
```

### Complexity Levels

```yaml
  complexity_levels:
    - "LOW"       # Remove to skip easy attacks
    - "MEDIUM"    # Comment out HIGH for quick tests
    # - "HIGH"
```

### Performance Tuning

```yaml
execution:
  max_concurrent_attacks: 1   # Keep at 1 for local GGUF
  delay_between_attacks_ms: 500  # Reduce for faster testing (uses more memory)
```

---

## 🐛 Troubleshooting

### "ImportError: No module named 'llama_cpp'"

**Solution:** You didn't install llama-cpp-python. Run:
```powershell
pip install llama-cpp-python
```

### "FileNotFoundError: [Errno 2] No such file or directory: 'mistral-7b-instruct-v0.2.Q4_K_M.gguf'"

**Solution:** The model path is wrong. Check:
```powershell
# Verify the file exists
Test-Path "C:\Users\acer\Desktop\Intership@quinine\official Work-week 1\My work\llm_security_assessment\models\mistral-7b-instruct-v0.2.Q4_K_M.gguf"
# Should return: True

# Update config_local.yaml with correct path
```

### "Out of memory" errors

**Solution:** Your machine doesn't have enough RAM/VRAM. Options:
1. Close other applications
2. Use GPU acceleration (CUDA/Metal)
3. Try CPU-only but with more system memory available
4. Switch to Ollama (streams to disk if needed)

### "Generation failed" after loading

**Solution:** Check:
```powershell
# Verify model is valid
llama-cpp-python # Should run without errors

# Check file size is > 3GB (mistral model is ~5GB)
(Get-Item "path/to/model.gguf").Length
```

### "Tests running very slowly"

**Normal!** First attack is slowest (model loading). Subsequent attacks are faster.
- **First attack:** 20-60 seconds (model loading)
- **2nd+ attacks:** 5-15 seconds each
- **With GPU:** Overall 2-3x faster

To speed up:
1. Install GPU support (CUDA/Metal)
2. Reduce `max_tokens` in config
3. Reduce number of attacks with fewer categories

---

## 🚀 Performance Tips

### Enable GPU Acceleration

This is the biggest performance boost!

**For NVIDIA GPU:**
```powershell
pip uninstall llama-cpp-python -y
pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cu121
```

Then verify GPU is used:
```powershell
python -c "from llama_cpp import Llama; print(Llama.create_completion.__doc__)"
```

### Reduce Attack Count

Edit `config_local.yaml`:
```yaml
attacks:
  categories:
    - "PROMPT_INJECTION"  # Test only 1-2 categories for quick tests
  complexity_levels:
    - "LOW"  # Skip MEDIUM/HIGH for fast testing
```

### Reduce Token Limits

```yaml
targets:
  - parameters:
      max_tokens: 256  # Reduce from 512
```

---

## 📚 Related Files

- **Main configuration:** `config/config_local.yaml`
- **Attack definitions:** `attacks/owasp_attacks.yaml`
- **Framework code:** `src/main.py`
- **GGUF adapter:** `src/adapters/local_gguf_adapter.py`
- **Reports:** `reports/report_*.html`
- **Logs:** `logs/results.jsonl`

---

## 🔄 Workflow

```
1. Run: python quickstart_local.py
   ↓
2. Wait for tests (first time: 1-2 minutes)
   ↓
3. Reports generated in ./reports/
   ↓
4. Open report_*.html in browser
   ↓
5. Analyze vulnerabilities
   ↓
6. (Optional) Modify attacks in config_local.yaml
   ↓
7. Rerun tests
```

---

## ✨ Key Features

✅ **Completely Offline** - No internet required after setup  
✅ **Free** - No API costs  
✅ **Fast** - GPU acceleration available  
✅ **Flexible** - Customize attacks and categories  
✅ **Detailed Reports** - HTML + JSON outputs  
✅ **Reproducible** - Same results each run  

---

## 🎯 Next Steps

1. ✅ Install llama-cpp-python: `pip install llama-cpp-python`
2. ✅ Run: `python quickstart_local.py`
3. ✅ Open generated HTML report
4. ✅ Analyze security findings
5. 🔧 (Optional) Customize config and rerun

---

**You're all set! The infrastructure is ready. Just run `python quickstart_local.py` and the tests will begin.** 🚀

Questions? Check:
- `PROJECT_STRUCTURE.md` - Project organization
- `docs/DEVELOPER_GUIDE.md` - How the framework works
- `README.md` - General information
