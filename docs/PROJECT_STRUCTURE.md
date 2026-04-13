# 📁 Project Structure & Organization Guide

## Directory Layout

```
llm-security-testing-framework/
│
├── 🚀 QUICKSTART SCRIPTS (Choose based on your setup)
│   ├── quickstart_local.py          ← Local GGUF Mistral (⭐ YOUR SETUP)
│   ├── quickstart_ollama.py         ← Ollama local models
│   ├── quickstart_gemini.py         ← Google Gemini (free)
│   └── quickstart_huggingface.py    ← HuggingFace (deprecated endpoints)
│
├── 📋 CONFIGURATION
│   └── config/
│       ├── config_local.yaml        ← Local GGUF settings (⭐ YOUR SETUP)
│       ├── config_ollama.yaml       ← Ollama settings
│       ├── config_gemini.yaml       ← Gemini settings
│       ├── config_huggingface.yaml  ← HuggingFace settings
│       ├── config.yaml              ← Default config
│       └── test_suites.yaml         ← Test suite definitions
│
├── 🔧 SOURCE CODE
│   └── src/
│       ├── main.py                  ← Framework entry point
│       ├── orchestrator.py          ← Model orchestrator
│       ├── attack_engine.py         ← Attack execution engine
│       ├── evaluator.py             ← Result evaluation
│       ├── reporter.py              ← Report generation
│       ├── telemetry.py             ← Metrics & logging
│       │
│       └── adapters/
│           ├── base.py              ← Adapter interface
│           ├── local_gguf_adapter.py    ← Local GGUF (⭐ NEW)
│           ├── ollama_adapter.py    ← Ollama
│           ├── gemini_adapter.py    ← Google Gemini
│           ├── openai_adapter.py    ← OpenAI
│           ├── anthropic_adapter.py ← Anthropic
│           ├── huggingface_adapter.py ← HuggingFace
│           └── promptintel_adapter.py
│
├── 🎯 ATTACK DEFINITIONS
│   └── attacks/
│       └── owasp_attacks.yaml       ← Attack library
│
├── 📚 DOCUMENTATION
│   ├── OLLAMA_QUICKSTART.md         ← Ollama setup guide
│   ├── LOCAL_GGUF_SETUP.md          ← Local GGUF guide (⭐ NEW)
│   ├── PROJECT_STRUCTURE.md         ← This file
│   ├── README.md                    ← Main readme
│   ├── docs/
│   │   ├── QUICKSTART.md           ← General quickstart
│   │   ├── SETUP.md                ← Detailed setup
│   │   ├── API_KEYS.md             ← API key configs
│   │   ├── BATCH_TESTING.md        ← Batch testing
│   │   ├── DEVELOPER_GUIDE.md      ← Dev guide
│   │   └── THREAT_MODEL.md         ← Security model
│   │
│   └── examples/
│       └── examples_batch_testing.py
│
├── 📊 OUTPUT DIRECTORIES (Auto-created)
│   ├── reports/                    ← HTML & JSON reports
│   ├── logs/                       ← Execution logs
│   └── src/reports/ & src/logs/    ← Backup locations
│
├── 📦 DEPENDENCIES
│   ├── requirements.txt             ← Python dependencies
│   ├── requirements-local.txt       ← Additional for local GGUF
│   ├── requirements-gpu.txt         ← GPU acceleration
│   └── Dockerfile                  ← Docker setup
│
└── 🔗 OTHER FILES
    ├── README.md
    ├── CHANGELOG.md
    ├── PROJECT_STATUS.md
    ├── api.txt
    └── [other docs...]
```

---

## 🎯 Quick Start Guide by Setup Type

### ⭐ Your Setup: Local GGUF Mistral

**Status:** ✅ Ready to use immediately

```bash
# 1. Install dependencies
pip install -r requirements.txt
pip install llama-cpp-python

# 2. Run the local quickstart
python quickstart_local.py

# 3. Check reports
# Reports will be generated in ./reports/report_*.html
```

**Config file:** `config/config_local.yaml`  
**Model location:** `C:\Users\acer\Desktop\Intership@quinine\official Work-week 1\My work\llm_security_assessment\models\mistral-7b-instruct-v0.2.Q4_K_M.gguf`

---

### Alternative Setup: Ollama

**Status:** ✅ Also configured

```bash
# 1. Install & start Ollama
ollama serve

# 2. In another terminal
ollama pull mistral
python quickstart_ollama.py
```

**Config file:** `config/config_ollama.yaml`

---

### Alternative Setup: Google Gemini

**Status:** ✅ Configured

```bash
# 1. Get free API key from https://ai.google.dev/pricing

# 2. Set environment variable
$env:GEMINI_API_KEY = "your_key"

# 3. Run
python quickstart_gemini.py
```

**Config file:** `config/config_gemini.yaml`

---

## 📋 File Organization Logic

### Quickstart Scripts (`*.py` at root)
- **Purpose:** Entry points for different setups
- **Who uses:** End users/testers
- **Action:** Choose ONE based on your setup
- **Examples:**
  - `quickstart_local.py` - Local models ⭐
  - `quickstart_ollama.py` - Ollama servers
  - `quickstart_gemini.py` - Cloud APIs

### Configuration Files (`config/`)
- **Purpose:** Define model setup, attack categories, execution params
- **Who uses:** Framework, quickstart scripts
- **Format:** YAML for readability
- **Examples:**
  - `config_local.yaml` - Local GGUF paths and settings
  - `config_ollama.yaml` - Ollama endpoints
  - `config_gemini.yaml` - API keys and models

### Adapters (`src/adapters/`)
- **Purpose:** Model-specific integrations
- **Who uses:** Orchestrator (internal)
- **Logic:**
  - `base.py` - Interface all adapters implement
  - `*_adapter.py` - Specific model implementations
  - `local_gguf_adapter.py` - Your local setup ⭐

### Attack Library (`attacks/`)
- **Purpose:** Define security test cases
- **Format:** YAML (easy to modify)
- **Examples:** Prompt injection, jailbreaks, PII leakage

### Reports & Logs (Auto-created)
- **Purpose:** Test results and execution details
- **Location:** `./reports/` and `./logs/`
- **Formats:** HTML (visual), JSON (data), JSONL (logs)

---

## 🔄 Data Flow

```
┌─────────────────┐
│ quickstart_local│ (Entry point)
└────────┬────────┘
         │
         ▼
┌──────────────────────┐
│ config_local.yaml    │ (Load settings)
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│ LLM SecurityTest     │
│ Framework (main.py)  │ (Initialize)
└────────┬─────────────┘
         │
         ├────► Orchestrator (Register models)
         │        │
         │        └─► LocalGGUFAdapter (Load model)
         │
         ├────► AttackEngine (Load attacks from attacks/)
         │
         └────► EvaluationPipeline (Evaluate results)
                 │
                 ▼
         Reporter (Generate HTML & JSON)
                 │
                 ▼
          ./reports/report_*.html
          ./reports/report_*.json
          ./logs/results.jsonl
```

---

## 🛠️ Key Files for Your Setup

| File | Purpose | Action |
|------|---------|--------|
| `quickstart_local.py` | Entry point for local GGUF | Run this ← |
| `config/config_local.yaml` | Settings for your model | Edit if path changes |
| `src/adapters/local_gguf_adapter.py` | GGUF model interface | Use as-is |
| `src/main.py` | Framework logic | Use as-is |
| `attacks/owasp_attacks.yaml` | Test cases | Customize if needed |

---

## 📊 Output Files Explained

After running tests, you'll find:

```
reports/
├── report_a1b2c3d4-e5f6-7890-abcd-ef1234567890.html  ← Open in browser
├── report_a1b2c3d4-e5f6-7890-abcd-ef1234567890.json  ← Raw data
├── report_x1y2z3w4-q5r6-7890-abcd-ef1234567890.html
└── report_x1y2z3w4-q5r6-7890-abcd-ef1234567890.json

logs/
└── results.jsonl  ← Execution log (one JSON per line)
```

### Report Contents:
- **Attacks tested** - Categories and complexity levels
- **Compliance scores** - Refusal, partial, full compliance percentages
- **Vulnerabilities found** - Specific attack successes
- **Response analysis** - Model behavior details
- **Execution metrics** - Duration, latency, token counts

---

## ✨ All Available Quickstarts

| Script | Setup | Speed | Cost | Best For |
|--------|-------|-------|------|----------|
| `quickstart_local.py` | ⭐ Local GGUF | Medium | FREE | Your use case |
| `quickstart_ollama.py` | Local (via Ollama) | Medium | FREE | Flexibility |
| `quickstart_gemini.py` | Google Cloud | Fast | FREE tier | Quick tests |
| `quickstart_huggingface.py` | HuggingFace API | Fast | FREE | Testing APIs |
| `examples_batch_testing.py` | Advanced | - | Varies | Multiple configs |

---

## 🚀 Next Steps

1. ✅ Run: `python quickstart_local.py`
2. ⏳ Wait for tests to complete
3. 📊 Open `reports/report_*.html` in browser
4. 📈 Analyze results
5. 🔧 Modify `config/config_local.yaml` if needed
6. 🎯 Rerun tests with different settings

---

## 📝 Notes

- **Model file path:** Already configured in `config_local.yaml`
- **GPU support:** Optional - install `llama-cpp-python[gpu]` for faster inference
- **Memory:** Q4_K_M quantization uses ~6GB GPU/CPU memory
- **First run:** Slower as model loads; subsequent runs faster
- **Customization:** Edit `config_local.yaml` to change test categories/complexity

---

**Your project is now organized and ready to go! Run `python quickstart_local.py` to start testing.** 🎉
