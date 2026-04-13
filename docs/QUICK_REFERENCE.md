# ⚡ Quick Reference - Local GGUF Setup

## 🎯 What Was Set Up For You

| Component | Details | Status |
|-----------|---------|--------|
| **Model** | Mistral 7B (Q4_K_M quantization) | ✅ Ready |
| **Adapter** | `local_gguf_adapter.py` | ✅ Created |
| **Configuration** | `config/config_local.yaml` | ✅ Created |
| **Quickstart** | `quickstart_local.py` | ✅ Created |
| **Documentation** | `LOCAL_GGUF_SETUP.md` | ✅ Created |
| **Project Structure** | `PROJECT_STRUCTURE.md` | ✅ Organized |

---

## 🚀 3-Step Quick Start

### 1. Install Dependency
```powershell
pip install llama-cpp-python
```

### 2. Run Tests
```powershell
cd "C:\Users\acer\Desktop\Intership@quinine\Official Work-week 4\llm-security-testing-framework"
python quickstart_local.py
```

### 3. View Results
```powershell
# Reports in ./reports/report_*.html
start (Get-ChildItem "./reports/report_*.html" | Sort CreationTime -Descending | Select -First 1)
```

---

## 📁 Key Files Created/Modified

### New Files Created ✨
- `src/adapters/local_gguf_adapter.py` - GGUF model handler
- `config/config_local.yaml` - Configuration for your setup
- `quickstart_local.py` - Main entry point
- `LOCAL_GGUF_SETUP.md` - This setup guide
- `PROJECT_STRUCTURE.md` - Project organization
- `requirements-local.txt` - Dependencies

### Updated/Enhanced Files
- `src/adapters/base.py` - Added LOCAL_GGUF model type
- `src/orchestrator.py` - Registered GGUF adapter

### Model File Location 📁
```
C:\Users\acer\Desktop\Intership@quinine\official Work-week 1\My work\llm_security_assessment\models\mistral-7b-instruct-v0.2.Q4_K_M.gguf
```
✅ Already configured in `config_local.yaml`

---

## 🔧 Configuration Details

**Model Setup:**
```yaml
type: local_gguf                    # Model type
model_name: C:\path\to\mistral...  # GGUF file path (already set)
```

**Inference Settings:**
```yaml
temperature: 0.7      # Creative responses
max_tokens: 512       # Max response length
top_p: 0.95          # Diversity
timeout: 120         # seconds
```

**Execution Settings:**
```yaml
max_concurrent_attacks: 1    # Sequential (required for local)
pool_size: 1                 # Single thread
delay_between_attacks_ms: 500
```

---

## 📊 What Tests Run

The framework tests for:
- ✅ **Prompt Injection** - Can hidden commands override system instructions?
- ✅ **Jailbreaks** - Can safety guidelines be bypassed?
- ✅ **PII Leakage** - Does it reveal personal/sensitive data?
- ✅ **Hallucinations** - Does it make up false information?

**Complexity levels:**
- LOW - Basic, obvious attacks
- MEDIUM - Subtle, indirect attacks
- HIGH - Advanced, complex attacks

---

## 💾 Output Files

After running `python quickstart_local.py`, you'll have:

```
reports/
├── report_UUID.html     ← Open in browser (visual report)
└── report_UUID.json     ← Raw data (machine-readable)

logs/
└── results.jsonl        ← Execution log (one JSON per line)
```

**Report contains:**
- Attack categories tested
- Compliance scores (refused %, partial %, full %)
- Specific vulnerabilities found
- Model responses to each attack
- Execution metrics (latency, tokens, duration)

---

## ⚡ Performance Tips

### GPU Acceleration (Recommended)

**Before (CPU):** ~10-15 sec per attack  
**After (GPU):** ~2-3 sec per attack  

**Set up GPU support:**

*NVIDIA CUDA:*
```powershell
pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cu121
```

*Apple Silicon Metal:*
```bash
CMAKE_ARGS='-DLLAMA_METAL=on' pip install llama-cpp-python
```

### Quick Tests (Skip High Complexity)

Edit `config_local.yaml`:
```yaml
complexity_levels:
  - "LOW"
  # - "MEDIUM"  # Comment out
  # - "HIGH"    # Comment out
```

---

## 🐛 Common Issues

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: llama_cpp` | `pip install llama-cpp-python` |
| `FileNotFoundError` on model | Check path in `config_local.yaml` |
| "Out of memory" | Use GPU or close other apps |
| Very slow tests | Install GPU support |
| Port already in use | Not applicable (no server) |

---

## 📚 Documentation Files

| File | Purpose |
|------|---------|
| `LOCAL_GGUF_SETUP.md` | Detailed setup guide (start here) |
| `PROJECT_STRUCTURE.md` | Project organization & all quickstarts |
| `quickstart_local.py` | Main script (execute this) |
| `config/config_local.yaml` | Settings (customize this) |
| `README.md` | General framework info |
| `docs/DEVELOPER_GUIDE.md` | How it works internally |

---

## 🔄 Typical Workflow

```
1. python quickstart_local.py
   │
2. ⏳ Loading model... (10-30 seconds)
   │
3. 🔍 Running attacks... (5-10 minutes depending on count)
   │
4. ✅ Tests complete
   │
5. 📊 Open reports/report_*.html in browser
   │
6. 📈 Analyze vulnerabilities
   │
7. (Optional) Customize config & rerun
```

---

## ✅ Verification Checklist

Before running, verify:

- [x] Model file exists at configured path
- [x] Python 3.9+ installed (`python --version`)
- [x] Dependencies installed (`pip list | grep llama`)
- [x] Config path is correct
- [ ] Enough disk space for reports (~10MB per run)
- [ ] (Optional) GPU drivers installed for acceleration

---

## 🎯 Next Actions

### Immediate (2 minutes)
1. Install: `pip install llama-cpp-python`
2. Run: `python quickstart_local.py`
3. Wait for completion

### After Tests (5 minutes)
1. Open generated HTML report
2. Review findings
3. Note vulnerabilities

### Further Exploration (30+ minutes)
1. Modify `config_local.yaml` to change tests
2. Add custom attacks to `attacks/owasp_attacks.yaml`
3. Run specific categories only
4. Experiment with different complexity levels

---

## 📞 Support Resources

- **Setup issues**: Read `LOCAL_GGUF_SETUP.md` troubleshooting section
- **Framework questions**: Check `docs/DEVELOPER_GUIDE.md`
- **Report interpretation**: See `reports/report_*.html` (self-documenting)
- **Adding attacks**: Read `docs/IMPLEMENTATION_GUIDE.md`

---

## 🎉 Summary

**You have everything you need:**
1. ✅ Local GGUF adapter built
2. ✅ Configuration ready
3. ✅ Quickstart script provided
4. ✅ Model path already set
5. ✅ Documentation complete

**Just run:** 
```powershell
python quickstart_local.py
```

**That's it! The framework will handle the rest.** 🚀
