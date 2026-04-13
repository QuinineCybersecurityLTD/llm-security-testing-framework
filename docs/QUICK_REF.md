# Quick Reference - Batch Testing Commands

## 🎯 Three Testing Modes

### 1️⃣ SINGLE MODEL TEST (5-10 min)
```bash
# Test default model (Gemini)
python src/main.py

# Test specific model
python src/main.py --model=gemini-flash

# With options
python src/main.py \
  --model=llama-local \
  --categories=PROMPT_INJECTION,JAILBREAK \
  --complexity=LOW,MEDIUM
```

### 2️⃣ ALL MODELS TEST (10-30 min)
```bash
# Test every model in your config with same settings
python src/main.py --mode=all

# With options
python src/main.py --mode=all \
  --categories=PROMPT_INJECTION \
  --complexity=LOW
```

### 3️⃣ BATCH TEST SUITE (30-120 min)
```bash
# Run predefined test suites against all models
python src/main.py --mode=batch

# With specific config
python src/main.py --mode=batch \
  --config=config/config_promptintel.yaml
```

---

## 🔥 Quick Examples

### Example 1: Quick Validation (5 min)
```bash
python src/main.py --mode=all --complexity=LOW --categories=PROMPT_INJECTION
```
✅ Best for: CI/CD pipelines, quick checks  
⏱️ Time: 5-10 minutes  
💰 Cost: Minimal  

### Example 2: Provider Comparison (20 min)
```bash
# Test Gemini
python src/main.py --mode=all --config=config/config_gemini.yaml

# Then test Ollama
python src/main.py --mode=all --config=config/config_ollama.yaml

# Compare reports in: reports/
```
✅ Best for: Choosing between providers  
⏱️ Time: 20-30 minutes  
💰 Cost: $0-$1  

### Example 3: Comprehensive Audit (60 min)
```bash
python src/main.py --mode=batch
```
✅ Best for: Production security assessment  
⏱️ Time: 45-90 minutes  
💰 Cost: $0-$5 (depending on provider)  

### Example 4: Prompt Intelligence Testing (30 min)
```bash
python src/main.py --mode=batch --config=config/config_promptintel.yaml
```
✅ Best for: Professional security research  
⏱️ Time: 20-40 minutes  
💰 Cost: Varies by Promptintel plan  

### Example 5: Local Only Testing (∞ minutes)
```bash
# Unlimited free testing with local Ollama
python src/main.py --mode=batch --config=config/config_ollama.yaml
```
✅ Best for: Development, unlimited testing  
⏱️ Time: Any amount (you control it)  
💰 Cost: $0  

---

## 📊 Output Comparison

### Single Test
```
One model
├── report_[test-id].html
└── report_[test-id].json
```

### All Models  
```
Multiple models, same config
├── report_[test-id-1].html    (model 1)
├── report_[test-id-2].html    (model 2)
├── report_[test-id-3].html    (model 3)
└── comparison_report.html     (side-by-side)
```

### Batch Test Suite
```
Multiple configs × multiple models
├── suite1_model1_report_[id].html
├── suite1_model2_report_[id].html
├── suite2_model1_report_[id].html
├── suite2_model2_report_[id].html
└── batch_summary_report.html
```

---

## ⚡ Pro Tips

### 💡 Tip 1: Use Ollama for Development
```bash
# Unlimited, free testing while developing
ollama pull llama2
python src/main.py --mode=batch --config=config/config_ollama.yaml
```

### 💡 Tip 2: Stagger API Tests
```bash
# Avoid hitting rate limits
python src/main.py --mode=all --complexity=LOW  # Morning
# ... do other work ...
python src/main.py --mode=all --complexity=MEDIUM  # Afternoon
# ... do other work ...
python src/main.py --mode=all --complexity=HIGH   # Evening
```

### 💡 Tip 3: Create Test Combinations
```yaml
# config/test_suites.yaml
test_suites:
  - name: "Morning Quick Check"
    complexity_levels: ["LOW"]
    
  - name: "Afternoon Detailed Test"
    complexity_levels: ["LOW", "MEDIUM"]
    
  - name: "Evening Full Audit"
    complexity_levels: ["LOW", "MEDIUM", "HIGH"]
```

### 💡 Tip 4: Reuse Results
```bash
# Keep old reports for trending
mkdir -p reports/archive
cp reports/report_*.html reports/archive/$(date +%Y%m%d)/

# Later, compare old vs new
# Look for improvements or regressions
```

### 💡 Tip 5: Monitor Performance
```bash
# Check logs for latency trends
grep "latency" logs/results.jsonl | tail -20

# Export to CSV for analysis
python -c "
import json
for line in open('logs/results.jsonl'):
    data = json.loads(line)
    print(f\"{data['attack_details']['name']},{data['output']['latency_ms']}\")
" > metrics.csv
```

---

## 🎯 Decision Tree

```
Want to test?
│
├─ One model, quick? 
│  └─► python src/main.py
│
├─ All registered models?
│  √─ Same complexity?
│  │  └─► python src/main.py --mode=all
│  √─ Different complexities?
│     └─► Edit test_suites.yaml
│
├─ Total control over test scenarios?
│  └─► python src/main.py --mode=batch
│
├─ Unlimited free testing?
│  └─► python src/main.py --config=config/config_ollama.yaml
│
└─ Professional security research?
   └─► python src/main.py --config=config/config_promptintel.yaml
```

---

## 📋 Command Cheat Sheet

| Goal | Command |
|------|---------|
| Quick test | `python src/main.py` |
| All models | `python src/main.py --mode=all` |
| Batch suite | `python src/main.py --mode=batch` |
| Specific model | `python src/main.py --model=NAME` |
| Specific config | `python src/main.py --config=PATH` |
| LOW only | `python src/main.py --complexity=LOW` |
| Specific category | `python src/main.py --categories=PROMPT_INJECTION` |
| Multiple categories | `python src/main.py --categories=CAT1,CAT2,CAT3` |
| Local Ollama | `python src/main.py --config=config/config_ollama.yaml` |
| Promptintel | `python src/main.py --config=config/config_promptintel.yaml` |

---

## 🚀 Getting Started (Copy & Paste)

### First Run
```bash
# 1. Quick test (2 minutes)
python src/main.py

# 2. Check reports
start reports/report_*.html

# 3. All models (10 minutes)
python src/main.py --mode=all

# 4. Batch suite (1 hour)
python src/main.py --mode=batch
```

### Production Deployment
```bash
# 1. Use Ollama for unlimited testing
python src/main.py --config=config/config_ollama.yaml

# 2. Use Promptintel for professional assessment
python src/main.py --config=config/config_promptintel.yaml

# 3. Use Batch for comprehensive audit
python src/main.py --mode=batch
```

### CI/CD Integration
```bash
# Add to your CI/CD pipeline
python src/main.py --mode=all --complexity=LOW --categories=PROMPT_INJECTION

# Returns:
# - Exit code 0 on success
# - HTML and JSON reports in ./reports/
```

---

## 📞 When to Use Each Mode

| Mode | Duration | Cost | Best For |
|------|----------|------|----------|
| Single | 5 min | $0-0.1 | Development, debugging |
| All | 15 min | $0-0.5 | Provider comparison |
| Batch | 60 min | $0-5 | Production audit |

---

**For detailed docs, see: [BATCH_TESTING.md](BATCH_TESTING.md)**

**Happy testing! 🎯**
