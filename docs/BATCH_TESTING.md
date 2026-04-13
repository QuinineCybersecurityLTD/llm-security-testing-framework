# Batch Testing Guide - Multiple Tests Across Models

This guide explains how to run **multiple security tests** against your LLM models efficiently.

---

## 🎯 Overview

The framework now supports **three testing modes**:

| Mode | Purpose | Use Case | Duration |
|------|---------|----------|----------|
| **Single** | Test ONE model with ONE configuration | Quick validation | 5-10 min |
| **All** | Test ALL models with ONE configuration | Provider comparison | 10-30 min |
| **Batch** | Test multiple configurations & models | Comprehensive assessment | 30-120 min |

---

## 📋 Running Different Test Modes

### Mode 1: Single Model Test (Default)

Test one model with default Gemini config:

```bash
python src/main.py
```

Test a specific model:

```bash
python src/main.py --model=gemini-flash
```

Test with custom categories:

```bash
python src/main.py --categories=PROMPT_INJECTION,JAILBREAK
```

Test specific complexity:

```bash
python src/main.py --complexity=LOW,MEDIUM
```

### Mode 2: Test All Models

Test **every model** in your configuration with the **same** test settings:

```bash
# Test all models with LOW complexity
python src/main.py --mode=all --complexity=LOW

# Test all models with PROMPT_INJECTION only
python src/main.py --mode=all --categories=PROMPT_INJECTION

# Test all models with everything
python src/main.py --mode=all
```

**Example Output:**
```
🎯 Running tests against ALL models...

[1/3] Testing: gemini-flash
  [1/5] Prompt Injection Test... ✅ REFUSED (Score: 100/100)
  [2/5] Role Play Attack... ✅ REFUSED (Score: 100/100)
  ...

[2/3] Testing: llama-local
  [1/5] Prompt Injection Test... ⚠️ PARTIAL_COMPLIANCE (Score: 45/100)
  ...

[3/3] Testing: promptintel-library
  [1/5] Prompt Injection Test... ✅ REFUSED (Score: 100/100)
  ...

✅ All-model test completed. Test IDs: [test-id-1, test-id-2, test-id-3]
```

### Mode 3: Batch Test Suite (NEW!)

Run **multiple test configurations** with different objectives:

```bash
# Run predefined batch test suite
python src/main.py --mode=batch

# Run batch with specific config file
python src/main.py --mode=batch --config=config/config_gemini.yaml
```

**What happens:**

1. ⚡ **Quick Validation** - LOW complexity attacks on all models (5-10 min)
2. 🔍 **Comprehensive Test** - ALL categories & complexity levels (30-60 min)
3. Generates separate HTML and JSON reports for each suite
4. Produces optional combined comparison report

---

## 🔧 Configuring Batch Tests

### Using Predefined Suites

Edit `config/test_suites.yaml`:

```yaml
test_suites:
  - name: "⚡ Quick Validation"
    categories: ["PROMPT_INJECTION"]
    complexity_levels: ["LOW"]
    models: null  # All models in config
```

### Creating Custom Batch Tests in Code

```python
import asyncio
from src.main import LLMSecurityTestFramework

async def run_custom_batch():
    framework = LLMSecurityTestFramework(
        config_path="config/config_gemini.yaml"
    )
    
    await framework.initialize()
    
    # Define custom test configurations
    custom_configs = [
        {
            "name": "⚡ Fast Test - Gemini Only",
            "categories": ["PROMPT_INJECTION"],
            "complexity_levels": ["LOW"],
            "models": ["gemini-flash"]
        },
        {
            "name": "🔍 Deep Test - Local Models",
            "categories": ["PROMPT_INJECTION", "JAILBREAK"],
            "complexity_levels": ["LOW", "MEDIUM", "HIGH"],
            "models": ["llama-local"]
        },
        {
            "name": "📊 Full Comparison",
            "categories": ["PROMPT_INJECTION", "JAILBREAK", "PII_LEAKAGE"],
            "complexity_levels": ["LOW", "MEDIUM", "HIGH"],
            "models": None  # Test all
        }
    ]
    
    # Run in sequential mode (safer for API limits)
    results = await framework.run_batch_tests(
        test_configurations=custom_configs,
        run_parallel=False
    )
    
    # Results: {
    #   "Fast Test - Gemini Only": ["test-id-1"],
    #   "Deep Test - Local Models": ["test-id-2"],
    #   "Full Comparison": ["test-id-3", "test-id-4", "test-id-5"]
    # }
    
    await framework.close()

# Run it
asyncio.run(run_custom_batch())
```

---

## 📊 Example Batch Test Scenarios

### Scenario 1: Quick CI/CD Validation

```bash
# Run quick tests in your CI/CD pipeline
python src/main.py --mode=all --complexity=LOW --categories=PROMPT_INJECTION

# Takes: 5-10 minutes
# Cost: Minimal (only quick tests)
# Good for: Every commit, automated validation
```

### Scenario 2: Provider Comparison

```bash
# Compare Gemini vs Local Ollama
python src/main.py --mode=all --config=config/config_gemini.yaml

# Then compare with:
python src/main.py --mode=all --config=config/config_ollama.yaml

# Check reports/comparison/
```

### Scenario 3: Comprehensive Security Audit

```python
# Run everything with all complexity levels
configs = [
    {
        "name": "Gemini-Flash Security Audit",
        "categories": ["PROMPT_INJECTION", "JAILBREAK", "PII_LEAKAGE"],
        "complexity_levels": ["LOW", "MEDIUM", "HIGH"],
        "models": ["gemini-flash"]
    },
    {
        "name": "Local Ollama Audit",
        "categories": ["PROMPT_INJECTION", "JAILBREAK", "PII_LEAKAGE"],
        "complexity_levels": ["LOW", "MEDIUM", "HIGH"],
        "models": ["llama-local"]
    }
]

# Run in Python
```

### Scenario 4: Prompt Intelligence Testing

```bash
# Use Promptintel prompts for testing
python src/main.py --mode=batch --config=config/config_promptintel.yaml

# Tests all models against Promptintel's vetted security prompts
# Best for: Professional security research
```

---

## 📈 Understanding Batch Test Results

### Directory Structure

```
reports/
├── report_test-id-1.html          # Suite 1, Model 1
├── report_test-id-1.json
├── report_test-id-2.html          # Suite 1, Model 2
├── report_test-id-2.json
├── report_test-id-3.html          # Suite 2, Model 1
├── report_test-id-3.json
└── comparison_report.html          # Cross-suite comparison (optional)
```

### Sample Batch Output

```
======================================================================
🎯 BATCH TEST SUITE
======================================================================
Total test configurations: 2
Running in: sequential mode

──────────────────────────────────────────────────────────────────────
📋 Test Configuration: ⚡ Quick Validation - Low Complexity
   Categories: ['PROMPT_INJECTION']
   Complexity: ['LOW']
   Models: gemini-flash, llama-local, promptintel-library

   [1/3] Testing: gemini-flash
   🎯 Starting test session: test-id-1
   [1/3] Prompt Injection Attack 1... ✅ REFUSED (Score: 100/100)
   [2/3] Prompt Injection Attack 2... ✅ REFUSED (Score: 100/100)
   [3/3] Prompt Injection Attack 3... ✅ REFUSED (Score: 100/100)
   
   📊 Test Summary:
   Total Attacks: 3
   Refused: 3 (100.0%)
   Partial: 0 (0.0%)
   Complied: 0 (0.0%)

──────────────────────────────────────────────────────────────────────
📋 Test Configuration: 🔍 Comprehensive Test
   Categories: ['PROMPT_INJECTION', 'JAILBREAK']
   Complexity: ['LOW', 'MEDIUM', 'HIGH']
   Models: gemini-flash, llama-local

   [1/2] Testing: gemini-flash
   🎯 Starting test session: test-id-2
   [1/12] Prompt Injection 1-A... ✅ REFUSED (Score: 100/100)
   ...

======================================================================
✅ BATCH TEST SUMMARY
======================================================================
Total Configurations: 2
Successful Configurations: 2
Total Test Sessions: 5

Detailed Results:
  ✅ ⚡ Quick Validation - Low Complexity: 3 test(s)
     └─ test-id-1
     └─ test-id-2
     └─ test-id-3
  ✅ 🔍 Comprehensive Test - All Complexity: 2 test(s)
     └─ test-id-4
     └─ test-id-5

Reports available in: ./reports/
======================================================================
```

---

## ⚙️ Advanced Configuration

### Control Execution

```yaml
# in test_suites.yaml
execution:
  parallel: false  # Sequential execution (safer)
  # parallel: true  # Parallel execution (faster, more resource-intensive)
  
  max_concurrent_suites: 2  # If parallel=true
  
  fail_fast: false  # Continue even if one suite fails
  # fail_fast: true  # Stop on first failure
  
  save_individual_reports: true  # Keep reports for each suite
  generate_combined_report: true  # Create comparison report
```

### Rate Limiting for API-Based Tests

```yaml
# in your config.yaml (e.g., config_gemini.yaml)
execution:
  rate_limit_rpm: 15     # Gemini free tier: 15 requests/minute
  delay_between_attacks_ms: 1000  # 1 second between attacks
  max_concurrent_attacks: 1  # Sequential attacks
```

**For batch testing, reduce these to avoid hitting rate limits:**

```yaml
execution:
  rate_limit_rpm: 5      # Conservative for batch
  delay_between_attacks_ms: 2000  # 2 seconds
  max_concurrent_attacks: 1       # Don't parallelize
```

### Custom Model Selection

```yaml
# Test only specific models
test_suites:
  - name: "Production Models Only"
    categories: ["PROMPT_INJECTION"]
    complexity_levels: ["LOW", "MEDIUM"]
    models:
      - "gemini-flash"        # Specific model
      - "llama-local"         # Specific model
      # Note: Don't include "promptintel-library"
```

---

## 🚀 Best Practices for Batch Testing

### 1. **Start Small, Scale Up**
```bash
# Day 1: Quick test
python src/main.py --mode=all --complexity=LOW

# Day 2: Add medium complexity
python src/main.py --mode=all --categories=PROMPT_INJECTION,JAILBREAK

# Week 1: Full comprehensive
python src/main.py --mode=batch
```

### 2. **Use Ollama for Development**

```bash
# Free, unlimited testing during development
python src/main.py --mode=batch --config=config/config_ollama.yaml
```

### 3. **Batch Test at Off-Peak Hours**

```bash
# For API-based testing, run batch tests at night
# to avoid rate limits during peak hours

# Create a scheduled job:
# Windows: Task Scheduler
# Linux/Mac: cron job
```

### 4. **Monitor API Costs**

```yaml
# Estimate costs before batch testing:
# Gemini: ~$0 (free tier up to limits)
# Ollama: $0 (local)
# OpenAI: ~$0.003 per 1K tokens
# 
# Example: 20 attacks × 100 tokens = 2000 tokens
#          2000 tokens × $0.003/K = $0.006
```

### 5. **Save Test Data for Trending**

```bash
# Keep historical reports
cp -r reports/ reports_backup_$(date +%Y%m%d)/

# Compare results over time
# Track security improvements/regressions
```

---

## 🐛 Troubleshooting Batch Tests

### Issue: Tests running too slow

**Solution:**
```bash
# Use Ollama (local, no API latency)
python src/main.py --mode=batch --config=config/config_ollama.yaml

# Or reduce complexity
python src/main.py --mode=batch --complexity=LOW
```

### Issue: API rate limits exceeded

**Solution:**
```yaml
# In config.yaml
execution:
  rate_limit_rpm: 5        # Reduce significantly
  delay_between_attacks_ms: 5000  # 5 seconds between attacks
  max_concurrent_attacks: 1       # No parallelization
```

### Issue: Out of memory with batch tests

**Solution:**
```bash
# Run tests sequentially, not in parallel
# export to YAML: execution.parallel = false

# Or run individual suites one at a time
python src/main.py --mode=all --config=config/config_gemini.yaml
# Then later:
python src/main.py --mode=all --config=config/config_ollama.yaml
```

### Issue: Some tests failing

**Solution:**
```bash
# Run with fail_fast: false to see all failures
# Check logs: cat logs/results.jsonl

# Run individual problematic model
python src/main.py --model=problematic-model --complexity=LOW
```

---

## 📚 Next Steps

1. **Try Single Test:** `python src/main.py`
2. **Try All Models:** `python src/main.py --mode=all`
3. **Try Batch Test:** `python src/main.py --mode=batch`
4. **Review Results:** Open `reports/` folder in browser
5. **Customize:** Edit `config/test_suites.yaml` for your needs

---

## 🔗 Related Documentation

- [Setup Guide](SETUP.md) - Initial setup
- [API Keys Guide](API_KEYS.md) - Getting API keys
- [Configuration Reference](config/config_gemini.yaml) - Config options
- [Main README](../README.md) - Overview

---

**Happy testing with multiple models! 🚀**
