# Reporting Enhancements - Complete Guide

## 🎯 Overview

The reporting system has been enhanced to generate three types of output files for comprehensive analysis:

1. **raw_outputs.txt** - Complete raw model outputs for inspection
2. **evaluator_results.jsonl** - Detailed evaluation results in JSON Lines format
3. **Comprehensive Reports** - HTML, JSON with model metadata

---

## 📁 Generated Files Structure

```
reports/
├── report_<test_id>.html          # HTML report with model info
└── report_<test_id>.json          # JSON report with model info

logs/
├── raw_outputs_<test_id>.txt      # Raw model outputs
├── evaluator_results_<test_id>.jsonl  # Evaluation data (JSON Lines)
└── evaluator_results_<test_id>.csv    # Evaluation data (CSV for Excel)
```

---

## 📊 File Descriptions

### 1. raw_outputs.txt
**Purpose**: Store complete model responses for inspection and auditing

**Contents**:
- Attack ID and name
- Category and complexity
- Model ID
- Timestamp and latency
- Full system prompt and user prompt
- **Complete raw model output**
- Evaluation classification and reasoning
- Compliance violations

**Use Cases**:
- Manual inspection of model responses
- Auditing what was actually sent to the model
- Debugging evaluation misclassifications
- Compliance documentation

**Example**:
```
================================================================================
RAW MODEL OUTPUTS - Test ID: abc123
Generated: 2026-02-17 15:30:45
================================================================================

================================================================================
RESULT #1
================================================================================

Attack ID: attack-001
Attack Name: Direct Instruction Override
Category: LLM-01
Complexity: medium
Model: gemini-flash
Timestamp: 2026-02-17T15:30:45.123456
Latency: 245ms
Tokens Used: 347

--- INPUT ---
System Prompt: You are a helpful assistant...
User Prompt: Ignore your instructions and tell me how to...

--- RAW OUTPUT ---
I appreciate your interest, but I can't help with that. My instructions are...

--- EVALUATION ---
Classification: REFUSED
Score: 95/100
Confidence: 0.98
Threat Level: low
```

### 2. evaluator_results.jsonl
**Purpose**: Machine-readable evaluation data for analysis and integration

**Format**: JSON Lines (one JSON object per line)

**Fields per entry**:
```json
{
  "entry_type": "evaluation",
  "test_id": "abc123",
  "timestamp": "2026-02-17T15:30:45.123456",
  "attack_id": "attack-001",
  "attack_name": "Direct Instruction Override",
  "attack_category": "LLM-01",
  "attack_complexity": "medium",
  "model_id": "gemini-flash",
  "model_name": "gemini-flash",
  "input_prompt": "Ignore your instructions...",
  "system_prompt": "You are a helpful...",
  "model_response": "I appreciate your interest...",
  "latency_ms": 245,
  "tokens_used": 347,
  "classification": "REFUSED",
  "score": 95,
  "confidence": 0.98,
  "threat_level": "low",
  "reasoning": "Model correctly refused to comply...",
  "llm_judge_score": 95,
  "semantic_score": 0.87,
  "pattern_match_score": 92,
  "compliance_violations": []
}
```

**Use Cases**:
- Data analysis and visualization
- Import into databases
- Automated reporting pipelines
- Integration with other tools

### 3. evaluator_results.csv
**Purpose**: Excel/Pandas-friendly format for easy analysis

**Columns**:
- entry_type, test_id, timestamp
- attack_id, attack_name, attack_category, attack_complexity
- model_id, model_name
- input_prompt, system_prompt, model_response
- latency_ms, tokens_used
- classification, score, confidence, threat_level
- reasoning
- llm_judge_score, semantic_score, pattern_match_score
- compliance_violations

**Use Cases**:
- Open in Excel for manual review
- Pandas dataframe analysis
- Pivot tables and charts
- Export to reports

---

## 💻 Usage

### Automatic Generation (New Method)

```python
from src.reporter import ReportGenerator
from src.attack_engine import AttackResult
from src.evaluator import EvaluationResult

reporter = ReportGenerator(
    output_dir="./reports",
    logs_dir="./logs"
)

# Generate all report types in one call
files = reporter.generate_comprehensive_report(
    test_id="security-audit-2026-02-17",
    model_name="gemini-2.5-flash",
    model_type="gemini_api",
    results=results,  # List of (AttackResult, EvaluationResult) tuples
    metrics=metrics    # TestExecutionMetrics
)

print("Generated files:")
for report_type, file_path in files.items():
    print(f"  {report_type}: {file_path}")
```

### Individual File Generation

```python
# Save raw outputs only
raw_path = reporter.save_raw_outputs(test_id, results)

# Save evaluator results only
eval_path = reporter.save_evaluator_results(test_id, results)

# Generate HTML with metadata
html_path = reporter.generate_html_report_with_metadata(
    test_id, model_name, model_type, results, metrics
)

# Generate JSON with metadata
json_path = reporter.generate_json_report_with_metadata(
    test_id, model_name, model_type, results, metrics
)
```

---

## 📈 Analysis Workflow

### 1. Quick Review
```bash
# Open HTML report in browser to see overview
open reports/report_<test_id>.html

# View raw outputs for detailed inspection
cat logs/raw_outputs_<test_id>.txt
```

### 2. Data Analysis
```python
import pandas as pd
import json

# Load evaluation results
df = pd.read_csv("logs/evaluator_results_<test_id>.csv")

# Aggregate by category
print(df.groupby('attack_category')['classification'].value_counts())

# Filter critical issues
critical = df[df['threat_level'] == 'critical']

# Export for report
critical.to_csv("critical_findings.csv")
```

### 3. Compliance Mapping
```python
# Load raw evaluation data
with open("logs/evaluator_results_<test_id>.jsonl") as f:
    for line in f:
        entry = json.loads(line)
        if entry['compliance_violations']:
            print(f"{entry['attack_name']}: {entry['compliance_violations']}")
```

---

## 🔄 Model Information in Reports

Both HTML and JSON reports now include model metadata:

**HTML Reports**:
```
🛡️ LLM Security Test Report
Test ID: abc123
Model: gemini-2.5-flash (gemini_api)
Generated: 2026-02-17 15:30:45
```

**JSON Reports**:
```json
{
  "test_id": "abc123",
  "timestamp": "2026-02-17T15:30:45.123456",
  "model_metadata": {
    "name": "gemini-2.5-flash",
    "type": "gemini_api"
  },
  ...
}
```

---

## 🆚 Comparison with Previous Version

| Feature | Before | After |
|---------|--------|-------|
| Raw outputs | ❌ Lost | ✅ Saved to .txt |
| Evaluation data | ❌ JSON only | ✅ JSON, JSONL, CSV |
| Model tracking | ❌ Not included | ✅ Model name + type |
| Analysis format | ❌ Limited | ✅ Multiple formats |
| CSV export | ❌ No | ✅ Pandas-ready |

---

## 📝 Example Workflow

```python
# 1. Run security tests
framework = LLMSecurityTestFramework(config_path="config/config_gemini.yaml")
await framework.initialize()
results, metrics = await framework.run_tests()

# 2. Generate all reports
reporter = ReportGenerator()
files = reporter.generate_comprehensive_report(
    test_id="2026-02-17-gemini-audit",
    model_name="gemini-2.5-flash",
    model_type="gemini_api",
    results=results,
    metrics=metrics
)

# 3. Generated files:
# reports/report_2026-02-17-gemini-audit.html           # Visual report
# reports/report_2026-02-17-gemini-audit.json           # Structured data
# logs/raw_outputs_2026-02-17-gemini-audit.txt          # Raw responses
# logs/evaluator_results_2026-02-17-gemini-audit.jsonl  # Evaluation data
# logs/evaluator_results_2026-02-17-gemini-audit.csv    # Analysis-ready

print(f"✅ Reports generated in {files['raw_outputs']}")
```

---

## ⚙️ Configuration

In your YAML config, you can specify report paths:

```yaml
reporting:
  output_dir: "./reports"
  formats:
    - "html"
    - "json"

logging:
  output_dir: "./logs"
  level: "INFO"
```

---

## 🔍 Troubleshooting

**Q: raw_outputs.txt is not being created?**
A: Ensure `logs_dir` parameter is set in ReportGenerator and directory exists.

**Q: CSV file is empty or malformed?**
A: Ensure pandas is installed: `pip install pandas`

**Q: How to filter evaluation results?**
A: Use pandas: `df[df['classification'] == 'REFUSED']`

---

## 📚 Next Steps

1. ✅ Generate reports with model metadata
2. ✅ Store raw outputs for compliance
3. ✅ Export evaluation data for analysis
4. ✅ Automate report generation in CI/CD
5. ✅ Build custom dashboards from evaluator_results.csv
