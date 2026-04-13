# Prompt Intel + Local Model Security Testing Guide

## Overview
This guide shows how to test your local GGUF model using attack prompts from the Prompt Intel API. Prompt Intel provides a curated library of adversarial prompts and jailbreak attempts that you can use to evaluate your model's security.

## Setup Steps

### 1. Install Dependencies
First, ensure you have the required packages:
```bash
pip install -r requirements.txt
pip install aiohttp pyyaml
```

### 2. Get Prompt Intel API Key
1. Go to [Prompt Intel](https://promptintel.novahunting.ai)
2. Sign up for an account if you haven't already
3. Navigate to API Keys or Settings
4. Generate a new API key
5. Copy the key (you'll need it in the next step)

### 3. Set Up Environment Variable
**Option A: Set environment variable (Recommended)**
```powershell
# Windows PowerShell
$env:PROMPTINTEL_API_KEY = "your-api-key-here"

# Or permanently (run as admin):
[Environment]::SetEnvironmentVariable("PROMPTINTEL_API_KEY", "your-api-key-here", "User")
```

**Option B: Update config file directly**
Edit `config/config_promptintel_local.yaml` and replace:
```yaml
api_key: "${PROMPTINTEL_API_KEY}"
```
with:
```yaml
api_key: "your-actual-api-key"
```

### 4. Verify Local Model Path
Make sure your local GGUF model path is correct in `config/config_promptintel_local.yaml`:
```yaml
target_model:
  model_name: "C:\\Users\\acer\\Desktop\\...\\mistral-7b-instruct-v0.2.Q4_K_M.gguf"
```

## Running the Test

### From Python Terminal
```python
import asyncio
from orchestrator_promptintel_local import PromptIntelLocalTester

async def run_test():
    tester = PromptIntelLocalTester()
    test_id = await tester.run_test_suite()
    print(f"Test completed: {test_id}")

asyncio.run(run_test())
```

### From Command Line
```bash
python src/orchestrator_promptintel_local.py
```

## Expected Output
The script will:
1. ✅ Initialize Prompt Intel API adapter
2. ✅ Initialize local GGUF model adapter
3. ✅ Initialize judge model adapter
4. 🎯 Fetch attack prompts from Prompt Intel (default: 5 categories × 5 prompts = 25 prompts)
5. 🔬 Test each prompt against your local model
6. 📊 Evaluate responses using the judge model
7. 📈 Generate detailed reports

## Configuration Options

### Adjust Attack Categories
Edit `config/config_promptintel_local.yaml`:
```yaml
attacks:
  categories:
    - "prompt_injection"
    - "jailbreak"
    - "adversarial"
  difficulty: "medium"  # low, medium, high
  limit_per_category: 5  # Number of prompts per category
```

### Reduce Test Duration
For faster testing, modify execution settings:
```yaml
execution:
  pool_size: 1
  max_concurrent_attacks: 1
  delay_between_attacks_ms: 500  # Reduce from 1000
```

### Change Judge Model
To use a different model for evaluation, update `judge_model`:
```yaml
judge_model:
  name: "other-model"
  type: "local_gguf"  # or "gemini_api", "ollama", etc.
  model_name: "path/to/other/model.gguf"
```

## Troubleshooting

### "Prompt Intel API key not found"
- Check environment variable: `echo $env:PROMPTINTEL_API_KEY`
- Or verify the config file has the correct key
- Make sure you're not using the placeholder `${PROMPTINTEL_API_KEY}`

### "Failed to connect to Prompt Intel API"
- Check your internet connection
- Verify the API key is valid
- Try: `await tester.promptintel_adapter.health_check()`
- API might be down (check status on Prompt Intel website)

### "Local model initialization failed"
- Verify the model file path exists
- Check you have enough disk space and RAM
- Try running the model independently first with `local_gguf_adapter.py`
- Check if llama-cpp-python is installed: `pip install llama-cpp-python`

### "Out of memory errors"
- Reduce `max_tokens` in target_model parameters
- Increase `delay_between_attacks_ms` to allow garbage collection
- Use a smaller quantization (e.g., Q4 instead of Q6)
- Run on a machine with more RAM

## Output Files

### Reports
Generated in `reports/` directory:
- `report_<test_id>.html` - Human-readable report
- `report_<test_id>.json` - Machine-readable results

### Raw Results
Generated in `logs/` directory:
- `test_<test_id>_results.json` - Complete test results with all responses

## Example Custom Config

Create `config/custom_promptintel_test.yaml`:
```yaml
judge_model:
  name: "mistral-judge"
  type: "local_gguf"
  model_name: "path/to/model.gguf"
  parameters:
    temperature: 0.3
    max_tokens: 300
  timeout: 120
  max_retries: 2

execution:
  pool_size: 1
  max_concurrent_attacks: 1
  delay_between_attacks_ms: 2000  # Longer delay for safety

attacks:
  categories: ["jailbreak"]  # Only test jailbreak attacks
  difficulty: "high"  # Only high-difficulty attacks
  limit_per_category: 10

target_model:
  name: "mistral-local"
  type: "local_gguf"
  model_name: "path/to/your/model.gguf"
  parameters:
    temperature: 0.7
    max_tokens: 512
  timeout: 120
```

Then run:
```python
tester = PromptIntelLocalTester("config/custom_promptintel_test.yaml")
await tester.run_test_suite()
```

## Next Steps

1. **Review Results**: Check the HTML report in `reports/`
2. **Analyze Security**: Look for patterns in successful attacks
3. **Fine-tune Model**: Use insights to improve model prompts or safety measures
4. **Iterate**: Run tests again after making changes to verify improvements

## Support

For issues with:
- **Prompt Intel API**: Visit https://promptintel.novahunting.ai/docs
- **Local GGUF**: Check [llama-cpp-python docs](https://github.com/abetlen/llama-cpp-python)
- **Framework**: See `docs/` directory
