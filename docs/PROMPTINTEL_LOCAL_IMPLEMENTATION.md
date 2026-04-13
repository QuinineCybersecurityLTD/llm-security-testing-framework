# Implementing Prompt Intel for Local Model Testing

## What We've Set Up For You

I've created a complete integration between Prompt Intel API and your local GGUF model. Here's what's been implemented:

### Files Created:

1. **`config/config_promptintel_local.yaml`** - Configuration file for integrated testing
2. **`src/orchestrator_promptintel_local.py`** - Main orchestrator class
3. **`quickstart_promptintel_local.py`** - Quick start script with prerequisites check
4. **`docs/PROMPTINTEL_LOCAL_SETUP.md`** - Detailed setup guide

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│ Prompt Intel API (Attack Library)                       │
│ - Prompt Injection Attacks                              │
│ - Jailbreak Attempts                                    │
│ - Adversarial Prompts                                   │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────┐
│ Test Engine                                             │
│ - Fetch attacks from Prompt Intel                       │
│ - Send each attack to local model                       │
│ - Evaluate responses with judge model                   │
│ - Generate security report                              │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ├─────────────┬─────────────┐
                   ▼             ▼             ▼
        ┌──────────────────────────────────────────┐
        │  Target Model         Judge Model       │
        │  (Your Local Model)    (Evaluator)      │
        │  Mistral 7B           Mistral 7B        │
        │  Receives attacks      Evaluates safety │
        │  Generates responses   Scores responses │
        └──────────────────────────────────────────┘
                   │
                   ▼
        ┌──────────────────────────────────────┐
        │ Reports & Analysis                  │
        │ - HTML Report                       │
        │ - JSON Results                      │
        │ - Security Metrics                  │
        └──────────────────────────────────────┘
```

## Step-by-Step Implementation

### Step 1: Get Prompt Intel API Key

1. Go to https://promptintel.novahunting.ai
2. Create an account or log in
3. Navigate to API settings/dashboard
4. Create a new API key
5. Copy the key (save it somewhere safe)

### Step 2: Set Environment Variable

**Windows PowerShell:**
```powershell
# Set for current session
$env:PROMPTINTEL_API_KEY = "your-api-key-here"

# Or set permanently (run as Administrator)
[Environment]::SetEnvironmentVariable("PROMPTINTEL_API_KEY", "your-api-key", "User")

# Verify it worked
echo $env:PROMPTINTEL_API_KEY
```

### Step 3: Verify Configuration

Check that your local model path is correct in `config/config_promptintel_local.yaml`:

```yaml
target_model:
  model_name: "C:\\Users\\acer\\Desktop\\Intership@quinine\\official Work-week 1\\My work\\llm_security_assessment\\models\\mistral-7b-instruct-v0.2.Q4_K_M.gguf"
```

If your model is in a different location, update this path.

### Step 4: Run the Tests

**Option A: Using Quick Start Script (Recommended)**
```bash
python quickstart_promptintel_local.py
```

**Option B: Direct Python Script**
```python
import asyncio
from src.orchestrator_promptintel_local import PromptIntelLocalTester

async def main():
    tester = PromptIntelLocalTester()
    test_id = await tester.run_test_suite()
    await tester.cleanup()

asyncio.run(main())
```

**Option C: From PowerShell Terminal**
```powershell
# Make sure API key is set
$env:PROMPTINTEL_API_KEY = "your-key"

# Run test
python quickstart_promptintel_local.py
```

## What Happens During Testing

1. **Initialization Phase** (30 seconds)
   - Connects to Prompt Intel API
   - Loads local GGUF model
   - Initializes judge model

2. **Attack Fetching Phase** (10-20 seconds)
   - Fetches attacks from 5 categories
   - ~25 attack prompts total (5 per category)
   - Categories: prompt_injection, jailbreak, adversarial, etc.

3. **Testing Phase** (10-30 minutes, depending on model)
   - For each attack prompt:
     - Sends to local model
     - Records response
     - Evaluates with judge model
     - Logs results

4. **Reporting Phase** (30 seconds)
   - Generates HTML report
   - Creates JSON results file
   - Displays summary statistics

## Customization Examples

### Test Only Jailbreak Attacks
Edit `config/config_promptintel_local.yaml`:
```yaml
attacks:
  categories: ["jailbreak"]
  limit_per_category: 10
  difficulty: "high"
```

### Use Fewer Attacks for Quick Test
```yaml
attacks:
  categories: ["prompt_injection", "jailbreak"]
  limit_per_category: 3  # Only 3 per category = 6 total
```

### Test With Different Judge Model
```yaml
judge_model:
  name: "gemini-judge"
  type: "gemini_api"  # Use Gemini instead
  model_name: "gemini-2.5-flash"
  # ... other config
```

## Output Explained

### Terminal Output
```
🚀 Starting Prompt Intel Security Test
Test ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Target Model: mistral-local-gguf
...
🎯 Fetching attacks from Prompt Intel API...
   → Fetching prompt_injection attacks...
     ✓ Retrieved 5 prompts
   → Fetching jailbreak attacks...
     ✓ Retrieved 5 prompts
...
📊 Total attacks fetched: 25

🔬 Testing Local Model Against 25 Attack Prompts

[1/25] Testing: prompt_injection (difficulty: medium)
     Status: ✅ Success
     Evaluation: Received
...
```

### HTML Report (`reports/report_*.html`)
- Detailed security analysis
- Response examples
- Success/failure rates
- Evaluation scores
- Visualizations

### JSON Results (`logs/test_*_results.json`)
```json
{
  "test_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2026-02-13T10:30:45.123456",
  "summary": {
    "total_tests": 25,
    "successful_tests": 24,
    "successful_evaluations": 24
  },
  "results": [
    {
      "attack_index": 1,
      "attack_category": "prompt_injection",
      "attack_text": "...",
      "test_result": {
        "success": true,
        "response": "...",
        "latency_ms": 1234
      },
      "evaluation_result": {
        "success": true,
        "evaluation": "..."
      }
    }
  ]
}
```

## Troubleshooting

### Error: "Prompt Intel API key not found"
**Solution:** 
- Set environment variable: `$env:PROMPTINTEL_API_KEY = "your-key"`
- Verify with: `echo $env:PROMPTINTEL_API_KEY`
- If still not working, directly edit config file (not recommended)

### Error: "Failed to connect to Prompt Intel API"
**Solution:**
- Check internet connection
- Verify API key is correct
- Check if Prompt Intel service is up
- Try making a simple health check:
  ```python
  import asyncio
  from src.adapters.promptintel_adapter import PromptintelAdapter
  from src.adapters.base import ModelConfig, ModelType
  
  async def test():
      config = ModelConfig(
          model_type=ModelType.PROMPTINTEL,
          api_key="your-key",
          endpoint="https://api.promptintel.novahunting.ai/api/v1"
      )
      adapter = PromptintelAdapter(config)
      await adapter.initialize()
      print("✅ Connected!")
  
  asyncio.run(test())
  ```

### Error: "Local model initialization failed"
**Solution:**
- Verify model file exists: 
  ```powershell
  Test-Path "C:\path\to\model.gguf"
  ```
- Install llama-cpp-python:
  ```bash
  pip install llama-cpp-python
  ```
- Check available RAM (Mistral 7B needs ~8GB)
- Try using smaller model or lower quantization

### Error: "Out of memory"
**Solution:**
- Reduce `max_tokens` in config (e.g., 256 instead of 512)
- Increase `delay_between_attacks_ms` (e.g., 2000 instead of 1000)
- Use smaller quantized model
- Close other applications to free memory

## Advanced: Custom Integration

If you want to integrate Prompt Intel into your existing code:

```python
from src.adapters.promptintel_adapter import PromptintelAdapter
from src.adapters.local_gguf_adapter import LocalGGUFAdapter
from src.adapters.base import ModelConfig, ModelType

async def test_local_model_with_promptintel():
    # Initialize Prompt Intel
    pi_config = ModelConfig(
        model_type=ModelType.PROMPTINTEL,
        api_key="your-key",
        endpoint="https://api.promptintel.novahunting.ai/api/v1"
    )
    pi_adapter = PromptintelAdapter(pi_config)
    await pi_adapter.initialize()
    
    # Fetch attacks
    prompts = await pi_adapter.fetch_prompt(
        category="jailbreak",
        difficulty="medium",
        limit=5
    )
    
    # Initialize local model
    local_config = ModelConfig(
        model_type=ModelType.LOCAL_GGUF,
        model_name="path/to/model.gguf"
    )
    local_adapter = LocalGGUFAdapter(local_config)
    await local_adapter.initialize()
    
    # Test each prompt
    for prompt_data in prompts['prompts']:
        response = await local_adapter.generate(
            prompt=prompt_data['text']
        )
        print(f"Attack: {prompt_data['text'][:50]}...")
        print(f"Response: {response.content[:100]}...")
```

## Next Steps

1. **Run the Test**
   ```bash
   python quickstart_promptintel_local.py
   ```

2. **Review Results**
   - Check HTML report in `reports/`
   - Examine JSON results in `logs/`

3. **Analyze Security**
   - Look for patterns in successful attacks
   - Identify weak areas in your model
   - Note common jailbreak techniques

4. **Iterate**
   - Modify model prompts based on findings
   - Add safety guidelines
   - Re-run tests to verify improvements

5. **Integrate Into CI/CD** (Optional)
   - Add this script to your deployment pipeline
   - Run tests before releasing model updates
   - Track security metrics over time

## Support & Documentation

- **Setup Guide**: `docs/PROMPTINTEL_LOCAL_SETUP.md`
- **API Reference**: Check Prompt Intel docs
- **Local Model**: See `docs/` for GGUF setup
- **Framework**: Check `docs/DEVELOPER_GUIDE.md`

## Key Metrics to Watch

1. **Success Rate** - % of tests that completed without errors
2. **Jailbreak Attempts** - How many attacks bypassed safety measures
3. **Response Time** - Latency of model responses
4. **Evaluation Coverage** - % of responses that were evaluated
5. **False Positive Rate** - % of safe responses flagged as unsafe

Enjoy testing! 🚀
