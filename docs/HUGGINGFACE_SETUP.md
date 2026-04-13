# HuggingFace Mistral Integration Guide

## Quick Start

### 1. Get Your HuggingFace API Key
1. Go to [HuggingFace Settings](https://huggingface.co/settings/tokens)
2. Click "New token"
3. Select "Read" permission
4. Copy your token

### 2. Set Environment Variable
```powershell
# Windows PowerShell
$env:HF_API_KEY = "your_token_here"

# Or set permanently
[System.Environment]::SetEnvironmentVariable("HF_API_KEY", "your_token_here", "User")
```

### 3. Run with HuggingFace Config
```bash
# Using Mistral 7B (fast, unrestricted)
python quickstart.py --config config/config_huggingface.yaml

# Or with main.py
# Edit line 26 in src/main.py to use config_huggingface.yaml
```

## Why HuggingFace Mistral?

✅ **Unlimited Requests** - No 5-prompt limit (unlike Gemini)
✅ **Fast Responses** - 2-5s per request
✅ **Free Tier** - Full API access at no cost
✅ **No Rate Limiting** - Test attacks aggressively
✅ **Unrestricted Output** - Better for security testing
✅ **Efficient Pipeline** - Can run 5 concurrent attacks
✅ **Parallelizable** - Batch test multiple attack patterns

## Comparison with Gemini

| Feature | Gemini | HuggingFace Mistral |
|---------|--------|-------------------|
| Free Tier Limit | 5 prompts/min | Unlimited |
| Rate Limiting | Strict | None (free) |
| Response Time | 1-3s | 2-5s |
| Model Quality | Claude 3 equivalent | 7B parameter (good) |
| Concurrent Requests | 1 | 5+ |
| Cost per 1k tests | $10-50 | Free |
| Best for | Quick tests | Large-scale testing |

## Configuration Details

The `config_huggingface.yaml` includes:

- **Model**: `mistralai/Mistral-7B-Instruct-v0.2`
  - Instruction-tuned for security testing
  - Supports complex reasoning
  - Follows instructions better than base models

- **Execution Settings**:
  - Pool size: 5 concurrent connections
  - Rate limit: 1000 RPM (no real limit)
  - Max concurrent attacks: 5
  - Minimal delay between attacks

- **Performance Optimized**:
  - 512 token max for efficiency
  - Temperature 0.7 for balanced responses
  - Timeout 60s (first request may be slow due to model loading)

## Advanced: Custom Models

You can use any HuggingFace model. Edit `config_huggingface.yaml`:

```yaml
model_name: "meta-llama/Llama-2-7b-chat"  # Llama 2
# or
model_name: "NousResearch/Nous-Hermes-2-Mistral-7B"  # Nous Hermes
# or
model_name: "mistralai/Mistral-7B-v0.1"  # Base Mistral
```

## Testing Attack Coverage

Run full attack suite with:

```bash
# Single model test (Mistral)
python src/main.py

# Compare across models
# Modify main.py to load:
# - config_huggingface.yaml (Mistral)
# - config_gemini.yaml (Gemini)
# - config.yaml (OpenAI)
```

## Monitoring and Logs

The framework tracks:
- ✅ Response times per attack
- ✅ Token usage (shown in metadata)
- ✅ Success/failure rates
- ✅ Generation time from HF API

Check `logs/results.jsonl` for detailed metrics.

## Troubleshooting

### "Model is loading" Error
First request to a model takes 10-30s while HF loads it. The adapter automatically retries.

### Token Validation Failed
- Check token is correct: `huggingface.co/settings/tokens`
- Verify token has "Read" permission
- Set environment variable correctly

### Connection Timeout
- HF servers may be slow. Increase timeout in config to 120s:
  ```yaml
  timeout: 120
  ```

### Out of Memory on HF
- Use smaller model: `mistralai/Mistral-7B-v0.1`
- Or use OpenAI's GPT-3.5-turbo as fallback

## Scaling for Production

For large-scale testing:

1. **Increase concurrency**:
   ```yaml
   execution:
     pool_size: 10
     max_concurrent_attacks: 10
   ```

2. **Use multiple models**:
   ```yaml
   targets:
     - name: "mistral"
       model_name: "mistralai/Mistral-7B-Instruct-v0.2"
     - name: "nous-hermes"
       model_name: "NousResearch/Nous-Hermes-2-Mistral-7B"
   ```

3. **Monitor usage**:
   - Check HF dashboard for inference stats
   - Monitor logs for errors and latency

## Cost Analysis

Running 1000 attack tests:

| Provider | Cost | Speed |
|----------|------|-------|
| OpenAI GPT-4 | $30 | Fast |
| OpenAI GPT-3.5 | $0.50 | Fast |
| Google Gemini | ~Free (5 prompt limit) | Medium |
| **HuggingFace** | **Free** | **Medium-Good** |

✅ **HuggingFace = Best value for security testing**

## Next Steps

1. Set `HF_API_KEY` environment variable
2. Update main.py line 26 to use `config_huggingface.yaml`
3. Run: `python quickstart.py`
4. Check generated reports in `reports/`

For questions, see [HuggingFace Docs](https://huggingface.co/docs/hub/inference-api)
