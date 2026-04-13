# API Keys Quick Reference

## Getting Started with LLM Security Testing Framework

This guide shows how to quickly get API keys for the different providers.

---

## 🟦 Google Gemini (FREE - Recommended for Beginners)

**Cost:** Free tier available  
**Limit:** 15 requests/minute for Flash, 2 for Pro  
**Best for:** Getting started quickly

### Setup Steps:

1. Visit: https://ai.google.dev/pricing
2. Click "Get API Key"
3. Create a new Google Cloud project (or use existing)
4. Generate and copy your API key

### Set Environment Variable:

**Windows (Command Prompt):**
```batch
set GEMINI_API_KEY=your_api_key_here
```

**Windows (PowerShell):**
```powershell
$env:GEMINI_API_KEY="your_api_key_here"
```

**macOS/Linux:**
```bash
export GEMINI_API_KEY="your_api_key_here"
```

### Test Connection:

```bash
python src/main.py --config config/config_gemini.yaml
```

---

## 🦙 Ollama (FREE - Local Models)

**Cost:** Completely free  
**Limit:** Unlimited (runs locally)  
**Best for:** Privacy, cost-saving, development

### Setup Steps:

1. Download from: https://ollama.ai
2. Install and run
3. Pull a model:
   ```bash
   ollama pull llama2      # Official Meta model
   ollama pull mistral     # Fast 7B model
   ollama pull neural-chat # Good for Q&A
   ```
4. Verify it's running:
   ```bash
   curl http://localhost:11434/api/tags
   ```

### Test Connection:

```bash
python src/main.py --config config/config_ollama.yaml
```

---

## 🔐 Promptintel (Professional Prompts)

**Cost:** Free tier + paid plans  
**Limit:** Varies by plan  
**Best for:** Professional security testing with vetted prompts

### Setup Steps:

1. Visit: https://promptintel.novahunting.ai
2. Sign up for free account
3. Go to API Keys section
4. Generate and copy your API key
5. Also get a Gemini or other judge model key for evaluation

### Set Environment Variables:

**Windows (Command Prompt):**
```batch
set PROMPTINTEL_API_KEY=your_promptintel_key
set GEMINI_API_KEY=your_gemini_key
```

**macOS/Linux:**
```bash
export PROMPTINTEL_API_KEY="your_promptintel_key"
export GEMINI_API_KEY="your_gemini_key"
```

### Test Connection:

```bash
python src/main.py --config config/config_promptintel.yaml
```

---

## 🔓 OpenAI (ChatGPT, GPT-4)

**Cost:** Paid only ($0.003-$0.06 per 1K tokens)  
**Limit:** 4,000-90,000 requests per minute (paid)  
**Best for:** Production deployments

### Setup Steps:

1. Visit: https://platform.openai.com/api-keys
2. Sign up or log in
3. Create new API key
4. Copy and save securely

### Set Environment Variable:

```bash
export OPENAI_API_KEY="sk-..."
```

---

## 🧠 Anthropic (Claude)

**Cost:** Paid only ($0.003-$0.024 per 1K tokens)  
**Limit:** 50-100 RPM  
**Best for:** Advanced reasoning tasks

### Setup Steps:

1. Visit: https://console.anthropic.com
2. Sign up or log in
3. Create new API key
4. Copy and save securely

### Set Environment Variable:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

---

## 📋 Recommended Setup for Different Use Cases

### For Learning/Development
```bash
# Just use Gemini free tier
export GEMINI_API_KEY="your_key"
python src/main.py --config config/config_gemini.yaml
```

### For Local Private Testing
```bash
# Use Ollama (completely local, no API keys needed)
# Just make sure Ollama is running
ollama serve  # In one terminal
python src/main.py --config config/config_ollama.yaml  # In another
```

### For Professional/Research
```bash
# Use Promptintel with Gemini evaluation
export PROMPTINTEL_API_KEY="your_key"
export GEMINI_API_KEY="your_key"
python src/main.py --config config/config_promptintel.yaml
```

### For Production
```bash
# Use OpenAI or Anthropic with circuit breakers and rate limiting
export OPENAI_API_KEY="your_key"
python src/main.py --config config/config.yaml
```

---

## 🔒 Security Best Practices

### ❌ DON'T DO THIS:
```python
# Hardcoding keys is insecure!
api_key = "sk-1234567890abcdef"
```

### ✅ DO THIS:
```python
import os

# Get from environment
api_key = os.getenv("GEMINI_API_KEY")

# Or use .env file
from dotenv import load_dotenv
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
```

### Create a `.env` file (don't commit to git!):
```
# .env
GEMINI_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here
PROMPTINTEL_API_KEY=your_key_here
ANTHROPIC_API_KEY=your_key_here
```

### Add to `.gitignore`:
```
# .gitignore
.env
.env.local
*.key
secrets/
```

---

## 🧪 Testing Your Setup

### Test Gemini:
```bash
python -c "
from adapters.base import ModelConfig, ModelType
from adapters.gemini_adapter import GeminiAdapter
import asyncio
import os

async def test():
    config = ModelConfig(
        name='test',
        model_type=ModelType.GEMINI_API,
        api_key=os.getenv('GEMINI_API_KEY'),
        model_name='gemini-2.5-flash'
    )
    adapter = GeminiAdapter(config)
    await adapter.initialize()
    print('✅ Gemini API works!')

asyncio.run(test())
"
```

### Test Ollama:
```bash
curl http://localhost:11434/api/tags
# Should return list of available models
```

### Test Promptintel:
```bash
export PROMPTINTEL_API_KEY="your_key"
curl -H "Authorization: Bearer $PROMPTINTEL_API_KEY" \
  https://api.promptintel.novahunting.ai/api/v1/health
# Should return: {"status": "healthy"}
```

---

## 💡 Cost Comparison

| Provider | Cost | Setup Time | Privacy | Limits |
|----------|------|-----------|---------|--------|
| Gemini | Free tier ✅ | 5 min | Google | 15 RPM |
| Ollama | Free ✅ | 10 min | Local ✅ | None |
| Promptintel | Free trial | 5 min | Mixed | Varies |
| OpenAI | $$ Paid | 5 min | Remote | High |
| Anthropic | $$ Paid | 5 min | Remote | Medium |

---

## 🚨 Troubleshooting API Keys

### "Invalid API key"
- Check key is copied completely (no extra spaces)
- Verify key is set: `echo $GEMINI_API_KEY`
- Delete and regenerate key if very old

### "Rate limit exceeded"
- Reduce `rate_limit_rpm` in config
- Use smaller value like 5 instead of 60
- Increase `delay_between_attacks_ms` to 5000

### "Connection refused"
- Check service is running (especially Ollama)
- Verify endpoint URL is correct
- Test with curl/check logs

### "Quota exceeded"
- Gemini free tier has daily limits
- Switch to Ollama for unlimited local testing
- Or upgrade to paid plan

---

## 📞 Support Links

- **Gemini Support:** https://support.google.com/ai-studio
- **Ollama Issues:** https://github.com/jmorganca/ollama/issues
- **Promptintel Support:** https://promptintel.novahunting.ai/support
- **OpenAI Help:** https://help.openai.com
- **Anthropic Support:** https://support.anthropic.com

---

**Ready to start testing? Pick your provider and follow the setup steps! 🚀**
