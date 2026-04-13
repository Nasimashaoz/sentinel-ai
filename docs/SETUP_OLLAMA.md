# Using Sentinel AI Fully Offline with Ollama

Run AI-powered threat analysis with **zero internet, zero API cost** using a local LLM.

## Step 1 — Install Ollama

```bash
# Linux/macOS
curl -fsSL https://ollama.ai/install.sh | sh

# Verify
ollama --version
```

## Step 2 — Pull a Model

| Model | Size | Speed | Quality |
|---|---|---|---|
| `llama3` | 4.7 GB | Fast | ⭐⭐⭐⭐⭐ |
| `mistral` | 4.1 GB | Fastest | ⭐⭐⭐⭐ |
| `gemma2:2b` | 1.6 GB | Very Fast | ⭐⭐⭐ |
| `phi3` | 2.3 GB | Fast | ⭐⭐⭐⭐ |

```bash
ollama pull llama3   # recommended
```

## Step 3 — Configure Sentinel AI

Edit `.env`:
```env
# Disable Claude (or keep it as fallback)
# CLAUDE_API_KEY=

# Enable Ollama
OLLAMA_ENABLED=true
OLLAMA_MODEL=llama3
OLLAMA_BASE_URL=http://localhost:11434
```

## Step 4 — Verify

```bash
python -c "
import asyncio
from dotenv import load_dotenv; load_dotenv()
from core.ollama_analyzer import OllamaAnalyzer
analyzer = OllamaAnalyzer()
asyncio.run(analyzer.health_check())
"
```

## Why Use Ollama?

- ✅ **Zero cost** — no API bills, ever
- ✅ **Fully offline** — works with no internet
- ✅ **Private** — your threat data never leaves the machine
- ✅ **Fast** — llama3 on a modern CPU: ~5-10 seconds per analysis
