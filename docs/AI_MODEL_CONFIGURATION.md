# AI Model Configuration Guide

## Overview

Weissman Cybersecurity uses local vLLM (OpenAI-compatible) servers for AI-powered security testing. This guide explains how to configure AI models correctly.

## Fixed Issues (May 2026)

### Previous Problems
1. **Non-existent models**: Code referenced `Llama-4` (not released), `Mistral-Large-3` (doesn't exist), and `DeepSeek-Coder-V3` (incorrect name)
2. **OpenAI models in local setup**: Default models like `gpt-4o-mini` and `text-embedding-3-small` required OpenAI API
3. **No fallback logic**: If configured model unavailable, system would fail completely
4. **No model validation**: No checks if model exists before attempting to use it

### Current Solutions
1. **Real model names**: Updated to actual HuggingFace model IDs that exist
2. **Local-first defaults**: All defaults now point to models that can run on vLLM
3. **Automatic fallback**: System tries backup models if primary unavailable
4. **Model validation**: Can check `/v1/models` endpoint to verify availability

## Default Models

### Supreme Council (Multi-Agent Debate)
When `WEISSMAN_SUPREME_COUNCIL=1`:

- **Offensive Proposer**: `deepseek-ai/deepseek-coder-33b-instruct`
  - Generates exploit strategies
  - Alternative: `meta-llama/Meta-Llama-3.1-70B-Instruct`

- **Defensive Critic**: `mistralai/Mistral-Large-Instruct-2407`
  - Evaluates stealth and detection risks
  - Alternative: `meta-llama/Meta-Llama-3.1-70B-Instruct`

- **Sovereign General**: `meta-llama/Meta-Llama-3.1-70B-Instruct`
  - Final authority on attack execution
  - Alternative: `deepseek-ai/deepseek-coder-33b-instruct`

### General Purpose
- **Default Model**: `meta-llama/Llama-3.2-3B-Instruct`
  - Used for: fuzzing, path prediction, vulnerability analysis
  - Lightweight and fast for general security scanning

### Embeddings
- **Default Model**: `BAAI/bge-small-en-v1.5`
  - Used for: semantic memory, vector search, similarity matching
  - Runs locally via vLLM `/v1/embeddings` endpoint

## Configuration Methods

### 1. Environment Variables

```bash
# Base vLLM URL (must include /v1)
export WEISSMAN_LLM_BASE_URL="http://127.0.0.1:8000/v1"

# Default model for all operations
export WEISSMAN_LLM_MODEL="meta-llama/Llama-3.2-3B-Instruct"

# Optional: Bearer token if vLLM has authentication
export WEISSMAN_LLM_API_KEY="your-token-here"

# Supreme Council specific models (optional overrides)
export WEISSMAN_COUNCIL_MODEL_CODER="deepseek-ai/deepseek-coder-33b-instruct"
export WEISSMAN_COUNCIL_MODEL_GENERALIST="mistralai/Mistral-Large-Instruct-2407"
export WEISSMAN_COUNCIL_MODEL_SYNTHESIZER="meta-llama/Meta-Llama-3.1-70B-Instruct"

# Embedding model for semantic memory
export WEISSMAN_COUNCIL_EMBEDDING_MODEL="BAAI/bge-small-en-v1.5"
```

### 2. Database Configuration (Per-Tenant)

Models can be configured per tenant in the `system_configs` table:

```sql
INSERT INTO system_configs (tenant_id, key, value, description)
VALUES
    (1, 'llm_base_url', 'http://127.0.0.1:8000/v1', 'vLLM server URL'),
    (1, 'llm_model', 'meta-llama/Llama-3.2-3B-Instruct', 'Default model ID');
```

## Fallback Chain

If primary model unavailable, system automatically tries:

1. Primary configured model
2. `meta-llama/Llama-3.2-3B-Instruct` (default fallback)
3. `meta-llama/Meta-Llama-3.1-8B-Instruct`
4. `mistralai/Mistral-7B-Instruct-v0.2`
5. `mistralai/Mistral-7B-Instruct-v0.3`

System logs warnings when using fallback models.

## Setting Up vLLM

### Option 1: Docker (Recommended for Testing)

```bash
# Pull and run vLLM with Llama 3.2
docker run --gpus all \
  -p 8000:8000 \
  --name vllm \
  vllm/vllm-openai:latest \
  --model meta-llama/Llama-3.2-3B-Instruct \
  --dtype auto \
  --api-key optional-token
```

### Option 2: NixOS Module

See `nix/nixos-modules/weissman-vllm.nix` for declarative configuration.

### Option 3: Manual Installation

```bash
pip install vllm
python -m vllm.entrypoints.openai.api_server \
  --model meta-llama/Llama-3.2-3B-Instruct \
  --host 0.0.0.0 \
  --port 8000
```

## Model Requirements

### Hardware Recommendations

| Model | VRAM | RAM | Notes |
|-------|------|-----|-------|
| Llama-3.2-3B | 8GB | 16GB | Good for testing |
| Llama-3.1-8B | 16GB | 32GB | Balanced |
| Llama-3.1-70B | 80GB+ | 128GB+ | Production quality |
| DeepSeek-Coder-33B | 40GB | 64GB | Code-focused |
| Mistral-Large | 80GB+ | 128GB+ | General purpose |
| bge-small-en (embedding) | 1GB | 4GB | Lightweight |

### CPU-Only Mode

For CPU inference (slower but works without GPU):

```bash
export OMP_NUM_THREADS=32  # Match your CPU threads
export VLLM_CPU_KVCACHE_SPACE=40  # GB of RAM for cache

python -m vllm.entrypoints.openai.api_server \
  --model meta-llama/Llama-3.2-3B-Instruct \
  --device cpu
```

## Verifying Model Availability

### Check via API

```bash
curl http://127.0.0.1:8000/v1/models
```

Expected response:
```json
{
  "object": "list",
  "data": [
    {
      "id": "meta-llama/Llama-3.2-3B-Instruct",
      "object": "model",
      "created": 1234567890,
      "owned_by": "vllm"
    }
  ]
}
```

### Check via Code

The system automatically validates models:

```rust
use weissman_engines::openai_chat;

// Check if model is available
let client = openai_chat::llm_http_client(30);
let available = openai_chat::check_model_available(
    &client,
    "http://127.0.0.1:8000/v1",
    "meta-llama/Llama-3.2-3B-Instruct"
).await?;

// Resolve with automatic fallback
let model = openai_chat::resolve_model_with_fallback(
    &client,
    "http://127.0.0.1:8000/v1",
    "my-preferred-model"
).await?;
```

## Deployment Modes

### Mode 1: Local vLLM (Recommended)
- Run vLLM locally on same or dedicated server
- Use `http://127.0.0.1:8000/v1` or `http://vllm-host:8000/v1`
- No API keys needed (optional auth)
- Full control over models

### Mode 2: OpenAI API
- Use OpenAI cloud service
- Set `WEISSMAN_LLM_BASE_URL="https://api.openai.com/v1"`
- Set `WEISSMAN_LLM_API_KEY="sk-..."`
- Set `WEISSMAN_LLM_MODEL="gpt-4o-mini"`
- Higher cost but no local hardware needed

### Mode 3: Ollama
- Run Ollama locally (its OpenAI-compatible server listens on port `11434`)
- Set `WEISSMAN_LLM_BASE_URL="http://127.0.0.1:11434"` (or the `llm_base_url` system_config).
  `normalize_openai_base_url` appends `/v1` automatically, so it reaches Ollama's
  OpenAI-compatible `/v1/chat/completions` endpoint — do **not** add `/v1` yourself.
- Limited OpenAI compatibility
- Note: the legacy `ollama_base_url` tenant config is **not** read by the LLM path. Migration
  `20250406120000_llm_vllm_system_configs.sql` seeds `llm_base_url` from it once; thereafter all
  AI features read `llm_base_url` / `WEISSMAN_LLM_BASE_URL`.

## Troubleshooting

### Error: "LLM unreachable"
- Check vLLM is running: `curl http://127.0.0.1:8000/v1/models`
- Verify URL includes `/v1`: `http://127.0.0.1:8000/v1` not `http://127.0.0.1:8000`
- Check firewall/network connectivity

### Error: "Model not found"
- List available models: `curl http://127.0.0.1:8000/v1/models`
- Ensure model name matches exactly (case-sensitive)
- Check vLLM logs for model loading errors

### Error: "Circuit breaker open"
- vLLM failed 3+ times, circuit opened for 45 seconds
- Check vLLM logs for out-of-memory or crashes
- Reduce model size or increase hardware

### Error: "Empty content"
- Model returned no text (possible crash or OOM)
- Check vLLM memory usage
- Try smaller model

### Warning: "Using fallback model"
- Primary model unavailable, automatic fallback activated
- This is normal if you haven't loaded all models
- Check logs for which fallback was used

## Best Practices

1. **Start Small**: Begin with Llama-3.2-3B for testing
2. **Scale Up**: Move to 8B or 70B models for production
3. **Monitor Memory**: Watch VRAM/RAM usage during scans
4. **Use Fallbacks**: Don't load all models, let fallback handle missing ones
5. **Separate Inference**: Run vLLM on dedicated hardware if possible
6. **Cache Models**: Store model weights locally to avoid re-downloading
7. **Validate First**: Always check `/v1/models` before full deployment

## Security Considerations

1. **Model Source**: Only use models from trusted sources (HuggingFace verified)
2. **API Authentication**: Use `WEISSMAN_LLM_API_KEY` if vLLM is exposed
3. **Network Isolation**: Keep vLLM on internal network
4. **Resource Limits**: Set memory limits to prevent DoS
5. **Audit Logs**: All LLM calls are logged in `tenant_llm_usage` table

## References

- [vLLM Documentation](https://docs.vllm.ai/)
- [OpenAI API Compatibility](https://platform.openai.com/docs/api-reference)
- [HuggingFace Model Hub](https://huggingface.co/models)
- [Supreme Council Architecture](./SOC_ENGINES_ARCHITECTURE.md)
