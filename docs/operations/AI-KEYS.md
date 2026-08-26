# AI keys — what to supply, and how Weissman uses them

This is the operator checklist for **every** AI and enrichment secret the
platform can consume. Secrets are never returned by the API: `GET /api/ai/readiness`
exposes only `configured` plus a SHA-256 fingerprint prefix.

The Command Center page is **AI Key Readiness** (`/command-center/ai-readiness`).
The advisory script is `node scripts/verify_ai_keys.mjs` (wired into
`scripts/full_audit_gate.sh`; it does not fail the gate).

## How failover works

1. If `WEISSMAN_LLM_ENDPOINTS` is a JSON array of `{label, base_url, model?, provider?, api_key_env?, auth?}`, that chain is used as-is.
2. If that variable is unset, `weissman-engines::llm_providers::discover_endpoints` builds a chain from whichever provider keys are present.
3. If nothing is present, the historical default (`WEISSMAN_LLM_BASE_URL` or `http://127.0.0.1:8000/v1`) is used so local vLLM keeps working.

Per-endpoint keys are applied at call time (`Bearer`, Anthropic `x-api-key`, Azure `api-key`). Direct `openai_chat` callers that do not go through the router still use `WEISSMAN_LLM_API_KEY` as a Bearer token.

## LLM providers

| Env var | Provider | Notes |
|---|---|---|
| `WEISSMAN_LLM_BASE_URL` | Self-hosted vLLM / OpenAI-compatible | Pair with `WEISSMAN_LLM_API_KEY` if the gateway requires auth. Alias: `LLM_BASE_URL`. |
| `WEISSMAN_LLM_API_KEY` | vLLM / generic Bearer | Also the fallback for endpoints that do not name `api_key_env`. |
| `WEISSMAN_LLM_MODEL` | Default model id | Used when an endpoint omits `model`. |
| `WEISSMAN_LLM_ENDPOINTS` | Explicit failover JSON | See `docs/LLM_MULTI_PROVIDER_ROUTER.md`. |
| `OPENAI_API_KEY` | OpenAI | `https://api.openai.com/v1` |
| `ANTHROPIC_API_KEY` | Anthropic | `x-api-key` + `anthropic-version: 2023-06-01` |
| `GEMINI_API_KEY` | Google Gemini | OpenAI-compat: `generativelanguage.googleapis.com/v1beta/openai` |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI | Requires `AZURE_OPENAI_ENDPOINT` + `AZURE_OPENAI_DEPLOYMENT`. Optional `AZURE_OPENAI_API_VERSION` (default `2024-10-21`). |
| `GROQ_API_KEY` | Groq | |
| `MISTRAL_API_KEY` | Mistral | |
| `DEEPSEEK_API_KEY` | DeepSeek | |
| `OPENROUTER_API_KEY` | OpenRouter | |
| `TOGETHER_API_KEY` | Together AI | |
| `XAI_API_KEY` | xAI | |
| `PERPLEXITY_API_KEY` | Perplexity | |
| `FIREWORKS_API_KEY` | Fireworks | |
| `COHERE_API_KEY` | Cohere | compatibility API |
| `OLLAMA_HOST` | Ollama | URL or `host:port`; auto-appends `/v1`. Optional `OLLAMA_MODEL`. |

Override a discovered provider's URL/model with `WEISSMAN_<ID>_BASE_URL` / `WEISSMAN_<ID>_MODEL` (id uppercased, hyphens become underscores is **not** applied — use the id as listed, e.g. `WEISSMAN_OPENAI_BASE_URL`).

## Enrichment keys (recon / intel)

| Env var | Used by |
|---|---|
| `WEISSMAN_SHODAN_API_KEY` | `iot_shodan_scan` and related recon. Alias: `SHODAN_API_KEY`. |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | Censys recon (Python + documented production template). |
| `NVD_API_KEY` / `WEISSMAN_NVD_API_KEY` | NVD CVE feed rate limits. |
| `GITHUB_TOKEN` / `WEISSMAN_GITHUB_TOKEN` | GitHub advisory / OSINT pulls. |

## Probe

`POST /api/ai/readiness/probe` (authenticated) hits the primary endpoint's `/models` with a 4s timeout and returns HTTP status + latency. It never echoes the key.

## After you set keys

Restart `weissman-server` (and the worker if it also talks to the LLM). Then open `/command-center/ai-readiness` and confirm the provider row is **ready** with a fingerprint, and run **Probe primary endpoint**.
