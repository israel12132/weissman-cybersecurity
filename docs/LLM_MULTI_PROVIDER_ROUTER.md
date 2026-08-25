# Multi-Provider LLM Router

**Status:** shipped (milestone 2). **Module:** `weissman-engines::llm_router`. **Opt-in.**

## Why

The base LLM client (`weissman-engines::openai_chat`) already provides, **per endpoint**:
retry with backoff, a circuit breaker, health probes, token metering, and model fallback.
What it did *not* do is fail over to a **different provider** when the whole primary endpoint
is down — a dead vLLM node, an exhausted quota, a network partition. For an
intelligence-grade platform the AI path must degrade gracefully across providers, not go dark.

This router adds an **ordered endpoint chain with circuit-aware failover** on top of the
existing machinery. It is **additive and opt-in**: existing single-endpoint callers are
untouched, and with no configuration the router resolves to exactly today's single default
endpoint.

## Configuration

`WEISSMAN_LLM_ENDPOINTS` — a JSON array of endpoints, **primary first**:

```json
[
  {"label":"vllm-local","base_url":"http://127.0.0.1:8000/v1"},
  {"label":"openai","base_url":"https://api.openai.com/v1","model":"gpt-4o-mini"}
]
```

| Field | Required | Meaning |
|---|---|---|
| `base_url` | yes | OpenAI-compatible base URL. Entries without one are dropped. |
| `label` | no | Name for logs/metrics. Defaults to `endpoint-<n>`. |
| `model` | no | Model id. Empty ⇒ resolved from `WEISSMAN_LLM_MODEL` / default at call time. |

Unset / empty / invalid ⇒ a single default endpoint from `WEISSMAN_LLM_BASE_URL` (or the
built-in default), preserving current behavior. Auth reuses `WEISSMAN_LLM_API_KEY`,
then the OpenAI alias `OPENAI_API_KEY`.

## Behavior

- **Ordering** (`failover_order`): circuit-**closed** endpoints first (in config order), then
  open-circuit ones last — so a total outage still *attempts* every provider instead of giving
  up early.
- **Failover** (`routed_chat_completion_text`): try endpoints in that order; on a **retryable**
  error (transport / 5xx / 429 / timeout / circuit-open) fail over to the next. A
  **non-retryable** client-side error (bad-request decode, empty content) returns immediately —
  failing over would just repeat it.
- Each endpoint's own **retry + circuit breaker** still apply inside `chat_completion_text`, so
  the router layers *provider* failover on top of *request* retry, not instead of it.

## Observability

| Metric | Labels | Meaning |
|---|---|---|
| `weissman_llm_router_requests_total` | `endpoint`, `outcome` (`success` / `failover` / `error`) | Per-endpoint outcome of each routed attempt. |
| `weissman_llm_router_exhausted_total` | — | Every configured endpoint failed for one request (total AI outage). |

Wire these into the Grafana/Prometheus layer (`deploy/observability`). A rising `failover`
rate on the primary endpoint is an early warning; any `exhausted` increment is a page.

## Runbook — "AI features degraded / erroring"

1. **Scope it.** Check `weissman_llm_router_requests_total`:
   - primary `success` steady ⇒ not a routing problem.
   - primary `failover` rising, secondary `success` rising ⇒ **failover is working**; the
     primary provider is unhealthy — investigate that endpoint (vLLM node, quota, network).
   - `weissman_llm_router_exhausted_total` climbing ⇒ **all** providers down; page. Check each
     `base_url`'s `/v1/models` reachability and credentials.
2. **Add capacity/headroom.** Append a healthy provider to `WEISSMAN_LLM_ENDPOINTS` (e.g. a
   hosted OpenAI-compatible endpoint) so the chain has a fallback. Order matters — cheapest/
   fastest first.
3. **Verify.** After the config change, watch a routed operation: the primary should carry
   traffic (`success`), and pulling the primary should shift traffic to the next endpoint
   within one circuit-open window (default 45s) without user-visible failures.

## Adoption & follow-ups

- **Opt-in today:** call `llm_router::routed_chat_completion_text(...)` (plain text) or
  `llm_router::routed_chat_completion_text_json_object(...)` (JSON-mode) instead of the direct
  `openai_chat::chat_completion_text(...)`. Both carry the full failover chain.
- **Already migrated:** the natural-language query planner (`nl_query.rs` uses the routed
  JSON-object variant) and generative fuzzing (`generative_fuzz_llm.rs` uses the routed text
  variant). Still direct and unmigrated: the reporter (`reporter.rs`) and the ~40 engine call
  sites that call `openai_chat::chat_completion_text` — a mechanical follow-up.
- **Planned:** per-endpoint API keys (today all endpoints share `WEISSMAN_LLM_API_KEY`);
  weighted / cost-aware routing; a routed variant for the embedding path
  (`openai_chat::create_embedding` has no router wrapper yet).
