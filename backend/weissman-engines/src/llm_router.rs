//! Multi-provider LLM router — an ordered chain of OpenAI-compatible endpoints with
//! **circuit-aware failover**.
//!
//! The base client ([`crate::openai_chat`]) already gives us per-endpoint retry, a circuit
//! breaker, and model fallback *within one endpoint*. What it does not do is fail over to a
//! **different provider** when the whole primary endpoint is down (vLLM node dead, quota
//! exhausted, network partition). This module adds that: configure a list of endpoints
//! (primary first) and the router tries healthy ones first, failing over to the next on any
//! retryable error.
//!
//! **Backward compatible:** with no configuration it resolves to the single default endpoint,
//! so existing single-endpoint behavior is byte-for-byte unchanged. It is also **opt-in** —
//! callers reach it via [`routed_chat_completion_text`]; direct `openai_chat` callers are
//! untouched.
//!
//! ## Configuration
//! `WEISSMAN_LLM_ENDPOINTS` — a JSON array of endpoints, primary first:
//! ```json
//! [
//!   {"label":"vllm-local","base_url":"http://127.0.0.1:8000/v1"},
//!   {"label":"openai","base_url":"https://api.openai.com/v1","model":"gpt-4o-mini"}
//! ]
//! ```
//! `model` is optional (empty ⇒ resolved via [`crate::openai_chat::resolve_llm_model`]). Auth
//! reuses the existing `WEISSMAN_LLM_API_KEY` bearer.

use crate::openai_chat::{
    chat_completion_text, endpoint_circuit_open, resolve_llm_model, LlmError, DEFAULT_LLM_BASE_URL,
};
use serde::Deserialize;

/// Env var holding the JSON endpoint chain. See the module docs.
pub const LLM_ENDPOINTS_ENV: &str = "WEISSMAN_LLM_ENDPOINTS";

/// One provider endpoint in the failover chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmEndpoint {
    /// Human label for logs/metrics (e.g. `"openai"`); defaults to `endpoint-<n>`.
    pub label: String,
    /// OpenAI-compatible base URL, e.g. `https://api.openai.com/v1`.
    pub base_url: String,
    /// Model id; empty ⇒ resolved from `WEISSMAN_LLM_MODEL` / default at call time.
    pub model: String,
}

#[derive(Debug, Deserialize)]
struct RawEndpoint {
    #[serde(default)]
    label: String,
    base_url: String,
    #[serde(default)]
    model: String,
}

/// Parse the `WEISSMAN_LLM_ENDPOINTS` JSON payload. Pure (no env access) so it is unit-tested
/// directly. Returns an empty vec for empty/invalid input or when every entry lacks a base_url.
fn parse_endpoints(raw: &str) -> Vec<LlmEndpoint> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(list) = serde_json::from_str::<Vec<RawEndpoint>>(trimmed) else {
        return Vec::new();
    };
    list.into_iter()
        .filter(|e| !e.base_url.trim().is_empty())
        .enumerate()
        .map(|(i, e)| LlmEndpoint {
            label: if e.label.trim().is_empty() {
                format!("endpoint-{i}")
            } else {
                e.label
            },
            base_url: e.base_url,
            model: e.model,
        })
        .collect()
}

/// The single default endpoint used when no chain is configured — mirrors the base client's
/// `WEISSMAN_LLM_BASE_URL` / [`DEFAULT_LLM_BASE_URL`] resolution.
fn default_endpoint() -> LlmEndpoint {
    let base_url = std::env::var("WEISSMAN_LLM_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_LLM_BASE_URL.to_string());
    LlmEndpoint {
        label: "default".to_string(),
        base_url,
        model: String::new(),
    }
}

/// Resolve the ordered endpoint chain from the environment, falling back to the single
/// default endpoint when unset/empty/invalid.
#[must_use]
pub fn resolve_endpoints() -> Vec<LlmEndpoint> {
    let configured = std::env::var(LLM_ENDPOINTS_ENV)
        .ok()
        .map(|raw| parse_endpoints(&raw))
        .unwrap_or_default();
    if configured.is_empty() {
        if std::env::var(LLM_ENDPOINTS_ENV).is_ok_and(|r| !r.trim().is_empty()) {
            tracing::warn!(
                target: "llm_router",
                "WEISSMAN_LLM_ENDPOINTS set but unparseable/empty; using default endpoint"
            );
        }
        vec![default_endpoint()]
    } else {
        configured
    }
}

/// Order endpoints for a failover attempt: circuit-**closed** endpoints first (in config
/// order), then open-circuit ones as a last resort — so a total outage still attempts every
/// provider rather than giving up. `is_open` is injected for testability.
#[must_use]
pub fn failover_order(
    endpoints: &[LlmEndpoint],
    is_open: impl Fn(&str) -> bool,
) -> Vec<&LlmEndpoint> {
    let mut closed = Vec::new();
    let mut open = Vec::new();
    for ep in endpoints {
        if is_open(&ep.base_url) {
            open.push(ep);
        } else {
            closed.push(ep);
        }
    }
    closed.into_iter().chain(open).collect()
}

/// Chat completion with automatic failover across the configured endpoint chain.
///
/// Tries circuit-closed endpoints first; on a **retryable** error (transport / 5xx / 429 /
/// timeout / circuit-open) it fails over to the next endpoint. A non-retryable (client-side)
/// error returns immediately — failing over would just repeat it. Each endpoint's own retry +
/// circuit breaker still apply inside [`chat_completion_text`].
#[allow(clippy::too_many_arguments)]
pub async fn routed_chat_completion_text(
    client: &reqwest::Client,
    system: Option<&str>,
    user: &str,
    temperature: f64,
    max_tokens: u32,
    tenant_id: Option<i64>,
    operation: &'static str,
    sanitize_user_input: bool,
) -> Result<String, LlmError> {
    let endpoints = resolve_endpoints();
    let order = failover_order(&endpoints, endpoint_circuit_open);
    let mut last_err = LlmError::Unreachable("no llm endpoints configured".to_string());

    for ep in order {
        let model = if ep.model.trim().is_empty() {
            resolve_llm_model("")
        } else {
            ep.model.clone()
        };
        match chat_completion_text(
            client,
            &ep.base_url,
            &model,
            system,
            user,
            temperature,
            max_tokens,
            tenant_id,
            operation,
            sanitize_user_input,
        )
        .await
        {
            Ok(text) => {
                metrics::counter!(
                    "weissman_llm_router_requests_total",
                    "endpoint" => ep.label.clone(),
                    "outcome" => "success",
                )
                .increment(1);
                return Ok(text);
            }
            Err(e) => {
                let retryable = e.retryable();
                metrics::counter!(
                    "weissman_llm_router_requests_total",
                    "endpoint" => ep.label.clone(),
                    "outcome" => if retryable { "failover" } else { "error" },
                )
                .increment(1);
                if !retryable {
                    return Err(e);
                }
                tracing::warn!(
                    target: "llm_router",
                    endpoint = %ep.label,
                    "llm endpoint failed with a retryable error; failing over to next"
                );
                last_err = e;
            }
        }
    }

    metrics::counter!("weissman_llm_router_exhausted_total").increment(1);
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(label: &str, base_url: &str, model: &str) -> LlmEndpoint {
        LlmEndpoint {
            label: label.to_string(),
            base_url: base_url.to_string(),
            model: model.to_string(),
        }
    }

    #[test]
    fn parses_ordered_endpoint_chain() {
        let raw = r#"[
            {"label":"vllm","base_url":"http://127.0.0.1:8000/v1"},
            {"label":"openai","base_url":"https://api.openai.com/v1","model":"gpt-4o-mini"}
        ]"#;
        let eps = parse_endpoints(raw);
        assert_eq!(eps.len(), 2);
        assert_eq!(eps[0], ep("vllm", "http://127.0.0.1:8000/v1", ""));
        assert_eq!(
            eps[1],
            ep("openai", "https://api.openai.com/v1", "gpt-4o-mini")
        );
    }

    #[test]
    fn synthesizes_labels_and_drops_entries_without_base_url() {
        let raw = r#"[{"base_url":"http://a/v1"},{"base_url":"  "},{"base_url":"http://b/v1"}]"#;
        let eps = parse_endpoints(raw);
        assert_eq!(eps.len(), 2);
        assert_eq!(eps[0].label, "endpoint-0");
        assert_eq!(eps[0].base_url, "http://a/v1");
        // The blank-base_url entry is filtered before indexing the survivors.
        assert_eq!(eps[1].label, "endpoint-1");
        assert_eq!(eps[1].base_url, "http://b/v1");
    }

    #[test]
    fn invalid_or_empty_payload_parses_to_nothing() {
        assert!(parse_endpoints("").is_empty());
        assert!(parse_endpoints("   ").is_empty());
        assert!(parse_endpoints("not json").is_empty());
        assert!(parse_endpoints("{}").is_empty());
        assert!(parse_endpoints("[]").is_empty());
        assert!(parse_endpoints(r#"[{"model":"x"}]"#).is_empty()); // no base_url
    }

    #[test]
    fn failover_order_prefers_closed_circuits_then_open() {
        let eps = vec![
            ep("a", "http://a/v1", ""),
            ep("b", "http://b/v1", ""),
            ep("c", "http://c/v1", ""),
        ];
        // b is open; expect a, c (closed, config order) then b (open) last.
        let order = failover_order(&eps, |u| u.contains("//b/"));
        let labels: Vec<&str> = order.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(labels, vec!["a", "c", "b"]);
    }

    #[test]
    fn failover_order_all_closed_keeps_config_order() {
        let eps = vec![ep("a", "http://a/v1", ""), ep("b", "http://b/v1", "")];
        let order = failover_order(&eps, |_| false);
        let labels: Vec<&str> = order.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(labels, vec!["a", "b"]);
    }

    #[test]
    fn failover_order_all_open_still_attempts_every_provider() {
        let eps = vec![ep("a", "http://a/v1", ""), ep("b", "http://b/v1", "")];
        let order = failover_order(&eps, |_| true);
        assert_eq!(
            order.len(),
            2,
            "a total outage must still try all endpoints"
        );
        let labels: Vec<&str> = order.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(labels, vec!["a", "b"]);
    }
}
