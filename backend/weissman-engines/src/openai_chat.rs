//! OpenAI-compatible HTTP client (local vLLM: `/v1/chat/completions`).
//! Circuit breaker, health probes, structured errors, token metering hook, prompt sanitization.
//! Model fallback: if primary model unavailable, tries fallback list automatically.
//!
//! **Transport:** Sub-millisecond zero-copy shared memory between this client and Python vLLM
//! would need a bespoke colocated plugin plus a non-HTTP wire format on both sides. The supported
//! path remains HTTP JSON against stock OpenAI-compatible servers (loopback UDS/TCP tuning is deployment-level).

use crate::llm_sanitize;
use dashmap::DashMap;
use serde::Serialize;
use serde_json::{json, Value};
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Default when `llm_base_url` / env is empty: vLLM OpenAI API on loopback.
pub const DEFAULT_LLM_BASE_URL: &str = "http://127.0.0.1:8000/v1";

/// Default model id if tenant `llm_model` is empty (override per deployment).
pub const DEFAULT_LLM_MODEL: &str = "meta-llama/Llama-3.2-3B-Instruct";

const CIRCUIT_FAILURE_THRESHOLD: u32 = 3;
const CIRCUIT_OPEN_SECS: u64 = 45;
const HEALTH_PROBE_TTL: Duration = Duration::from_secs(20);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const LLM_RETRY_ATTEMPTS: u32 = 3;
const LLM_RETRY_INITIAL_BACKOFF_MS: u64 = 250;
const LLM_RETRY_MAX_BACKOFF_MS: u64 = 2_000;

/// Optional global hook: `(tenant_id, prompt_tokens, completion_tokens, model, operation)` — typically spawns DB insert.
pub type LlmUsageReporter = Arc<dyn Fn(i64, u32, u32, String, &'static str) + Send + Sync>;

static LLM_USAGE_REPORTER: OnceLock<Mutex<Option<LlmUsageReporter>>> = OnceLock::new();

fn usage_reporter_slot() -> &'static Mutex<Option<LlmUsageReporter>> {
    LLM_USAGE_REPORTER.get_or_init(|| Mutex::new(None))
}

/// Register token metering (e.g. from `fingerprint_engine` startup). Idempotent last-wins.
pub fn set_llm_usage_reporter(r: LlmUsageReporter) {
    if let Ok(mut g) = usage_reporter_slot().lock() {
        *g = Some(r);
    }
}

fn fire_usage_reporter(
    tenant_id: Option<i64>,
    prompt_tokens: u32,
    completion_tokens: u32,
    model: &str,
    operation: &'static str,
) {
    let Some(tid) = tenant_id else {
        return;
    };
    let Ok(guard) = usage_reporter_slot().lock() else {
        return;
    };
    if let Some(f) = guard.as_ref() {
        f(
            tid,
            prompt_tokens,
            completion_tokens,
            model.to_string(),
            operation,
        );
    }
}

struct CircuitEntry {
    failures: u32,
    open_until: Option<Instant>,
}

fn circuit_map() -> &'static DashMap<String, CircuitEntry> {
    static M: OnceLock<DashMap<String, CircuitEntry>> = OnceLock::new();
    M.get_or_init(DashMap::new)
}

fn circuit_key(base_url: &str) -> String {
    normalize_openai_base_url(base_url)
}

fn circuit_check(base_url: &str) -> Result<(), LlmError> {
    let key = circuit_key(base_url);
    let mut e = circuit_map().entry(key).or_insert(CircuitEntry {
        failures: 0,
        open_until: None,
    });
    if let Some(until) = e.open_until {
        if Instant::now() < until {
            let secs = until
                .saturating_duration_since(Instant::now())
                .as_secs()
                .max(1);
            return Err(LlmError::CircuitOpen {
                cooldown_secs: secs,
            });
        }
        e.open_until = None;
        e.failures = 0;
    }
    Ok(())
}

fn circuit_on_success(base_url: &str) {
    circuit_map().insert(
        circuit_key(base_url),
        CircuitEntry {
            failures: 0,
            open_until: None,
        },
    );
}

fn circuit_on_failure(base_url: &str) {
    let key = circuit_key(base_url);
    let mut e = circuit_map().entry(key).or_insert(CircuitEntry {
        failures: 0,
        open_until: None,
    });
    e.failures = e.failures.saturating_add(1);
    if e.failures >= CIRCUIT_FAILURE_THRESHOLD {
        e.open_until = Some(Instant::now() + Duration::from_secs(CIRCUIT_OPEN_SECS));
    }
}

/// True when the circuit breaker for `base_url` is currently open (cooling down after
/// repeated failures). Used by the multi-provider router to skip a known-bad endpoint.
#[must_use]
pub fn endpoint_circuit_open(base_url: &str) -> bool {
    matches!(circuit_check(base_url), Err(LlmError::CircuitOpen { .. }))
}

fn health_cache() -> &'static DashMap<String, Instant> {
    static H: OnceLock<DashMap<String, Instant>> = OnceLock::new();
    H.get_or_init(DashMap::new)
}

/// GET `/v1/models` with short timeout. Throttled per base URL.
async fn ensure_llm_reachable(_client: &reqwest::Client, base_url: &str) -> Result<(), LlmError> {
    let base = normalize_openai_base_url(base_url)
        .trim_end_matches('/')
        .to_string();
    let key = base.clone();
    {
        if let Some(t) = health_cache().get(&key) {
            if t.elapsed() < HEALTH_PROBE_TTL {
                return Ok(());
            }
        }
    }
    let url = format!("{}/models", base);
    let probe = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(HEALTH_TIMEOUT)
        .build()
        .map_err(|e| LlmError::Unreachable(e.to_string()))?
        .get(&url);
    let probe = apply_bearer(probe);
    let resp = probe.send().await.map_err(|e| {
        if e.is_timeout() {
            LlmError::Timeout
        } else {
            LlmError::Unreachable(e.to_string())
        }
    })?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let preview = body.chars().take(512).collect();
        return Err(LlmError::Http {
            status,
            body_preview: preview,
        });
    }
    health_cache().insert(key, Instant::now());
    Ok(())
}

fn apply_bearer(mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Some(ref k) = llm_api_key_from_env() {
        req = req.header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", k.trim()),
        );
    }
    crate::llm_handshake::apply_to_request(req)
}

/// JSON shape for API / job results when LLM fails.
#[derive(Debug, Clone, Serialize)]
pub struct LlmClientErrorBody {
    pub code: &'static str,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

/// Structured LLM failure (maps to frontend-facing `LlmClientErrorBody`).
#[derive(Debug, Clone)]
pub enum LlmError {
    CircuitOpen { cooldown_secs: u64 },
    Unreachable(String),
    Http { status: u16, body_preview: String },
    Timeout,
    Decode(String),
    EmptyContent,
    InternalLock,
}

impl LlmError {
    #[must_use]
    pub fn to_client_value(&self) -> Value {
        serde_json::to_value(self.client_body()).unwrap_or(json!({"code": "llm_error"}))
    }

    /// Whether retrying — or failing over to another provider endpoint — may succeed.
    /// Transport/5xx/429/timeout/circuit errors are retryable; client-side errors
    /// (bad request decode, empty content) are not — failover would just repeat them.
    #[must_use]
    pub fn retryable(&self) -> bool {
        self.client_body().retryable
    }

    /// Whether *this endpoint* cannot serve the request but *another* provider in the failover
    /// chain still might — i.e. the router should advance to the next endpoint rather than abort.
    /// Covers all retryable transport/5xx/429 errors plus endpoint-fatal-but-request-valid cases:
    /// auth failure (401/403), model-not-found (404), and empty content from a hung/OOM upstream.
    /// A genuinely bad request (400/422/…) is NOT chain-continuable: every endpoint rejects it
    /// identically, so the router returns it immediately.
    #[must_use]
    pub fn should_try_next_endpoint(&self) -> bool {
        if self.retryable() {
            return true;
        }
        match self {
            LlmError::Http { status, .. } => matches!(status, 401 | 403 | 404),
            LlmError::EmptyContent => true,
            _ => false,
        }
    }

    fn client_body(&self) -> LlmClientErrorBody {
        match self {
            LlmError::CircuitOpen { cooldown_secs } => LlmClientErrorBody {
                code: "llm_circuit_open",
                message: "LLM service temporarily unavailable after repeated failures".into(),
                retryable: true,
                detail: Some(json!({"cooldown_secs": cooldown_secs})),
            },
            LlmError::Unreachable(msg) => LlmClientErrorBody {
                code: "llm_unreachable",
                message: msg.clone(),
                retryable: true,
                detail: None,
            },
            LlmError::Http {
                status,
                body_preview,
            } => LlmClientErrorBody {
                code: "llm_http_error",
                message: format!("LLM returned HTTP {}", status),
                retryable: *status == 429 || (500..600).contains(status),
                detail: Some(json!({"http_status": status, "body_preview": body_preview})),
            },
            LlmError::Timeout => LlmClientErrorBody {
                code: "llm_timeout",
                message: "LLM request timed out".into(),
                retryable: true,
                detail: None,
            },
            LlmError::Decode(msg) => LlmClientErrorBody {
                code: "llm_bad_response",
                message: msg.clone(),
                retryable: false,
                detail: None,
            },
            LlmError::EmptyContent => LlmClientErrorBody {
                code: "llm_empty_content",
                message: "LLM returned no assistant text".into(),
                retryable: false,
                detail: None,
            },
            LlmError::InternalLock => LlmClientErrorBody {
                code: "llm_internal",
                message: "LLM client internal error".into(),
                retryable: true,
                detail: None,
            },
        }
    }
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.client_body().message)
    }
}

fn is_retryable_llm_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

fn llm_retry_delay(attempt: u32) -> Duration {
    let exponent = attempt.saturating_sub(1).min(8);
    let delay_ms = LLM_RETRY_INITIAL_BACKOFF_MS
        .saturating_mul(2_u64.saturating_pow(exponent))
        .min(LLM_RETRY_MAX_BACKOFF_MS);
    Duration::from_millis(delay_ms)
}

fn record_llm_outcome(started: Instant, outcome: &'static str) {
    metrics::histogram!("weissman_llm_inference_seconds", "outcome" => outcome)
        .record(started.elapsed().as_secs_f64());
}

fn record_llm_error_outcome(started: Instant, error: &LlmError) {
    let outcome = match error {
        LlmError::Timeout => "timeout",
        LlmError::Http { .. } => "http_error",
        LlmError::Decode(_) => "decode",
        LlmError::EmptyContent => "empty",
        _ => "error",
    };
    record_llm_outcome(started, outcome);
}

async fn send_with_llm_retry<F, Fut>(
    base_url: &str,
    operation: &'static str,
    mut make_request: F,
) -> Result<reqwest::Response, LlmError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    for attempt in 1..=LLM_RETRY_ATTEMPTS {
        match make_request().await {
            Ok(resp) if resp.status().is_success() => return Ok(resp),
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body_preview = resp.text().await.unwrap_or_default();
                let retryable = is_retryable_llm_status(status) && attempt < LLM_RETRY_ATTEMPTS;

                if retryable {
                    tracing::warn!(
                        operation,
                        base_url = %base_url,
                        attempt,
                        status,
                        "LLM request failed; retrying"
                    );
                    tokio::time::sleep(llm_retry_delay(attempt)).await;
                    continue;
                }

                circuit_on_failure(base_url);
                return Err(LlmError::Http {
                    status,
                    body_preview: body_preview.chars().take(1024).collect(),
                });
            }
            Err(err) => {
                let retryable =
                    (err.is_timeout() || err.is_connect()) && attempt < LLM_RETRY_ATTEMPTS;

                if retryable {
                    tracing::warn!(
                        operation,
                        base_url = %base_url,
                        attempt,
                        error = %err,
                        "LLM request transport error; retrying"
                    );
                    tokio::time::sleep(llm_retry_delay(attempt)).await;
                    continue;
                }

                circuit_on_failure(base_url);
                return Err(if err.is_timeout() {
                    LlmError::Timeout
                } else {
                    LlmError::Unreachable(err.to_string())
                });
            }
        }
    }

    circuit_on_failure(base_url);
    Err(LlmError::Unreachable(format!(
        "{}: request failed after retries",
        operation
    )))
}

fn send_with_llm_retry_blocking<F>(
    base_url: &str,
    operation: &'static str,
    mut make_request: F,
) -> Result<reqwest::blocking::Response, LlmError>
where
    F: FnMut() -> Result<reqwest::blocking::Response, reqwest::Error>,
{
    for attempt in 1..=LLM_RETRY_ATTEMPTS {
        match make_request() {
            Ok(resp) if resp.status().is_success() => return Ok(resp),
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body_preview = resp.text().unwrap_or_default();
                let retryable = is_retryable_llm_status(status) && attempt < LLM_RETRY_ATTEMPTS;

                if retryable {
                    tracing::warn!(
                        operation,
                        base_url = %base_url,
                        attempt,
                        status,
                        "LLM request failed; retrying"
                    );
                    std::thread::sleep(llm_retry_delay(attempt));
                    continue;
                }

                circuit_on_failure(base_url);
                return Err(LlmError::Http {
                    status,
                    body_preview: body_preview.chars().take(1024).collect(),
                });
            }
            Err(err) => {
                let retryable =
                    (err.is_timeout() || err.is_connect()) && attempt < LLM_RETRY_ATTEMPTS;

                if retryable {
                    tracing::warn!(
                        operation,
                        base_url = %base_url,
                        attempt,
                        error = %err,
                        "LLM request transport error; retrying"
                    );
                    std::thread::sleep(llm_retry_delay(attempt));
                    continue;
                }

                circuit_on_failure(base_url);
                return Err(if err.is_timeout() {
                    LlmError::Timeout
                } else {
                    LlmError::Unreachable(err.to_string())
                });
            }
        }
    }

    circuit_on_failure(base_url);
    Err(LlmError::Unreachable(format!(
        "{}: request failed after retries",
        operation
    )))
}

/// Normalize base: trim, ensure `/v1` suffix for OpenAI-style paths.
#[must_use]
pub fn normalize_openai_base_url(raw: &str) -> String {
    let s = raw.trim().trim_end_matches('/');
    if s.is_empty() {
        return DEFAULT_LLM_BASE_URL.to_string();
    }
    if s.ends_with("/v1") {
        s.to_string()
    } else {
        format!("{}/v1", s)
    }
}

#[must_use]
pub fn chat_completions_endpoint(base_url: &str) -> String {
    format!(
        "{}/chat/completions",
        normalize_openai_base_url(base_url).trim_end_matches('/')
    )
}

#[must_use]
pub fn embeddings_endpoint(base_url: &str) -> String {
    format!(
        "{}/embeddings",
        normalize_openai_base_url(base_url).trim_end_matches('/')
    )
}

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

/// Resolve model: non-empty `config_model`, else `WEISSMAN_LLM_MODEL`, else [`DEFAULT_LLM_MODEL`].
#[must_use]
pub fn resolve_llm_model(config_model: &str) -> String {
    let t = config_model.trim();
    if !t.is_empty() {
        return t.to_string();
    }
    std::env::var("WEISSMAN_LLM_MODEL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_LLM_MODEL.to_string())
}

/// Optional Bearer for vLLM / proxies (`WEISSMAN_LLM_API_KEY`).
#[must_use]
pub fn llm_api_key_from_env() -> Option<String> {
    std::env::var("WEISSMAN_LLM_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[derive(Debug, Clone)]
pub struct ChatCompletionOutput {
    pub text: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

/// Wrap untrusted user-controlled segments before they are placed in the user message (re-export).
#[must_use]
pub fn wrap_untrusted_user_input(raw: &str) -> String {
    llm_sanitize::sanitize_untrusted_user_text(raw)
}

/// Single-shot chat completion with circuit breaker, health probe, metering hook, optional sanitization.
pub async fn chat_completion_text(
    client: &reqwest::Client,
    base_url: &str,
    model: &str,
    system: Option<&str>,
    user: &str,
    temperature: f64,
    max_tokens: u32,
    tenant_id: Option<i64>,
    operation: &'static str,
    sanitize_user_input: bool,
) -> Result<String, LlmError> {
    let out = chat_completion_detailed(
        client,
        base_url,
        model,
        system,
        user,
        temperature,
        max_tokens,
        tenant_id,
        operation,
        sanitize_user_input,
    )
    .await?;
    Ok(out.text)
}

pub async fn chat_completion_detailed(
    client: &reqwest::Client,
    base_url: &str,
    model: &str,
    system: Option<&str>,
    user: &str,
    temperature: f64,
    max_tokens: u32,
    tenant_id: Option<i64>,
    operation: &'static str,
    sanitize_user_input: bool,
) -> Result<ChatCompletionOutput, LlmError> {
    circuit_check(base_url)?;
    if let Err(e) = ensure_llm_reachable(client, base_url).await {
        circuit_on_failure(base_url);
        return Err(e);
    }

    let user_msg = if sanitize_user_input {
        wrap_untrusted_user_input(user)
    } else {
        user.to_string()
    };
    let user_ref = user_msg.as_str();

    let url = chat_completions_endpoint(base_url);
    let mut messages: Vec<ChatMessage<'_>> = Vec::new();
    if let Some(s) = system {
        if !s.trim().is_empty() {
            messages.push(ChatMessage {
                role: "system",
                content: s,
            });
        }
    }
    messages.push(ChatMessage {
        role: "user",
        content: user_ref,
    });
    let body = json!({
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": false,
    });

    let t0 = std::time::Instant::now();
    let resp = match send_with_llm_retry(base_url, operation, || {
        let body = body.clone();
        let mut req = client.post(&url).json(&body);
        req = apply_bearer(req);
        async move { req.send().await }
    })
    .await
    {
        Ok(r) => r,
        Err(err) => {
            record_llm_error_outcome(t0, &err);
            return Err(err);
        }
    };

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let txt = resp.text().await.unwrap_or_default();
        let preview = txt.chars().take(1024).collect();
        return Err(LlmError::Http {
            status,
            body_preview: preview,
        });
    }

    let data: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            circuit_on_failure(base_url);
            metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "decode")
                .record(t0.elapsed().as_secs_f64());
            return Err(LlmError::Decode(e.to_string()));
        }
    };

    let pt = data
        .pointer("/usage/prompt_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let ct = data
        .pointer("/usage/completion_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let text = data
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if text.is_empty() {
        circuit_on_failure(base_url);
        metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "empty")
            .record(t0.elapsed().as_secs_f64());
        return Err(LlmError::EmptyContent);
    }

    circuit_on_success(base_url);
    record_llm_outcome(t0, "ok");
    fire_usage_reporter(tenant_id, pt, ct, model, operation);

    Ok(ChatCompletionOutput {
        text,
        prompt_tokens: pt,
        completion_tokens: ct,
    })
}

/// When false (default), adds OpenAI-style `response_format: { "type": "json_object" }` for constrained JSON.
#[must_use]
pub fn llm_json_response_format_enabled() -> bool {
    !matches!(
        std::env::var("WEISSMAN_LLM_DISABLE_JSON_RESPONSE_FORMAT").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Chat completion with JSON-object mode (vLLM / OpenAI). Fails closed on empty content; no conversational filler expected.
pub async fn chat_completion_text_json_object(
    client: &reqwest::Client,
    base_url: &str,
    model: &str,
    system: Option<&str>,
    user: &str,
    temperature: f64,
    max_tokens: u32,
    tenant_id: Option<i64>,
    operation: &'static str,
    sanitize_user_input: bool,
) -> Result<String, LlmError> {
    let out = chat_completion_detailed_json_object(
        client,
        base_url,
        model,
        system,
        user,
        temperature,
        max_tokens,
        tenant_id,
        operation,
        sanitize_user_input,
    )
    .await?;
    Ok(out.text)
}

pub async fn chat_completion_detailed_json_object(
    client: &reqwest::Client,
    base_url: &str,
    model: &str,
    system: Option<&str>,
    user: &str,
    temperature: f64,
    max_tokens: u32,
    tenant_id: Option<i64>,
    operation: &'static str,
    sanitize_user_input: bool,
) -> Result<ChatCompletionOutput, LlmError> {
    circuit_check(base_url)?;
    if let Err(e) = ensure_llm_reachable(client, base_url).await {
        circuit_on_failure(base_url);
        return Err(e);
    }

    let user_msg = if sanitize_user_input {
        wrap_untrusted_user_input(user)
    } else {
        user.to_string()
    };
    let user_ref = user_msg.as_str();

    let url = chat_completions_endpoint(base_url);
    let mut messages: Vec<ChatMessage<'_>> = Vec::new();
    if let Some(s) = system {
        if !s.trim().is_empty() {
            messages.push(ChatMessage {
                role: "system",
                content: s,
            });
        }
    }
    messages.push(ChatMessage {
        role: "user",
        content: user_ref,
    });
    let mut body = json!({
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": false,
    });
    if llm_json_response_format_enabled() {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("response_format".into(), json!({ "type": "json_object" }));
        }
    }

    let t0 = std::time::Instant::now();
    let resp = match send_with_llm_retry(base_url, operation, || {
        let body = body.clone();
        let mut req = client.post(&url).json(&body);
        req = apply_bearer(req);
        async move { req.send().await }
    })
    .await
    {
        Ok(r) => r,
        Err(err) => {
            record_llm_error_outcome(t0, &err);
            return Err(err);
        }
    };

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let txt = resp.text().await.unwrap_or_default();
        let preview = txt.chars().take(1024).collect();
        return Err(LlmError::Http {
            status,
            body_preview: preview,
        });
    }

    let data: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            circuit_on_failure(base_url);
            metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "decode")
                .record(t0.elapsed().as_secs_f64());
            return Err(LlmError::Decode(e.to_string()));
        }
    };

    let pt = data
        .pointer("/usage/prompt_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let ct = data
        .pointer("/usage/completion_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let mut text = data
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if text.is_empty() {
        circuit_on_failure(base_url);
        metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "empty")
            .record(t0.elapsed().as_secs_f64());
        return Err(LlmError::EmptyContent);
    }
    // Qwen / smaller models may emit markdown fences, truncated braces, or trailing commas — normalize to strict JSON text.
    if serde_json::from_str::<Value>(&text).is_err() {
        if let Ok(v) = crate::llm_json_repair::parse_value_from_llm(&text) {
            text = serde_json::to_string(&v).unwrap_or(text);
        }
    }

    circuit_on_success(base_url);
    record_llm_outcome(t0, "ok");
    fire_usage_reporter(tenant_id, pt, ct, model, operation);

    Ok(ChatCompletionOutput {
        text,
        prompt_tokens: pt,
        completion_tokens: ct,
    })
}

/// OpenAI-compatible `/v1/embeddings` (vLLM / TEI). Used for Supreme Council semantic memory.
pub async fn create_embedding(
    client: &reqwest::Client,
    base_url: &str,
    model: &str,
    input: &str,
    tenant_id: Option<i64>,
    operation: &'static str,
) -> Result<Vec<f32>, LlmError> {
    circuit_check(base_url)?;
    if let Err(e) = ensure_llm_reachable(client, base_url).await {
        circuit_on_failure(base_url);
        return Err(e);
    }
    let input = input.chars().take(12_000).collect::<String>();
    if input.trim().is_empty() {
        return Ok(Vec::new());
    }
    let url = embeddings_endpoint(base_url);
    let body = json!({
        "model": model,
        "input": input,
    });
    let t0 = std::time::Instant::now();
    let resp = match send_with_llm_retry(base_url, operation, || {
        let body = body.clone();
        let mut req = client.post(&url).json(&body);
        req = apply_bearer(req);
        async move { req.send().await }
    })
    .await
    {
        Ok(r) => r,
        Err(err) => {
            record_llm_error_outcome(t0, &err);
            return Err(err);
        }
    };
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let txt = resp.text().await.unwrap_or_default();
        return Err(LlmError::Http {
            status,
            body_preview: txt.chars().take(1024).collect(),
        });
    }
    let data: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            circuit_on_failure(base_url);
            metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "decode")
                .record(t0.elapsed().as_secs_f64());
            return Err(LlmError::Decode(e.to_string()));
        }
    };
    let pt = data
        .pointer("/usage/prompt_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let arr = data
        .pointer("/data/0/embedding")
        .and_then(|v| v.as_array())
        .ok_or_else(|| LlmError::Decode("embeddings: missing data[0].embedding".into()))?;
    let mut out = Vec::with_capacity(arr.len());
    for x in arr {
        let f = x
            .as_f64()
            .ok_or_else(|| LlmError::Decode("embeddings: non-numeric".into()))?;
        out.push(f as f32);
    }
    if out.is_empty() {
        circuit_on_failure(base_url);
        return Err(LlmError::Decode("embeddings: empty vector".into()));
    }
    circuit_on_success(base_url);
    record_llm_outcome(t0, "ok");
    fire_usage_reporter(tenant_id, pt, 0, model, operation);
    Ok(out)
}

/// Build a client with timeout suitable for local inference.
#[must_use]
pub fn llm_http_client(timeout_secs: u64) -> reqwest::Client {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(timeout)
        // Match high fan-out from parallel scan workers to a local vLLM server (Ryzen-class throughput).
        .pool_max_idle_per_host(64)
        .build()
        .unwrap_or_else(|e| {
            // `reqwest::Client::new()` carries NO request timeout, degrading "fail fast" into
            // "hang forever" (the retry wrapper only retries on timeout/connect). Preserve the
            // timeout on the fallback so a stuck endpoint still errors out.
            tracing::error!(target: "llm", error = %e, "llm_http_client builder failed; using timeout-preserving fallback");
            reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .unwrap_or_default()
        })
}

/// Same as [`chat_completion_text`] for synchronous callers (e.g. blocking pipeline analysis).
pub fn chat_completion_text_blocking(
    base_url: &str,
    model: &str,
    system: Option<&str>,
    user: &str,
    temperature: f64,
    max_tokens: u32,
    timeout_secs: u64,
    tenant_id: Option<i64>,
    operation: &'static str,
    sanitize_user_input: bool,
) -> Result<String, LlmError> {
    circuit_check(base_url)?;
    let base = normalize_openai_base_url(base_url)
        .trim_end_matches('/')
        .to_string();
    let url_models = format!("{}/models", base);
    let url = chat_completions_endpoint(base_url);
    let probe = reqwest::blocking::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(HEALTH_TIMEOUT)
        .build()
        .map_err(|e| LlmError::Unreachable(e.to_string()))?;
    let mut probe_req = probe.get(&url_models);
    probe_req = apply_bearer_blocking(probe_req);
    match probe_req.send() {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => {
            let st = r.status().as_u16();
            let body = r.text().unwrap_or_default();
            circuit_on_failure(base_url);
            return Err(LlmError::Http {
                status: st,
                body_preview: body.chars().take(512).collect(),
            });
        }
        Err(e) => {
            circuit_on_failure(base_url);
            return if e.is_timeout() {
                Err(LlmError::Timeout)
            } else {
                Err(LlmError::Unreachable(e.to_string()))
            };
        }
    }

    let user_msg = if sanitize_user_input {
        wrap_untrusted_user_input(user)
    } else {
        user.to_string()
    };
    let user_ref = user_msg.as_str();

    let mut messages: Vec<ChatMessage<'_>> = Vec::new();
    if let Some(s) = system {
        if !s.trim().is_empty() {
            messages.push(ChatMessage {
                role: "system",
                content: s,
            });
        }
    }
    messages.push(ChatMessage {
        role: "user",
        content: user_ref,
    });
    let body = json!({
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": false,
    });
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .build()
        .map_err(|e| LlmError::Unreachable(e.to_string()))?;
    let t0 = std::time::Instant::now();
    let resp = match send_with_llm_retry_blocking(base_url, operation, || {
        let body = body.clone();
        let mut req = client.post(&url).json(&body);
        req = apply_bearer_blocking(req);
        req.send()
    }) {
        Ok(r) => r,
        Err(err) => {
            record_llm_error_outcome(t0, &err);
            return Err(err);
        }
    };
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let txt = resp.text().unwrap_or_default();
        return Err(LlmError::Http {
            status,
            body_preview: txt.chars().take(1024).collect(),
        });
    }
    let data: Value = resp.json().map_err(|e| {
        circuit_on_failure(base_url);
        LlmError::Decode(e.to_string())
    })?;
    let pt = data
        .pointer("/usage/prompt_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let ct = data
        .pointer("/usage/completion_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let text = data
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if text.is_empty() {
        circuit_on_failure(base_url);
        metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "empty")
            .record(t0.elapsed().as_secs_f64());
        return Err(LlmError::EmptyContent);
    }
    circuit_on_success(base_url);
    record_llm_outcome(t0, "ok");
    fire_usage_reporter(tenant_id, pt, ct, model, operation);
    Ok(text)
}

fn apply_bearer_blocking(
    mut req: reqwest::blocking::RequestBuilder,
) -> reqwest::blocking::RequestBuilder {
    if let Some(ref k) = llm_api_key_from_env() {
        req = req.header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", k.trim()),
        );
    }
    crate::llm_handshake::apply_to_blocking_request(req)
}

/// List of fallback models when primary model is unavailable
const FALLBACK_MODELS: &[&str] = &[
    "meta-llama/Llama-3.2-3B-Instruct",
    "meta-llama/Meta-Llama-3.1-8B-Instruct",
    "mistralai/Mistral-7B-Instruct-v0.2",
    "mistralai/Mistral-7B-Instruct-v0.3",
];

/// Check if a model is available on the vLLM/OpenAI server
pub async fn check_model_available(
    client: &reqwest::Client,
    base_url: &str,
    model: &str,
) -> Result<bool, LlmError> {
    let base = normalize_openai_base_url(base_url)
        .trim_end_matches('/')
        .to_string();
    let url = format!("{}/models", base);

    let probe = client.get(&url).timeout(HEALTH_TIMEOUT);
    let probe = apply_bearer(probe);

    let resp = probe.send().await.map_err(|e| {
        if e.is_timeout() {
            LlmError::Timeout
        } else {
            LlmError::Unreachable(e.to_string())
        }
    })?;

    if !resp.status().is_success() {
        return Ok(false);
    }

    let data: Value = resp
        .json()
        .await
        .map_err(|e| LlmError::Decode(e.to_string()))?;

    // Check if model exists in the list
    if let Some(models_arr) = data.pointer("/data").and_then(|v| v.as_array()) {
        for model_entry in models_arr {
            if let Some(id) = model_entry.pointer("/id").and_then(|v| v.as_str()) {
                if id == model || id.contains(model) || model.contains(id) {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

/// Resolve model with fallback: tries primary model, then fallbacks if unavailable
pub async fn resolve_model_with_fallback(
    client: &reqwest::Client,
    base_url: &str,
    primary_model: &str,
) -> Result<String, LlmError> {
    let resolved = resolve_llm_model(primary_model);

    // Try primary model first
    if check_model_available(client, base_url, &resolved)
        .await
        .unwrap_or(false)
    {
        return Ok(resolved);
    }

    // Try fallback models
    for fallback in FALLBACK_MODELS {
        if check_model_available(client, base_url, fallback)
            .await
            .unwrap_or(false)
        {
            tracing::warn!(
                "Primary model '{}' not available, using fallback '{}'",
                resolved,
                fallback
            );
            return Ok(fallback.to_string());
        }
    }

    // If no model is available, return the original resolved model
    // The actual API call will fail with a proper error message
    tracing::error!(
        "No models available on vLLM server at {}, falling back to '{}'",
        base_url,
        resolved
    );
    Ok(resolved)
}
