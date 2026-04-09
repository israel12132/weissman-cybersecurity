//! OpenAI-compatible HTTP client (local vLLM: `/v1/chat/completions`).
//! Circuit breaker, health probes, structured errors, token metering hook, prompt sanitization.
//!
//! **Transport:** Sub-millisecond zero-copy shared memory between this client and Python vLLM
//! would need a bespoke colocated plugin plus a non-HTTP wire format on both sides. The supported
//! path remains HTTP JSON against stock OpenAI-compatible servers (loopback UDS/TCP tuning is deployment-level).

use crate::llm_sanitize;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt;
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

fn circuit_map() -> &'static Mutex<HashMap<String, CircuitEntry>> {
    static M: OnceLock<Mutex<HashMap<String, CircuitEntry>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

fn circuit_key(base_url: &str) -> String {
    normalize_openai_base_url(base_url)
}

fn circuit_check(base_url: &str) -> Result<(), LlmError> {
    let key = circuit_key(base_url);
    let mut m = circuit_map().lock().map_err(|_| LlmError::InternalLock)?;
    let e = m.entry(key).or_insert(CircuitEntry {
        failures: 0,
        open_until: None,
    });
    if let Some(until) = e.open_until {
        if Instant::now() < until {
            let secs = until.saturating_duration_since(Instant::now()).as_secs().max(1);
            return Err(LlmError::CircuitOpen { cooldown_secs: secs });
        }
        e.open_until = None;
        e.failures = 0;
    }
    Ok(())
}

fn circuit_on_success(base_url: &str) {
    if let Ok(mut m) = circuit_map().lock() {
        let key = circuit_key(base_url);
        m.insert(
            key,
            CircuitEntry {
                failures: 0,
                open_until: None,
            },
        );
    }
}

fn circuit_on_failure(base_url: &str) {
    if let Ok(mut m) = circuit_map().lock() {
        let key = circuit_key(base_url);
        let e = m.entry(key).or_insert(CircuitEntry {
            failures: 0,
            open_until: None,
        });
        e.failures = e.failures.saturating_add(1);
        if e.failures >= CIRCUIT_FAILURE_THRESHOLD {
            e.open_until = Some(Instant::now() + Duration::from_secs(CIRCUIT_OPEN_SECS));
        }
    }
}

fn health_cache() -> &'static Mutex<HashMap<String, Instant>> {
    static H: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    H.get_or_init(|| Mutex::new(HashMap::new()))
}

/// GET `/v1/models` with short timeout. Throttled per base URL.
async fn ensure_llm_reachable(_client: &reqwest::Client, base_url: &str) -> Result<(), LlmError> {
    let base = normalize_openai_base_url(base_url).trim_end_matches('/').to_string();
    let key = base.clone();
    {
        let c = health_cache().lock().map_err(|_| LlmError::InternalLock)?;
        if let Some(t) = c.get(&key) {
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
    let resp = probe
        .send()
        .await
        .map_err(|e| {
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
    if let Ok(mut c) = health_cache().lock() {
        c.insert(key, Instant::now());
    }
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
    Http {
        status: u16,
        body_preview: String,
    },
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
    let mut req = client.post(&url).json(&body);
    req = apply_bearer(req);

    let t0 = std::time::Instant::now();
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            circuit_on_failure(base_url);
            if e.is_timeout() {
                metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "timeout")
                    .record(t0.elapsed().as_secs_f64());
                return Err(LlmError::Timeout);
            }
            metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "error")
                .record(t0.elapsed().as_secs_f64());
            return Err(LlmError::Unreachable(e.to_string()));
        }
    };

    if !resp.status().is_success() {
        circuit_on_failure(base_url);
        let status = resp.status().as_u16();
        let txt = resp.text().await.unwrap_or_default();
        let preview = txt.chars().take(1024).collect();
        metrics::histogram!(
            "weissman_llm_inference_seconds",
            "outcome" => "http_error"
        )
        .record(t0.elapsed().as_secs_f64());
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
    metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "ok")
        .record(t0.elapsed().as_secs_f64());
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
            obj.insert(
                "response_format".into(),
                json!({ "type": "json_object" }),
            );
        }
    }
    let mut req = client.post(&url).json(&body);
    req = apply_bearer(req);

    let t0 = std::time::Instant::now();
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            circuit_on_failure(base_url);
            if e.is_timeout() {
                metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "timeout")
                    .record(t0.elapsed().as_secs_f64());
                return Err(LlmError::Timeout);
            }
            metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "error")
                .record(t0.elapsed().as_secs_f64());
            return Err(LlmError::Unreachable(e.to_string()));
        }
    };

    if !resp.status().is_success() {
        circuit_on_failure(base_url);
        let status = resp.status().as_u16();
        let txt = resp.text().await.unwrap_or_default();
        let preview = txt.chars().take(1024).collect();
        metrics::histogram!(
            "weissman_llm_inference_seconds",
            "outcome" => "http_error"
        )
        .record(t0.elapsed().as_secs_f64());
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
    metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "ok")
        .record(t0.elapsed().as_secs_f64());
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
    let mut req = client.post(&url).json(&body);
    req = apply_bearer(req);
    let t0 = std::time::Instant::now();
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            circuit_on_failure(base_url);
            if e.is_timeout() {
                metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "timeout")
                    .record(t0.elapsed().as_secs_f64());
                return Err(LlmError::Timeout);
            }
            metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "error")
                .record(t0.elapsed().as_secs_f64());
            return Err(LlmError::Unreachable(e.to_string()));
        }
    };
    if !resp.status().is_success() {
        circuit_on_failure(base_url);
        let status = resp.status().as_u16();
        let txt = resp.text().await.unwrap_or_default();
        metrics::histogram!(
            "weissman_llm_inference_seconds",
            "outcome" => "http_error"
        )
        .record(t0.elapsed().as_secs_f64());
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
    metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "ok")
        .record(t0.elapsed().as_secs_f64());
    fire_usage_reporter(tenant_id, pt, 0, model, operation);
    Ok(out)
}

/// Build a client with timeout suitable for local inference.
#[must_use]
pub fn llm_http_client(timeout_secs: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        // Match high fan-out from parallel scan workers to a local vLLM server (Ryzen-class throughput).
        .pool_max_idle_per_host(64)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
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
    let base = normalize_openai_base_url(base_url).trim_end_matches('/').to_string();
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
    let mut req = client.post(&url).json(&body);
    req = apply_bearer_blocking(req);
    let t0 = std::time::Instant::now();
    let resp = match req.send() {
        Ok(r) => r,
        Err(e) => {
            circuit_on_failure(base_url);
            if e.is_timeout() {
                metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "timeout")
                    .record(t0.elapsed().as_secs_f64());
                return Err(LlmError::Timeout);
            }
            metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "error")
                .record(t0.elapsed().as_secs_f64());
            return Err(LlmError::Unreachable(e.to_string()));
        }
    };
    if !resp.status().is_success() {
        circuit_on_failure(base_url);
        let status = resp.status().as_u16();
        let txt = resp.text().unwrap_or_default();
        metrics::histogram!(
            "weissman_llm_inference_seconds",
            "outcome" => "http_error"
        )
        .record(t0.elapsed().as_secs_f64());
        return Err(LlmError::Http {
            status,
            body_preview: txt.chars().take(1024).collect(),
        });
    }
    let data: Value = resp
        .json()
        .map_err(|e| {
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
    metrics::histogram!("weissman_llm_inference_seconds", "outcome" => "ok")
        .record(t0.elapsed().as_secs_f64());
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
