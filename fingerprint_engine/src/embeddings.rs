//! Text embeddings client — OpenAI `/v1/embeddings` compatible.
//!
//! Works against any OpenAI-protocol server: OpenAI itself, Azure OpenAI,
//! self-hosted vLLM, Ollama (`/api/embeddings` we map below), TogetherAI, etc.
//! Server URL + model + API key are read from the same environment variables
//! the rest of the platform already uses for chat completions.
//!
//! Output: `Vec<f32>` of length [`EMBEDDING_DIM`] (1536 — matches OpenAI's
//! `text-embedding-3-small` and OpenAI legacy `text-embedding-ada-002`). Other
//! models are accepted but their output is right-zero-padded or truncated to
//! 1536 so a single pgvector column type works across providers.
//!
//! Robust failure mode: when the backend is unreachable we return `Ok(None)`
//! and the caller falls back to keyword-based retrieval. We **never** return
//! a fake / random embedding — that would silently poison the vector index.

use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const EMBEDDING_DIM: usize = 1536;
const HTTP_TIMEOUT_SECS: u64 = 30;
const MAX_BATCH: usize = 100;
const MAX_TEXT_CHARS: usize = 8000; // hard cap so we don't ship huge prompts

#[derive(Debug, Serialize)]
struct OpenAiEmbedRequest<'a> {
    model: &'a str,
    input: Vec<&'a str>,
}

#[derive(Debug, Deserialize)]
struct OpenAiEmbedResponse {
    #[serde(default)]
    data: Vec<EmbedDatum>,
}

#[derive(Debug, Deserialize)]
struct EmbedDatum {
    #[serde(default)]
    embedding: Vec<f32>,
    #[serde(default)]
    index: usize,
}

#[derive(Debug, Clone)]
pub struct EmbeddingsConfig {
    pub base_url: String,
    pub api_key: Option<String>,
    pub model: String,
}

impl EmbeddingsConfig {
    /// Read config from the same env vars used by the chat client + override
    /// for embeddings specifically. Returns `None` if no provider is reachable.
    pub fn from_env() -> Option<Self> {
        // Local-first ("sovereign") default: a self-hosted vLLM/Ollama embedding endpoint on
        // loopback, so the RAG memory stays 100% on-box with no external key and no data egress.
        // Point at OpenAI/Azure/Together by setting WEISSMAN_EMBEDDINGS_BASE_URL + OPENAI_API_KEY.
        let base_url = std::env::var("WEISSMAN_EMBEDDINGS_BASE_URL")
            .or_else(|_| std::env::var("WEISSMAN_LLM_BASE_URL"))
            .or_else(|_| std::env::var("OPENAI_BASE_URL"))
            .unwrap_or_else(|_| "http://127.0.0.1:8000".to_string())
            .trim_end_matches('/')
            .trim_end_matches("/v1")
            .to_string();
        let api_key = weissman_engines::openai_chat::llm_api_key_from_env();
        // Default to a local open-weight embedding model (same one the council uses). Output is
        // padded/truncated to EMBEDDING_DIM, so any provider's dimension works.
        let model = std::env::var("WEISSMAN_EMBEDDINGS_MODEL")
            .or_else(|_| std::env::var("WEISSMAN_COUNCIL_EMBEDDING_MODEL"))
            .unwrap_or_else(|_| "BAAI/bge-small-en-v1.5".to_string());
        if !base_url.starts_with("http") {
            return None;
        }
        Some(Self {
            base_url,
            api_key,
            model,
        })
    }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .user_agent("Weissman-Embeddings/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Normalise an output vector to exactly `EMBEDDING_DIM` dims: zero-pad if
/// shorter, truncate if longer. Returns `None` for empty input.
fn fit_vec(v: Vec<f32>) -> Option<Vec<f32>> {
    if v.is_empty() {
        return None;
    }
    if v.len() == EMBEDDING_DIM {
        return Some(v);
    }
    let mut out = vec![0f32; EMBEDDING_DIM];
    let n = v.len().min(EMBEDDING_DIM);
    out[..n].copy_from_slice(&v[..n]);
    Some(out)
}

/// Embed a single string. Returns `Ok(None)` when no provider is configured
/// or the call fails — caller must degrade gracefully.
pub async fn embed_one(text: &str) -> Result<Option<Vec<f32>>, String> {
    let Some(cfg) = EmbeddingsConfig::from_env() else {
        return Ok(None);
    };
    let mut v = embed_batch(&cfg, &[text]).await?;
    Ok(v.pop().flatten())
}

/// Embed a batch of strings. Returns one `Option<Vec<f32>>` per input (None
/// for items the provider didn't return). Caps batch at [`MAX_BATCH`].
pub async fn embed_batch(
    cfg: &EmbeddingsConfig,
    texts: &[&str],
) -> Result<Vec<Option<Vec<f32>>>, String> {
    if texts.is_empty() {
        return Ok(vec![]);
    }
    let mut out: Vec<Option<Vec<f32>>> = vec![None; texts.len()];
    let client = http_client();
    let url = format!("{}/v1/embeddings", cfg.base_url);

    for (chunk_start, chunk) in texts.chunks(MAX_BATCH).enumerate() {
        let inputs: Vec<&str> = chunk
            .iter()
            .map(|t| {
                // Hard cap so we never ship a 1MB blob (vLLM rejects, OpenAI bills).
                if t.len() <= MAX_TEXT_CHARS {
                    *t
                } else {
                    &t[..MAX_TEXT_CHARS]
                }
            })
            .collect();
        let body = OpenAiEmbedRequest {
            model: &cfg.model,
            input: inputs,
        };

        let mut req = client.post(&url).json(&body);
        if let Some(key) = &cfg.api_key {
            req = req.bearer_auth(key);
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                target: "embeddings",
                status = %status,
                url = %url,
                body = %body.chars().take(200).collect::<String>(),
                "embeddings backend rejected request",
            );
            return Err(format!("HTTP {}", status));
        }
        let parsed: OpenAiEmbedResponse = resp.json().await.map_err(|e| e.to_string())?;
        for d in parsed.data {
            let abs_idx = chunk_start * MAX_BATCH + d.index;
            if abs_idx >= out.len() {
                continue;
            }
            out[abs_idx] = fit_vec(d.embedding);
        }
    }
    Ok(out)
}

/// Render a `Vec<f32>` as pgvector's text representation `[v1,v2,...]` so it
/// can be bound as a `text` parameter and cast `::vector` server-side. Lets
/// us use plain sqlx without a vector-aware bindings crate.
pub fn vec_to_pg_text(v: &[f32]) -> String {
    let mut s = String::with_capacity(v.len() * 8 + 2);
    s.push('[');
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        // Use Display: enough precision for ANN search; smaller than scientific
        // notation for transport.
        s.push_str(&format!("{:.6}", x));
    }
    s.push(']');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_vec_pads_short() {
        let v = vec![1.0_f32, 2.0, 3.0];
        let fitted = fit_vec(v).unwrap();
        assert_eq!(fitted.len(), EMBEDDING_DIM);
        assert!((fitted[0] - 1.0).abs() < 1e-9);
        assert!(fitted[10].abs() < 1e-9); // padded zeros
    }

    #[test]
    fn fit_vec_truncates_long() {
        let v: Vec<f32> = (0..EMBEDDING_DIM * 2).map(|i| i as f32).collect();
        let fitted = fit_vec(v).unwrap();
        assert_eq!(fitted.len(), EMBEDDING_DIM);
    }

    #[test]
    fn pg_text_round_trip_shape() {
        let s = vec_to_pg_text(&[0.1, -0.5, 1.0]);
        assert!(s.starts_with('['));
        assert!(s.ends_with(']'));
        assert!(s.contains(','));
    }
}
