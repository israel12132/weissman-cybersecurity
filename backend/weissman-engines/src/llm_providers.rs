//! Catalog of LLM providers Weissman can talk to.
//!
//! The product speaks OpenAI-compatible HTTP (`/v1/chat/completions`) plus a handful of
//! first-class adapters (Anthropic Messages, Azure OpenAI). Setting any one of the
//! documented API-key environment variables is enough: [`discover_endpoints`] builds a
//! failover chain automatically when `WEISSMAN_LLM_ENDPOINTS` is unset.

use serde::Serialize;

/// How the provider expects the secret to be presented.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthStyle {
    #[default]
    Bearer,
    XApiKey,
    ApiKeyHeader,
    None,
}

/// One known provider.
#[derive(Clone, Copy, Debug)]
pub struct Provider {
    pub id: &'static str,
    pub label: &'static str,
    pub key_env: &'static str,
    /// Extra env vars that must be set together with the key (Azure endpoint, etc.).
    pub extra_env: &'static [&'static str],
    pub default_base_url: &'static str,
    pub default_model: &'static str,
    pub auth: AuthStyle,
    pub openai_compatible: bool,
}

pub const PROVIDERS: &[Provider] = &[
    Provider {
        id: "vllm-local",
        label: "Self-hosted vLLM / Ollama",
        key_env: "WEISSMAN_LLM_API_KEY",
        extra_env: &[],
        default_base_url: "http://127.0.0.1:8000/v1",
        default_model: "meta-llama/Llama-3.2-3B-Instruct",
        auth: AuthStyle::Bearer,
        openai_compatible: true,
    },
    Provider {
        id: "openai",
        label: "OpenAI",
        key_env: "OPENAI_API_KEY",
        extra_env: &[],
        default_base_url: "https://api.openai.com/v1",
        default_model: "gpt-4o-mini",
        auth: AuthStyle::Bearer,
        openai_compatible: true,
    },
    Provider {
        id: "anthropic",
        label: "Anthropic",
        key_env: "ANTHROPIC_API_KEY",
        extra_env: &[],
        default_base_url: "https://api.anthropic.com/v1",
        default_model: "claude-3-5-sonnet-latest",
        auth: AuthStyle::XApiKey,
        openai_compatible: false,
    },
    Provider {
        id: "gemini",
        label: "Google Gemini",
        key_env: "GEMINI_API_KEY",
        extra_env: &[],
        default_base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
        default_model: "gemini-2.0-flash",
        auth: AuthStyle::Bearer,
        openai_compatible: true,
    },
    Provider {
        id: "azure-openai",
        label: "Azure OpenAI",
        key_env: "AZURE_OPENAI_API_KEY",
        extra_env: &["AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_DEPLOYMENT"],
        default_base_url: "",
        default_model: "",
        auth: AuthStyle::ApiKeyHeader,
        openai_compatible: true,
    },
    Provider {
        id: "groq",
        label: "Groq",
        key_env: "GROQ_API_KEY",
        extra_env: &[],
        default_base_url: "https://api.groq.com/openai/v1",
        default_model: "llama-3.3-70b-versatile",
        auth: AuthStyle::Bearer,
        openai_compatible: true,
    },
    Provider {
        id: "mistral",
        label: "Mistral",
        key_env: "MISTRAL_API_KEY",
        extra_env: &[],
        default_base_url: "https://api.mistral.ai/v1",
        default_model: "mistral-small-latest",
        auth: AuthStyle::Bearer,
        openai_compatible: true,
    },
    Provider {
        id: "deepseek",
        label: "DeepSeek",
        key_env: "DEEPSEEK_API_KEY",
        extra_env: &[],
        default_base_url: "https://api.deepseek.com/v1",
        default_model: "deepseek-chat",
        auth: AuthStyle::Bearer,
        openai_compatible: true,
    },
    Provider {
        id: "openrouter",
        label: "OpenRouter",
        key_env: "OPENROUTER_API_KEY",
        extra_env: &[],
        default_base_url: "https://openrouter.ai/api/v1",
        default_model: "openrouter/auto",
        auth: AuthStyle::Bearer,
        openai_compatible: true,
    },
    Provider {
        id: "together",
        label: "Together AI",
        key_env: "TOGETHER_API_KEY",
        extra_env: &[],
        default_base_url: "https://api.together.xyz/v1",
        default_model: "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        auth: AuthStyle::Bearer,
        openai_compatible: true,
    },
    Provider {
        id: "xai",
        label: "xAI",
        key_env: "XAI_API_KEY",
        extra_env: &[],
        default_base_url: "https://api.x.ai/v1",
        default_model: "grok-2-latest",
        auth: AuthStyle::Bearer,
        openai_compatible: true,
    },
    Provider {
        id: "perplexity",
        label: "Perplexity",
        key_env: "PERPLEXITY_API_KEY",
        extra_env: &[],
        default_base_url: "https://api.perplexity.ai",
        default_model: "sonar",
        auth: AuthStyle::Bearer,
        openai_compatible: true,
    },
    Provider {
        id: "fireworks",
        label: "Fireworks",
        key_env: "FIREWORKS_API_KEY",
        extra_env: &[],
        default_base_url: "https://api.fireworks.ai/inference/v1",
        default_model: "accounts/fireworks/models/llama-v3p3-70b-instruct",
        auth: AuthStyle::Bearer,
        openai_compatible: true,
    },
    Provider {
        id: "cohere",
        label: "Cohere",
        key_env: "COHERE_API_KEY",
        extra_env: &[],
        default_base_url: "https://api.cohere.ai/compatibility/v1",
        default_model: "command-r-plus",
        auth: AuthStyle::Bearer,
        openai_compatible: true,
    },
    Provider {
        id: "ollama",
        label: "Ollama",
        key_env: "OLLAMA_HOST",
        extra_env: &[],
        default_base_url: "http://127.0.0.1:11434/v1",
        default_model: "llama3.2",
        auth: AuthStyle::None,
        openai_compatible: true,
    },
];

/// Look up a provider by id (case-insensitive).
#[must_use]
pub fn by_id(id: &str) -> Option<&'static Provider> {
    let id = id.trim().to_ascii_lowercase();
    PROVIDERS.iter().find(|p| p.id == id)
}

/// Non-empty env var, treating whitespace as unset.
#[must_use]
pub fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// First non-empty env var in `names`.
#[must_use]
pub fn env_first(names: &[&str]) -> Option<String> {
    names.iter().find_map(|n| env_nonempty(n))
}

/// SHA-256 fingerprint of a secret, hex-encoded, for readiness APIs. Never returns the secret.
#[must_use]
pub fn fingerprint(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(secret.as_bytes());
    let hex = digest
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    format!("sha256:{hex}…")
}

/// A resolved, ready-to-call endpoint.
#[derive(Clone, Debug)]
pub struct ResolvedEndpoint {
    pub provider: &'static str,
    pub label: String,
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub auth: AuthStyle,
}

impl ResolvedEndpoint {
    /// Masked view suitable for JSON APIs.
    #[must_use]
    pub fn public(&self) -> PublicEndpoint {
        PublicEndpoint {
            provider: self.provider.to_string(),
            label: self.label.clone(),
            base_url: self.base_url.clone(),
            model: self.model.clone(),
            configured: true,
            key_env: PROVIDERS
                .iter()
                .find(|p| p.id == self.provider)
                .map(|p| p.key_env.to_string())
                .unwrap_or_default(),
            key_fingerprint: self.api_key.as_deref().map(fingerprint),
            auth: self.auth,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PublicEndpoint {
    pub provider: String,
    pub label: String,
    pub base_url: String,
    pub model: String,
    pub configured: bool,
    pub key_env: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_fingerprint: Option<String>,
    pub auth: AuthStyle,
}

fn azure_base_url() -> Option<String> {
    let endpoint = env_nonempty("AZURE_OPENAI_ENDPOINT")?;
    let deployment = env_nonempty("AZURE_OPENAI_DEPLOYMENT")?;
    let endpoint = endpoint.trim_end_matches('/');
    // Deployment root only. `openai_chat::chat_completions_endpoint` appends
    // `/chat/completions?api-version=` so the query string cannot be glued onto the path.
    Some(format!("{endpoint}/openai/deployments/{deployment}"))
}

fn resolve_one(p: &Provider) -> Option<ResolvedEndpoint> {
    match p.id {
        "azure-openai" => {
            let key = env_nonempty(p.key_env)?;
            let base_url = azure_base_url()?;
            let model = env_nonempty("AZURE_OPENAI_DEPLOYMENT").unwrap_or_default();
            Some(ResolvedEndpoint {
                provider: p.id,
                label: p.label.to_string(),
                base_url,
                model,
                api_key: Some(key),
                auth: p.auth,
            })
        }
        "ollama" => {
            // OLLAMA_HOST is a URL, not a secret. Presence of the var (or a reachable default)
            // is enough to advertise the provider; we only auto-include it when explicitly set
            // so a missing local daemon does not become a failover target.
            let host = env_nonempty(p.key_env)?;
            let base = if host.contains("://") {
                if host.contains("/v1") {
                    host
                } else {
                    format!("{}/v1", host.trim_end_matches('/'))
                }
            } else {
                format!("http://{host}/v1")
            };
            Some(ResolvedEndpoint {
                provider: p.id,
                label: p.label.to_string(),
                base_url: base,
                model: env_nonempty("OLLAMA_MODEL").unwrap_or_else(|| p.default_model.to_string()),
                api_key: None,
                auth: AuthStyle::None,
            })
        }
        "vllm-local" => {
            // Only auto-include the local daemon when the operator pointed WEISSMAN_LLM_BASE_URL
            // at it, or set the dedicated vLLM/gateway key. OPENAI_API_KEY must not pull a
            // loopback endpoint into the failover chain.
            let base = env_nonempty("WEISSMAN_LLM_BASE_URL")
                .or_else(|| env_nonempty("LLM_BASE_URL"))
                .unwrap_or_else(|| p.default_base_url.to_string());
            let key = env_nonempty("WEISSMAN_LLM_API_KEY");
            let explicit = env_nonempty("WEISSMAN_LLM_BASE_URL").is_some()
                || env_nonempty("LLM_BASE_URL").is_some()
                || key.is_some();
            if !explicit {
                return None;
            }
            Some(ResolvedEndpoint {
                provider: p.id,
                label: p.label.to_string(),
                base_url: base,
                model: env_nonempty("WEISSMAN_LLM_MODEL")
                    .unwrap_or_else(|| p.default_model.to_string()),
                api_key: key,
                auth: p.auth,
            })
        }
        _ => {
            let tag = p.id.to_ascii_uppercase().replace('-', "_");
            let key = env_nonempty(p.key_env)?;
            let base = env_nonempty(&format!("WEISSMAN_{tag}_BASE_URL"))
                .unwrap_or_else(|| p.default_base_url.to_string());
            let model = env_nonempty(&format!("WEISSMAN_{tag}_MODEL"))
                .unwrap_or_else(|| p.default_model.to_string());
            Some(ResolvedEndpoint {
                provider: p.id,
                label: p.label.to_string(),
                base_url: base,
                model,
                api_key: Some(key),
                auth: p.auth,
            })
        }
    }
}

/// Endpoints implied by currently-set environment variables, cloud providers first.
#[must_use]
pub fn discover_endpoints() -> Vec<ResolvedEndpoint> {
    let mut out = Vec::new();
    // Prefer an explicit WEISSMAN_LLM_BASE_URL / key as the primary, then any cloud keys.
    for p in PROVIDERS {
        if let Some(ep) = resolve_one(p) {
            out.push(ep);
        }
    }
    // De-duplicate by base_url so OPENAI_API_KEY + WEISSMAN_LLM_BASE_URL=https://api.openai.com/v1
    // does not call the same host twice.
    let mut seen = std::collections::HashSet::new();
    out.retain(|e| seen.insert(e.base_url.clone()));
    out
}

/// Public catalog: every known provider with `configured` reflecting env presence.
#[must_use]
pub fn catalog() -> Vec<PublicEndpoint> {
    PROVIDERS
        .iter()
        .map(|p| {
            if let Some(ep) = resolve_one(p) {
                ep.public()
            } else {
                PublicEndpoint {
                    provider: p.id.to_string(),
                    label: p.label.to_string(),
                    base_url: p.default_base_url.to_string(),
                    model: p.default_model.to_string(),
                    configured: false,
                    key_env: p.key_env.to_string(),
                    key_fingerprint: None,
                    auth: p.auth,
                }
            }
        })
        .collect()
}

/// Apply the provider's auth scheme to an HTTP request.
pub fn apply_auth(
    mut req: reqwest::RequestBuilder,
    auth: AuthStyle,
    key: Option<&str>,
) -> reqwest::RequestBuilder {
    let Some(key) = key.map(str::trim).filter(|s| !s.is_empty()) else {
        return req;
    };
    match auth {
        AuthStyle::Bearer => {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {key}"));
        }
        AuthStyle::XApiKey => {
            req = req
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01");
        }
        AuthStyle::ApiKeyHeader => {
            req = req.header("api-key", key);
        }
        AuthStyle::None => {}
    }
    req
}

/// Blocking counterpart of [`apply_auth`] for the sync client path.
pub fn apply_auth_blocking(
    mut req: reqwest::blocking::RequestBuilder,
    auth: AuthStyle,
    key: Option<&str>,
) -> reqwest::blocking::RequestBuilder {
    let Some(key) = key.map(str::trim).filter(|s| !s.is_empty()) else {
        return req;
    };
    match auth {
        AuthStyle::Bearer => {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {key}"));
        }
        AuthStyle::XApiKey => {
            req = req
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01");
        }
        AuthStyle::ApiKeyHeader => {
            req = req.header("api-key", key);
        }
        AuthStyle::None => {}
    }
    req
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_lists_every_provider() {
        assert!(PROVIDERS.len() >= 12);
        assert!(by_id("openai").is_some());
        assert!(by_id("ANTHROPIC").is_some());
        assert!(by_id("nope").is_none());
    }

    #[test]
    fn fingerprint_is_stable_and_does_not_contain_the_secret() {
        let fp = fingerprint("sk-test-secret");
        assert!(fp.starts_with("sha256:"));
        assert!(!fp.contains("sk-test"));
        assert_eq!(fp, fingerprint("sk-test-secret"));
        assert_ne!(fp, fingerprint("other"));
    }

    #[test]
    fn env_first_prefers_the_earlier_name() {
        std::env::set_var("WEISSMAN_TEST_KEY_A", "aaa");
        std::env::set_var("WEISSMAN_TEST_KEY_B", "bbb");
        assert_eq!(
            env_first(&["WEISSMAN_TEST_KEY_A", "WEISSMAN_TEST_KEY_B"]).as_deref(),
            Some("aaa")
        );
        std::env::remove_var("WEISSMAN_TEST_KEY_A");
        std::env::remove_var("WEISSMAN_TEST_KEY_B");
    }
}
