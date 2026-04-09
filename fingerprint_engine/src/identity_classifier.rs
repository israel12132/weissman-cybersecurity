//! Dynamic endpoint classification and privilege-param derivation via LLM (OpenAI-compatible / vLLM). Zero hardcoded path tokens.

use serde_json::Value;
use weissman_engines::openai_chat;

const LLM_TIMEOUT_SECS: u64 = 15;

/// Classify endpoint from behavior: path, method, response status, body preview. No hardcoded keywords.
pub async fn classify_endpoint_llm(
    path: &str,
    method: &str,
    param_keys: &[String],
    response_status: u16,
    body_preview: &str,
    llm_base: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> Option<String> {
    let body_trim = body_preview.chars().take(400).collect::<String>();
    let params_joined = param_keys.join(", ");
    let prompt = format!(
        r#"Classify this API endpoint from URL, method, params and response. Reply with exactly one word: registration | profile | admin_setup | none.
- registration: user sign-up, account creation (often 201, returns token/session).
- profile: profile update, account patch (often 200, may return token).
- admin_setup: first-run setup, bootstrap, create admin without prior auth (often 201).
- none: other.

Path: {} Method: {} Param keys: {} Response status: {} Body preview: {}

One word only:"#,
        path, method, params_joined, response_status, body_trim
    );
    let client = openai_chat::llm_http_client(LLM_TIMEOUT_SECS);
    let model = openai_chat::resolve_llm_model(llm_model);
    let text = openai_chat::chat_completion_text(
        &client,
        llm_base,
        &model,
        None,
        &prompt,
        0.1,
        32,
        llm_tenant_id,
        "identity_classify_endpoint",
        true,
    )
    .await
    .ok()?;
    let text = text.trim().to_lowercase();
    let out = if text.contains("registration") {
        "registration"
    } else if text.contains("profile") {
        "profile"
    } else if text.contains("admin_setup") {
        "admin_setup"
    } else {
        "none"
    };
    Some(out.to_string())
}

/// Derive possible privilege/role parameter names from path using LLM. No hardcoded stems.
pub async fn derive_privilege_params_llm(
    path: &str,
    llm_base: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> Vec<String> {
    let prompt = format!(
        r#"From this API path only, list possible JSON body parameter names that could control user role or privilege. Common in REST APIs. Reply with a JSON array of strings only, e.g. ["role","is_admin","account_type"]. Path: {}"#,
        path
    );
    let client = openai_chat::llm_http_client(LLM_TIMEOUT_SECS);
    let model = openai_chat::resolve_llm_model(llm_model);
    let text = match openai_chat::chat_completion_text(
        &client,
        llm_base,
        &model,
        None,
        &prompt,
        0.2,
        256,
        llm_tenant_id,
        "identity_privilege_params",
        true,
    )
    .await
    {
        Ok(t) => t,
        Err(_) => return vec![],
    };
    let extracted = text
        .lines()
        .find(|l| l.trim().starts_with('['))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| text.to_string());
    let parsed: Vec<String> = serde_json::from_str(&extracted).unwrap_or_default();
    parsed.into_iter().take(20).collect()
}

/// Parse unstructured threat chatter (advisory, RSS, OSV) into a targetable JSON signature for correlation.
pub async fn threat_chatter_to_exploit_signature_llm(
    chatter: &str,
    llm_base: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> Option<Value> {
    let excerpt: String = chatter.chars().take(6000).collect();
    let prompt = format!(
        r#"You are a threat intel parser. Given the vulnerability text below, output ONLY a single JSON object with keys:
- "packages": array of strings, affected package names (npm, PyPI, crate, go module, etc.) normalized to lowercase where sensible
- "cve_id": string or null
- "severity_guess": one of critical|high|medium|low
- "safe_probe": object with keys path (string), method (GET or POST), headers (object or null), query_params (object or null), expected_regex (string) — detection-only HTTP signature

Threat text:
{}

JSON only, no markdown:"#,
        excerpt
    );
    let client = openai_chat::llm_http_client(LLM_TIMEOUT_SECS * 3);
    let model = openai_chat::resolve_llm_model(llm_model);
    let text = openai_chat::chat_completion_text(
        &client,
        llm_base,
        &model,
        None,
        &prompt,
        0.2,
        2048,
        llm_tenant_id,
        "identity_threat_signature",
        true,
    )
    .await
    .ok()?;
    let trimmed = text.trim();
    let start = trimmed.find('{')?;
    let end = trimmed.rfind('}')?;
    let slice = &trimmed[start..=end];
    serde_json::from_str(slice).ok()
}
