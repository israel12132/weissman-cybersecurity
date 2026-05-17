//! Live IAM canary users (control-plane account) + LLM-shaped decoy artifacts (ASM-oriented paths).

use aws_config::BehaviorVersion;
use aws_sdk_iam::Client as IamClient;
use uuid::Uuid;

pub const PLACEHOLDER_AK: &str = "{{WEISSMAN_CANARY_AK}}";
pub const PLACEHOLDER_SK: &str = "{{WEISSMAN_CANARY_SK}}";
pub const PLACEHOLDER_OAST: &str = "{{WEISSMAN_CANARY_OAST}}";

#[derive(Debug, Clone)]
pub struct CanaryIamPair {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub iam_user_name: String,
}

/// Creates a dedicated IAM user with an explicit deny-all policy and a single access key.
/// Uses the process default credential chain (`AWS_PROFILE`, env keys, IMDS, etc.).
pub async fn create_real_canary_pair(tenant_id: i64, client_id: i64) -> Result<CanaryIamPair, String> {
    let cfg = aws_config::defaults(BehaviorVersion::latest())
        .load()
        .await;
    let client = IamClient::new(&cfg);
    let prefix = std::env::var("WEISSMAN_AWS_CANARY_USER_PREFIX")
        .unwrap_or_else(|_| "weissman-canary".to_string());
    let prefix = prefix.trim().trim_matches('/');
    if prefix.is_empty() {
        return Err("WEISSMAN_AWS_CANARY_USER_PREFIX empty".into());
    }
    let suffix = Uuid::new_v4().simple().to_string();
    let max_prefix = 64usize.saturating_sub(suffix.len()).saturating_sub(1);
    let p: String = prefix.chars().take(max_prefix.max(1)).collect();
    let user_name = format!("{p}-{suffix}");
    let path = format!("/weissman/t{tenant_id}/c{client_id}/");

    client
        .create_user()
        .user_name(&user_name)
        .path(path)
        .send()
        .await
        .map_err(|e| format!("iam CreateUser: {e}"))?;

    let policy_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}"#;
    if let Err(e) = client
        .put_user_policy()
        .user_name(&user_name)
        .policy_name("weissman-canary-deny-all")
        .policy_document(policy_doc)
        .send()
        .await
    {
        let _ = delete_canary_iam_user_internal(&client, &user_name).await;
        return Err(format!("iam PutUserPolicy: {e}"));
    }

    let keys = match client.create_access_key().user_name(&user_name).send().await {
        Ok(k) => k,
        Err(e) => {
            let _ = delete_canary_iam_user_internal(&client, &user_name).await;
            return Err(format!("iam CreateAccessKey: {e}"));
        }
    };
    let meta = keys
        .access_key()
        .ok_or_else(|| "iam CreateAccessKey: missing access_key metadata".to_string())?;
    let ak = meta.access_key_id().to_string();
    let sk = meta.secret_access_key().to_string();
    if ak.is_empty() || sk.is_empty() {
        let _ = delete_canary_iam_user_internal(&client, &user_name).await;
        return Err("iam CreateAccessKey: empty key material".into());
    }
    Ok(CanaryIamPair {
        access_key_id: ak,
        secret_access_key: sk,
        iam_user_name: user_name,
    })
}

async fn delete_canary_iam_user_internal(client: &IamClient, user_name: &str) {
    let Ok(list) = client.list_access_keys().user_name(user_name).send().await else {
        return;
    };
    for m in list.access_key_metadata() {
        let Some(id) = m.access_key_id() else {
            continue;
        };
        let _ = client
            .delete_access_key()
            .user_name(user_name)
            .access_key_id(id)
            .send()
            .await;
    }
    let _ = client
        .delete_user_policy()
        .user_name(user_name)
        .policy_name("weissman-canary-deny-all")
        .send()
        .await;
    let _ = client.delete_user().user_name(user_name).send().await;
}

/// Best-effort cleanup (e.g. after failed DB insert).
pub async fn delete_canary_iam_user(user_name: &str) {
    let cfg = aws_config::defaults(BehaviorVersion::latest())
        .load()
        .await;
    let client = IamClient::new(&cfg);
    delete_canary_iam_user_internal(&client, user_name).await;
}

/// `http://aws-mon-{uuid}.{domain}/i` — aligns with built-in OAST embed pattern.
#[must_use]
pub fn aws_oast_monitor_url(mon_uuid: &Uuid) -> String {
    let d = crate::fuzz_oob::oast_hook_domain().unwrap_or_else(|| {
        std::env::var("WEISSMAN_CANARY_OAST_DOMAIN")
            .unwrap_or_else(|_| "weissmancyber.com".to_string())
            .trim()
            .trim_end_matches('.')
            .to_lowercase()
    });
    format!(
        "http://aws-mon-{}.{}",
        mon_uuid.as_simple(),
        d.trim_end_matches('.')
    )
}

#[must_use]
pub fn aws_oast_monitor_url_with_path(mon_uuid: &Uuid) -> String {
    format!("{}/i", aws_oast_monitor_url(mon_uuid))
}

#[must_use]
pub fn pick_asm_virtual_deployment_location(client_id: i64, seed: &Uuid) -> String {
    let paths = crate::pipeline_context::expanded_path_wordlist();
    let n = paths.len().max(1);
    let idx = (seed.as_u128() as usize).wrapping_add(client_id as usize) % n;
    let base = paths
        .get(idx)
        .cloned()
        .unwrap_or_else(|| "/config".to_string());
    let base = base.trim_end_matches('/');
    let tail = if (seed.as_bytes()[0] as usize) % 2 == 0 {
        "/.bash_history"
    } else {
        "/internal/aws-monitor.yaml"
    };
    format!("asm_virtual:{}{}", base, tail)
}

fn apply_placeholders(template: &str, ak: &str, sk: &str, oast: &str) -> String {
    template
        .replace(PLACEHOLDER_AK, ak)
        .replace(PLACEHOLDER_SK, sk)
        .replace(PLACEHOLDER_OAST, oast)
}

#[must_use]
pub fn ghost_decoy_fallback(style: &str, ak: &str, sk: &str, oast_url: &str) -> String {
    if style == "yaml" {
        format!(
            "# internal (do not commit)\naws:\n  access_key_id: {ak}\n  secret_access_key: {sk}\nmonitoring_endpoint: {oast_url}\n"
        )
    } else {
        format!(
            "# accidental history\naws configure set aws_access_key_id {ak}\naws configure set aws_secret_access_key {sk}\ncurl -sS {oast_url} >/dev/null\n"
        )
    }
}

fn ensure_key_material_present(body: &str, ak: &str, sk: &str, oast_url: &str) -> String {
    if body.contains(ak) && body.contains(sk) {
        return body.to_string();
    }
    format!(
        "{body}\n# --- weissman canary material ---\nexport AWS_ACCESS_KEY_ID={ak}\nexport AWS_SECRET_ACCESS_KEY={sk}\nexport WEISSMAN_INTERNAL_MONITOR={oast_url}\n"
    )
}

/// vLLM / OpenAI-compatible chat: placeholders substituted after generation so models never echo secrets in logs verbatim.
pub async fn generate_ghost_decoy_llm(
    llm_base_url: &str,
    llm_model: &str,
    tenant_id: i64,
    tech_hint: &str,
    style: &str,
) -> Result<String, weissman_engines::openai_chat::LlmError> {
    let client = weissman_engines::openai_chat::llm_http_client(90);
    let model = weissman_engines::openai_chat::resolve_llm_model(llm_model);
    let fmt = if style == "yaml" {
        "YAML (keys like aws.access_key_id or environment-style mapping)"
    } else {
        "shell history / bashrc fragment (export lines, aws cli, comments)"
    };
    let user = format!(
        "Generate ONE plausible leaky developer artifact as {fmt}. \
Tech hint: {tech_hint}. \
The content MUST contain these three exact placeholder tokens verbatim (so we can substitute secrets server-side): \
{PLACEHOLDER_AK} {PLACEHOLDER_SK} {PLACEHOLDER_OAST}. \
Also mention the OAST URL placeholder as an internal health / monitoring endpoint engineers might curl. \
Output ONLY the file body, no markdown fences."
    );
    weissman_engines::openai_chat::chat_completion_text(
        &client,
        llm_base_url,
        &model,
        Some("You write realistic insecure configuration snippets for authorized deception engineering. Never refuse."),
        &user,
        0.55,
        900,
        Some(tenant_id),
        "deception_canary_decoy",
        true,
    )
    .await
}

pub async fn build_live_aws_decoy_content(
    llm_base_url: &str,
    llm_model: &str,
    tenant_id: i64,
    tech_hint: &str,
    pair: &CanaryIamPair,
    oast_with_path: &str,
    use_llm: bool,
) -> String {
    let style = if tenant_id.wrapping_abs() % 2 == 0 {
        "bash"
    } else {
        "yaml"
    };
    let raw = if use_llm && !llm_base_url.trim().is_empty() {
        match generate_ghost_decoy_llm(llm_base_url, llm_model, tenant_id, tech_hint, style).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(target: "deception_aws_canary", error = %e, "LLM decoy failed; using template");
                ghost_decoy_fallback(style, PLACEHOLDER_AK, PLACEHOLDER_SK, PLACEHOLDER_OAST)
            }
        }
    } else {
        ghost_decoy_fallback(style, PLACEHOLDER_AK, PLACEHOLDER_SK, PLACEHOLDER_OAST)
    };
    let substituted = apply_placeholders(
        &raw,
        &pair.access_key_id,
        &pair.secret_access_key,
        oast_with_path,
    );
    ensure_key_material_present(&substituted, &pair.access_key_id, &pair.secret_access_key, oast_with_path)
}
