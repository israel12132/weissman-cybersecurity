//! Sovereign Shield — phantom trap material: Ed25519 (OpenSSH), RS256 JWT, vLLM target class, OAST binding.
//!
//! Trap correlation host: `trap-{uuid}.<WEISSMAN_OAST_DOMAIN>` (default suffix `weissmancyber.com` when unset).

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use ssh_key::{Algorithm as SshAlgorithm, LineEnding, PrivateKey};
use uuid::Uuid;

/// High-level trap shape chosen from fingerprint + vLLM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhantomTrapKind {
    AdminSshKey,
    LeakedApiConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct SovereignPhantomBundle {
    pub trap_token: Uuid,
    pub trap_kind: PhantomTrapKind,
    pub oast_probe_url: String,
    pub ed25519_private_openssh: String,
    pub ed25519_public_openssh: String,
    pub rs256_jwt: String,
    pub planted_artifact: String,
    pub llm_class_raw: String,
}

fn oast_suffix() -> String {
    crate::fuzz_oob::oast_hook_domain().unwrap_or_else(|| {
        std::env::var("WEISSMAN_OAST_DOMAIN")
            .or_else(|_| std::env::var("WEISSMAN_OAST_BASE_DOMAIN"))
            .unwrap_or_else(|_| "weissmancyber.com".to_string())
            .trim()
            .trim_end_matches('.')
            .to_lowercase()
    })
}

/// Canonical trap hostname segment + HTTP probe (`/i` matches OAST listener).
#[must_use]
pub fn sovereign_trap_oast_url(trap_id: &Uuid) -> String {
    let d = oast_suffix();
    format!(
        "http://trap-{}.{}",
        trap_id.as_hyphenated(),
        d.trim_end_matches('.')
    )
}

#[must_use]
pub fn sovereign_trap_oast_url_with_path(trap_id: &Uuid) -> String {
    format!("{}/i", sovereign_trap_oast_url(trap_id))
}

fn generate_ed25519_openssh_pair() -> Result<(String, String), String> {
    let key = PrivateKey::random(&mut OsRng, SshAlgorithm::Ed25519).map_err(|e| e.to_string())?;
    let priv_z = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| e.to_string())?;
    let priv_s = priv_z.to_string();
    let pub_s = key
        .public_key()
        .to_openssh()
        .map_err(|e| e.to_string())?;
    Ok((priv_s, pub_s))
}

#[derive(Serialize)]
struct PhantomJwtClaims {
    sub: String,
    iss: String,
    iat: u64,
    exp: u64,
    trap_id: String,
    kind: String,
}

fn mint_rs256_jwt(trap_id: &Uuid, kind: PhantomTrapKind) -> Result<String, String> {
    let rsa = Rsa::generate(2048).map_err(|e| e.to_string())?;
    let key = PKey::from_rsa(rsa).map_err(|e| e.to_string())?;
    let priv_pem = key.private_key_to_pem_pkcs8().map_err(|e| e.to_string())?;
    let enc = EncodingKey::from_rsa_pem(&priv_pem).map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let claims = PhantomJwtClaims {
        sub: "weissman-phantom".into(),
        iss: "weissman-sovereign".into(),
        iat: now,
        exp: now.saturating_add(3600),
        trap_id: trap_id.to_string(),
        kind: match kind {
            PhantomTrapKind::AdminSshKey => "admin_ssh_key",
            PhantomTrapKind::LeakedApiConfig => "leaked_api_config",
        }
        .into(),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".into());
    encode(&header, &claims, &enc).map_err(|e| e.to_string())
}

fn planted_body(kind: PhantomTrapKind, pub_ssh: &str, jwt: &str, oast: &str) -> String {
    match kind {
        PhantomTrapKind::AdminSshKey => {
            format!(
                "# phantom admin access (deception)\n{pub_ssh} weissman-phantom-admin\n# oast {oast}\n",
            )
        }
        PhantomTrapKind::LeakedApiConfig => {
            serde_json::to_string_pretty(&json!({
                "internal_api_base": "https://api.internal.invalid",
                "service_jwt": jwt,
                "health_probe": oast,
            }))
            .unwrap_or_else(|_| "{}".into())
                + "\n"
        }
    }
}

/// vLLM classifies fingerprint JSON into corporate server vs web app vs other.
pub async fn classify_target_with_llm(
    llm_base_url: &str,
    llm_model: &str,
    tenant_id: i64,
    fingerprint_json: &serde_json::Value,
) -> Result<(PhantomTrapKind, String), weissman_engines::openai_chat::LlmError> {
    let client = weissman_engines::openai_chat::llm_http_client(60);
    let model = weissman_engines::openai_chat::resolve_llm_model(llm_model);
    let fp = fingerprint_json.to_string();
    let user = format!(
        "You are a defensive cyber architect. Given this target fingerprint JSON, reply with ONLY minified JSON: {{\"profile\":\"high_value_corporate_server\"|\"web_app\"|\"other\"}}\n\n{fp}"
    );
    let text = weissman_engines::openai_chat::chat_completion_text(
        &client,
        llm_base_url,
        &model,
        Some("Output JSON only. No markdown."),
        &user,
        0.2,
        256,
        Some(tenant_id),
        "sovereign_phantom_classify",
        true,
    )
    .await?;
    let v: serde_json::Value = serde_json::from_str(text.trim())
        .or_else(|_| {
            let s = text.trim();
            let start = s.find('{').unwrap_or(0);
            let end = s.rfind('}').map(|i| i + 1).unwrap_or(s.len());
            serde_json::from_str(&s[start..end])
        })
        .unwrap_or(json!({ "profile": "other" }));
    let profile = v
        .get("profile")
        .and_then(|x| x.as_str())
        .unwrap_or("other")
        .to_lowercase();
    let kind = if profile.contains("corporate") || profile.contains("server") {
        PhantomTrapKind::AdminSshKey
    } else if profile.contains("web") {
        PhantomTrapKind::LeakedApiConfig
    } else {
        PhantomTrapKind::LeakedApiConfig
    };
    Ok((kind, profile))
}

/// Build a full phantom bundle (cryptographic material + OAST URL + planted decoy text).
pub async fn build_phantom_bundle(
    llm_base_url: &str,
    llm_model: &str,
    tenant_id: i64,
    fingerprint_json: &serde_json::Value,
) -> Result<SovereignPhantomBundle, String> {
    let trap_token = Uuid::new_v4();
    let oast = sovereign_trap_oast_url_with_path(&trap_token);
    let (kind, raw) = if llm_base_url.trim().is_empty() {
        (PhantomTrapKind::LeakedApiConfig, "llm_disabled".into())
    } else {
        classify_target_with_llm(llm_base_url, llm_model, tenant_id, fingerprint_json)
            .await
            .map_err(|e| e.to_string())?
    };
    let (priv_ssh, pub_ssh) = generate_ed25519_openssh_pair()?;
    let jwt = mint_rs256_jwt(&trap_token, kind)?;
    let planted = planted_body(kind, &pub_ssh, &jwt, &oast);
    Ok(SovereignPhantomBundle {
        trap_token,
        trap_kind: kind,
        oast_probe_url: oast,
        ed25519_private_openssh: priv_ssh,
        ed25519_public_openssh: pub_ssh,
        rs256_jwt: jwt,
        planted_artifact: planted,
        llm_class_raw: raw,
    })
}
