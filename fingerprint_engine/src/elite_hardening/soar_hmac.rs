//! HMAC-SHA256 signing for SOAR webhook / slack_notify / http_post dispatchers.

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn webhook_key() -> Option<Vec<u8>> {
    if let Ok(raw) = std::env::var("WEISSMAN_WEBHOOK_HMAC_SECRET") {
        let t = raw.trim();
        if t.len() >= 32 {
            return Some(t.as_bytes().to_vec());
        }
    }
    std::env::var("WEISSMAN_JWT_SECRET")
        .ok()
        .filter(|s| s.len() >= 32)
        .map(|s| s.into_bytes())
}

pub fn sign_body(body: &str) -> Option<(String, String)> {
    let key = webhook_key()?;
    let digest = crate::crypto_engine::sha256_hex(body.as_bytes());
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).ok()?;
    mac.update(b"weissman-soar-webhook-v1|");
    mac.update(body.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    Some((digest, sig))
}

/// POST JSON with digest + HMAC headers. Fail closed if the URL is blocked or signing is required
/// and no key is configured in production.
pub async fn post_signed_json(url: &str, payload: &Value) -> Result<(String, String), String> {
    crate::security_hardening::validate_outbound_url(url)
        .await
        .map_err(|e| format!("ssrf: {e}"))?;
    let body = payload.to_string();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.clone());
    if let Some((digest, sig)) = sign_body(&body) {
        req = req
            .header("X-Weissman-Digest", digest.as_str())
            .header("X-Weissman-Signature", format!("v1={sig}"));
    } else if tls_policy_is_production() {
        return Err(
            "fail-closed: WEISSMAN_WEBHOOK_HMAC_SECRET (or JWT secret) required in production"
                .into(),
        );
    }
    match req.send().await {
        Ok(r) if r.status().is_success() => Ok(("ok".into(), format!("HTTP {}", r.status()))),
        Ok(r) => Err(format!("HTTP {}", r.status())),
        Err(e) => Err(e.to_string()),
    }
}

fn tls_policy_is_production() -> bool {
    weissman_core::tls_policy::is_production_environment()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_when_secret_set() {
        let prev = std::env::var("WEISSMAN_WEBHOOK_HMAC_SECRET").ok();
        std::env::set_var(
            "WEISSMAN_WEBHOOK_HMAC_SECRET",
            "elite-hardening-webhook-secret-32bytes!!",
        );
        let signed = sign_body(r#"{"text":"hi"}"#).expect("signed");
        assert_eq!(signed.0.len(), 64);
        assert_eq!(signed.1.len(), 64);
        match prev {
            Some(v) => std::env::set_var("WEISSMAN_WEBHOOK_HMAC_SECRET", v),
            None => std::env::remove_var("WEISSMAN_WEBHOOK_HMAC_SECRET"),
        }
    }
}
