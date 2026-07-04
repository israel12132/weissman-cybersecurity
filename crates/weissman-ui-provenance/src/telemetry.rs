//! Telemetry event provenance — binds SSE events to signed capabilities manifest.

use crate::belief::{collapse_belief, FusionMode};
use crate::manifest::sha256_hex;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyStatus {
    Valid,
    Tampered,
    EngineMismatch,
    ManifestInvalid,
    MissingFields,
    CollapseScoreDrift,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryVerifyResult {
    pub status: VerifyStatus,
    pub event_hash: String,
    pub collapse_belief: Option<f64>,
    pub detail: String,
}

/// Verify an SSE telemetry event against capabilities manifest hash and optional belief vector.
pub fn verify_telemetry_event(
    event: &Value,
    manifest_payload_sha256: &str,
    secret: &str,
    belief_probs: &[f64],
    fusion_mode: FusionMode,
    reported_collapse: Option<f64>,
) -> TelemetryVerifyResult {
    let engine = event
        .get("engine")
        .or_else(|| event.get("engine_id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if engine.is_empty() {
        return TelemetryVerifyResult {
            status: VerifyStatus::MissingFields,
            event_hash: String::new(),
            collapse_belief: None,
            detail: "telemetry event missing engine id".into(),
        };
    }

    let canonical = format!(
        "v1|manifest={manifest_payload_sha256}|engine={engine}|msg={}",
        event.get("message").and_then(Value::as_str).unwrap_or("")
    );
    let event_hash = sha256_hex(canonical.as_bytes());

    let sig = event
        .get("provenance_sig")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !sig.is_empty() {
        if !verify_event_hmac(&event_hash, sig, secret) {
            return TelemetryVerifyResult {
                status: VerifyStatus::Tampered,
                event_hash,
                collapse_belief: None,
                detail: "telemetry provenance_sig HMAC invalid — forensic tamper".into(),
            };
        }
    }

    let collapse = if belief_probs.is_empty() {
        None
    } else {
        Some(collapse_belief(belief_probs, fusion_mode))
    };

    if let (Some(computed), Some(reported)) = (collapse, reported_collapse) {
        if (computed - reported).abs() > 0.02 {
            return TelemetryVerifyResult {
                status: VerifyStatus::CollapseScoreDrift,
                event_hash,
                collapse_belief: Some(computed),
                detail: format!(
                    "superposition collapse drift: computed={computed:.4} reported={reported:.4}"
                ),
            };
        }
    }

    TelemetryVerifyResult {
        status: VerifyStatus::Valid,
        event_hash,
        collapse_belief: collapse,
        detail: "telemetry provenance verified".into(),
    }
}

fn verify_event_hmac(event_hash: &str, sig_hex: &str, secret: &str) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.trim().as_bytes()) else {
        return false;
    };
    mac.update(event_hash.as_bytes());
    let expected = mac.finalize().into_bytes();
    let Ok(provided) = hex::decode(sig_hex.trim()) else {
        return false;
    };
    if provided.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in provided.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Server-side: sign telemetry event hash for optional client verification.
#[must_use]
pub fn sign_telemetry_event_hash(event_hash: &str, secret: &str) -> Option<String> {
    let mut mac = HmacSha256::new_from_slice(secret.trim().as_bytes()).ok()?;
    mac.update(event_hash.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn valid_event_without_sig_passes() {
        let event = json!({"engine": "jwt_attack", "message": "probe ok"});
        let r = verify_telemetry_event(&event, "abc123", "secret", &[], FusionMode::Hybrid, None);
        assert_eq!(r.status, VerifyStatus::Valid);
    }
}
