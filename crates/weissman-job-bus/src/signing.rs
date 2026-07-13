//! HMAC-SHA256 signed job envelopes — zero-trust dispatch/claim.

use crate::error::JobBusError;
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

type HmacSha256 = Hmac<sha2::Sha256>;

const ENVELOPE_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedJobEnvelope {
    pub v: u8,
    pub job_id: Uuid,
    pub tenant_id: i64,
    pub kind: String,
    pub payload: Value,
    pub issued_at: i64,
    pub nonce: String,
    pub signature: String,
}

impl SignedJobEnvelope {
    pub fn content_digest(&self) -> String {
        let bytes = signing_bytes(
            self.v,
            self.job_id,
            self.tenant_id,
            &self.kind,
            &self.payload,
            self.issued_at,
            &self.nonce,
        );
        format!("{:x}", Sha256::digest(bytes))
    }
}

pub fn orchestrator_key_from_env() -> Option<Vec<u8>> {
    let production = std::env::var("WEISSMAN_ENV")
        .ok()
        .map(|v| v.trim().eq_ignore_ascii_case("production"))
        .unwrap_or(false);

    let raw = if let Ok(s) = std::env::var("WEISSMAN_JOB_ORCHESTRATOR_SECRET") {
        if s.trim().is_empty() {
            if production {
                return None;
            }
            std::env::var("WEISSMAN_JWT_SECRET").ok()?
        } else {
            s
        }
    } else if production {
        return None;
    } else {
        std::env::var("WEISSMAN_JWT_SECRET").ok()?
    };

    let trimmed = raw.trim();
    if trimmed.len() < 32 {
        tracing::warn!(
            target: "job_bus",
            "WEISSMAN_JOB_ORCHESTRATOR_SECRET too short — job signing disabled"
        );
        return None;
    }
    Some(trimmed.as_bytes().to_vec())
}

fn signing_bytes(
    v: u8,
    job_id: Uuid,
    tenant_id: i64,
    kind: &str,
    payload: &Value,
    issued_at: i64,
    nonce: &str,
) -> Vec<u8> {
    let mut buf = vec![v];
    buf.extend_from_slice(job_id.as_bytes());
    buf.extend_from_slice(&tenant_id.to_le_bytes());
    buf.extend_from_slice(kind.as_bytes());
    if let Ok(p) = serde_json::to_vec(payload) {
        buf.extend_from_slice(&p);
    }
    buf.extend_from_slice(&issued_at.to_le_bytes());
    buf.extend_from_slice(nonce.as_bytes());
    buf
}

fn compute_hmac(key: &[u8], bytes: &[u8]) -> Result<String, JobBusError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| JobBusError::Signing(e.to_string()))?;
    mac.update(bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

pub fn sign_job_envelope(
    key: &[u8],
    job_id: Uuid,
    tenant_id: i64,
    kind: &str,
    payload: &Value,
) -> Result<SignedJobEnvelope, JobBusError> {
    let mut nonce_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);
    let issued_at = Utc::now().timestamp();
    let bytes = signing_bytes(
        ENVELOPE_VERSION,
        job_id,
        tenant_id,
        kind,
        payload,
        issued_at,
        &nonce,
    );
    let signature = compute_hmac(key, &bytes)?;
    Ok(SignedJobEnvelope {
        v: ENVELOPE_VERSION,
        job_id,
        tenant_id,
        kind: kind.to_string(),
        payload: payload.clone(),
        issued_at,
        nonce,
        signature,
    })
}

pub fn verify_job_envelope(key: &[u8], envelope: &SignedJobEnvelope) -> Result<(), JobBusError> {
    if envelope.v != ENVELOPE_VERSION {
        return Err(JobBusError::SignatureMismatch(format!(
            "unsupported envelope version {}",
            envelope.v
        )));
    }
    let bytes = signing_bytes(
        envelope.v,
        envelope.job_id,
        envelope.tenant_id,
        &envelope.kind,
        &envelope.payload,
        envelope.issued_at,
        &envelope.nonce,
    );
    let expected = compute_hmac(key, &bytes)?;
    if !constant_time_eq(expected.as_bytes(), envelope.signature.as_bytes()) {
        return Err(JobBusError::SignatureMismatch(
            "HMAC verification failed — reject spoofed job".into(),
        ));
    }
    // Reject stale envelopes (>24h skew)
    let now = Utc::now().timestamp();
    if (now - envelope.issued_at).abs() > 86_400 {
        return Err(JobBusError::SignatureMismatch("envelope expired".into()));
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sign_verify_roundtrip() {
        let key = b"test-orchestrator-secret-min-32-chars!!";
        let job_id = Uuid::new_v4();
        let env =
            sign_job_envelope(key, job_id, 1, "command_center_engine", &json!({"x": 1})).unwrap();
        verify_job_envelope(key, &env).unwrap();
    }

    #[test]
    fn tampered_payload_rejected() {
        let key = b"test-orchestrator-secret-min-32-chars!!";
        let job_id = Uuid::new_v4();
        let mut env = sign_job_envelope(key, job_id, 1, "noop", &json!({})).unwrap();
        env.payload = json!({"injected": true});
        assert!(verify_job_envelope(key, &env).is_err());
    }
}
