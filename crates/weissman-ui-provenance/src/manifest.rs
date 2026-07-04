//! HMAC-SHA256 manifest signing for engine capabilities payloads.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceManifest {
    pub v: u32,
    pub payload_sha256: String,
    pub signature: String,
    pub signed_at_unix: i64,
    pub algorithm: String,
}

/// Canonical JSON bytes for hashing — sorted keys, no provenance field.
pub fn canonical_capabilities_bytes(body: &Value) -> Vec<u8> {
    let mut clone = body.clone();
    if let Some(obj) = clone.as_object_mut() {
        obj.remove("provenance");
    }
    // Deterministic serialization: serde_json sorts object keys.
    serde_json::to_vec(&clone).unwrap_or_default()
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn signing_key(secret: &str) -> Option<HmacSha256> {
    let s = secret.trim();
    if s.is_empty() {
        return None;
    }
    HmacSha256::new_from_slice(s.as_bytes()).ok()
}

/// Sign a capabilities JSON body (without existing `provenance` field).
pub fn sign_capabilities_manifest(body: &Value, secret: &str) -> Option<ProvenanceManifest> {
    let bytes = canonical_capabilities_bytes(body);
    let payload_sha256 = sha256_hex(&bytes);
    let mut mac = signing_key(secret)?;
    mac.update(payload_sha256.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    Some(ProvenanceManifest {
        v: MANIFEST_VERSION,
        payload_sha256,
        signature: sig,
        signed_at_unix: chrono_now_unix(),
        algorithm: "HMAC-SHA256".to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestVerifyStatus {
    Valid,
    MissingSecret,
    HashMismatch,
    SignatureInvalid,
    VersionUnsupported,
}

/// Verify manifest against the capabilities body.
pub fn verify_capabilities_manifest(
    body: &Value,
    manifest: &ProvenanceManifest,
    secret: &str,
) -> ManifestVerifyStatus {
    if manifest.v != MANIFEST_VERSION {
        return ManifestVerifyStatus::VersionUnsupported;
    }
    let bytes = canonical_capabilities_bytes(body);
    let hash = sha256_hex(&bytes);
    if hash != manifest.payload_sha256 {
        return ManifestVerifyStatus::HashMismatch;
    }
    let Some(mut mac) = signing_key(secret) else {
        return ManifestVerifyStatus::MissingSecret;
    };
    mac.update(manifest.payload_sha256.as_bytes());
    let expected = mac.finalize().into_bytes();
    let Ok(provided) = hex::decode(manifest.signature.trim()) else {
        return ManifestVerifyStatus::SignatureInvalid;
    };
    if provided.len() != expected.len() {
        return ManifestVerifyStatus::SignatureInvalid;
    }
    let mut diff = 0u8;
    for (a, b) in provided.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    if diff == 0 {
        ManifestVerifyStatus::Valid
    } else {
        ManifestVerifyStatus::SignatureInvalid
    }
}

fn chrono_now_unix() -> i64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
    #[cfg(target_arch = "wasm32")]
    {
        #[cfg(feature = "wasm")]
        {
            (js_sys::Date::now() / 1000.0) as i64
        }
        #[cfg(not(feature = "wasm"))]
        {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sign_and_verify_roundtrip() {
        let body = json!({"total": 2, "engines": []});
        let m = sign_capabilities_manifest(&body, "test-secret-key-32bytes-min!!").unwrap();
        assert_eq!(
            verify_capabilities_manifest(&body, &m, "test-secret-key-32bytes-min!!"),
            ManifestVerifyStatus::Valid
        );
    }

    #[test]
    fn tampered_body_fails() {
        let body = json!({"total": 2});
        let m = sign_capabilities_manifest(&body, "secret").unwrap();
        let tampered = json!({"total": 3});
        assert_eq!(
            verify_capabilities_manifest(&tampered, &m, "secret"),
            ManifestVerifyStatus::HashMismatch
        );
    }
}
