//! Envelope encryption for durable job-bus payloads.
//!
//! `weissman_worker` is BYPASSRLS and can `SELECT` every queue row. A bulk dump
//! of `weissman_async_jobs.payload` must be ciphertext. The AES-256-GCM key is
//! derived per tenant from the process vault KEK
//! (`weissman-job-bus-v1|` ‖ tenant_id LE bytes). Decrypt happens only on the
//! claim path after the worker has the row's `tenant_id`.
//!
//! The zero-trust bus envelope (`_weissman_job_bus`) stays a **plaintext
//! sibling** so `payload ? '_weissman_job_bus'` still gates claim. Everything
//! else is sealed under `_weissman_job_enc`.
//!
//! No bulk-decrypt helper exists on purpose.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde_json::{json, Value};
use std::sync::RwLock;

use crate::job_orchestration::PAYLOAD_BUS_KEY;
use crate::secret_zeroize::derive_aes256_key;

const ENC_KEY: &str = "_weissman_job_enc";
const DOMAIN_PREFIX: &[u8] = b"weissman-job-bus-v1|";

static KEK: RwLock<Option<[u8; 32]>> = RwLock::new(None);

/// Install the vault KEK after [`crate::ceo::vault::prime_keys_from_env`].
pub fn install_kek(key: [u8; 32]) {
    if let Ok(mut g) = KEK.write() {
        *g = Some(key);
    }
}

fn current_kek() -> Option<[u8; 32]> {
    KEK.read().ok().and_then(|g| *g)
}

fn tenant_wrap_key(kek: &[u8; 32], tenant_id: i64) -> [u8; 32] {
    let mut domain = Vec::with_capacity(DOMAIN_PREFIX.len() + 8);
    domain.extend_from_slice(DOMAIN_PREFIX);
    domain.extend_from_slice(&tenant_id.to_le_bytes());
    derive_aes256_key(&domain, kek)
}

fn tenant_aad(tenant_id: i64) -> [u8; 8] {
    tenant_id.to_le_bytes()
}

/// Seal `payload` for storage. Passthrough when no KEK (dev without a vault key).
pub fn seal_job_payload(payload: &Value, tenant_id: i64) -> Result<Value, String> {
    let Some(kek) = current_kek() else {
        return Ok(payload.clone());
    };
    seal_with_kek(payload, tenant_id, &kek)
}

pub fn seal_job_payload_sqlx(payload: Value, tenant_id: i64) -> Result<Value, sqlx::Error> {
    seal_job_payload(&payload, tenant_id).map_err(|e| sqlx::Error::Configuration(e.into()))
}

/// Decrypt a claimed row. Legacy plaintext (no `_weissman_job_enc`) passes through.
pub fn open_job_payload(payload: &Value, tenant_id: i64) -> Result<Value, String> {
    if payload.get(ENC_KEY).is_none() {
        return Ok(payload.clone());
    }
    let Some(kek) = current_kek() else {
        return Err("job payload is encrypted but vault KEK is not installed".into());
    };
    open_with_kek(payload, tenant_id, &kek)
}

pub(crate) fn seal_with_kek(
    payload: &Value,
    tenant_id: i64,
    kek: &[u8; 32],
) -> Result<Value, String> {
    let plain = if payload.get(ENC_KEY).is_some() {
        open_with_kek(payload, tenant_id, kek)?
    } else {
        payload.clone()
    };
    let bus = plain.get(PAYLOAD_BUS_KEY).cloned();
    let mut inner = plain;
    if let Some(obj) = inner.as_object_mut() {
        obj.remove(PAYLOAD_BUS_KEY);
    }
    let msg = serde_json::to_vec(&inner).map_err(|e| e.to_string())?;
    let wrap = tenant_wrap_key(kek, tenant_id);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let aad = tenant_aad(tenant_id);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &msg,
                aad: &aad,
            },
        )
        .map_err(|_| "job envelope encrypt failed".to_string())?;
    let mut out = json!({
        ENC_KEY: {
            "v": 1,
            "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce.as_slice()),
            "ct": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ct),
        }
    });
    if let Some(bus) = bus {
        out[PAYLOAD_BUS_KEY] = bus;
    }
    Ok(out)
}

pub(crate) fn open_with_kek(
    payload: &Value,
    tenant_id: i64,
    kek: &[u8; 32],
) -> Result<Value, String> {
    let enc = payload
        .get(ENC_KEY)
        .ok_or_else(|| "missing job envelope".to_string())?;
    let v = enc.get("v").and_then(|x| x.as_i64()).unwrap_or(0);
    if v != 1 {
        return Err(format!("unsupported job envelope version {v}"));
    }
    let nonce_b64 = enc
        .get("nonce")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "job envelope missing nonce".to_string())?;
    let ct_b64 = enc
        .get("ct")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "job envelope missing ct".to_string())?;
    let nonce_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, nonce_b64)
        .map_err(|_| "job envelope nonce is not base64".to_string())?;
    let ct = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ct_b64)
        .map_err(|_| "job envelope ct is not base64".to_string())?;
    if nonce_bytes.len() != 12 {
        return Err("job envelope nonce must be 12 bytes".into());
    }
    let wrap = tenant_wrap_key(kek, tenant_id);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = tenant_aad(tenant_id);
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        .map_err(|_| "job envelope decrypt failed".to_string())?;
    let mut inner: Value = serde_json::from_slice(&pt)
        .map_err(|_| "job envelope plaintext is not JSON".to_string())?;
    if let Some(bus) = payload.get(PAYLOAD_BUS_KEY) {
        if let Some(obj) = inner.as_object_mut() {
            obj.insert(PAYLOAD_BUS_KEY.to_string(), bus.clone());
        }
    }
    Ok(inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn seal_round_trip_keeps_bus_plaintext_and_hides_inner() {
        let kek = [0x11u8; 32];
        let plain = json!({
            PAYLOAD_BUS_KEY: { "envelope": { "v": 1, "sig": "aabb" } },
            "target": "10.0.0.9",
            "api_token": "short-lived-secret"
        });
        let sealed = seal_with_kek(&plain, 7, &kek).expect("seal");
        assert!(sealed.get(ENC_KEY).is_some());
        assert_eq!(sealed.get(PAYLOAD_BUS_KEY), plain.get(PAYLOAD_BUS_KEY));
        let dumped = serde_json::to_string(&sealed).unwrap();
        assert!(
            !dumped.contains("10.0.0.9"),
            "target must not appear in ciphertext JSON"
        );
        assert!(
            !dumped.contains("short-lived-secret"),
            "inner secret must not appear in ciphertext JSON"
        );
        assert!(dumped.contains(PAYLOAD_BUS_KEY));
        let opened = open_with_kek(&sealed, 7, &kek).expect("open");
        assert_eq!(
            opened.get("target").and_then(|v| v.as_str()),
            Some("10.0.0.9")
        );
        assert_eq!(
            opened.get("api_token").and_then(|v| v.as_str()),
            Some("short-lived-secret")
        );
        assert_eq!(opened.get(PAYLOAD_BUS_KEY), plain.get(PAYLOAD_BUS_KEY));
    }

    #[test]
    fn wrong_tenant_cannot_open() {
        let kek = [0x22u8; 32];
        let plain = json!({ "target": "192.0.2.1" });
        let sealed = seal_with_kek(&plain, 1, &kek).unwrap();
        assert!(open_with_kek(&sealed, 2, &kek).is_err());
    }

    #[test]
    fn missing_enc_passthrough() {
        let plain = json!({ PAYLOAD_BUS_KEY: { "ok": true }, "x": 1 });
        assert!(plain.get(ENC_KEY).is_none());
        let opened = open_job_payload(&plain, 9).expect("legacy plaintext");
        assert_eq!(opened, plain);
    }

    #[test]
    fn open_job_payload_passthrough_without_enc_even_without_kek() {
        let plain = json!({ "kind": "scan", "host": "example.test" });
        let opened = open_job_payload(&plain, 3).expect("legacy");
        assert_eq!(opened, plain);
    }

    #[test]
    fn production_source_has_no_bulk_decrypt() {
        let src = include_str!("job_envelope.rs");
        let prod = src.split("#[cfg(test)]").next().expect("production source");
        assert!(!prod.contains("decrypt_all"));
        assert!(!prod.contains("SELECT payload FROM weissman_async_jobs"));
        assert!(prod.contains(ENC_KEY));
        assert!(prod.contains("weissman-job-bus-v1|"));
    }

    #[test]
    fn seal_with_kek_is_the_only_encrypt_entry() {
        let src = include_str!("job_envelope.rs");
        let prod = src.split("#[cfg(test)]").next().expect("production source");
        assert_eq!(
            prod.matches(".encrypt(").count(),
            1,
            "single encrypt site — no bulk helper"
        );
        assert!(prod.contains("cipher.encrypt") || prod.contains(".encrypt("));
    }
}
