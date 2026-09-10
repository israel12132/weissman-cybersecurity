//! Envelope encryption for durable job-bus payloads.
//!
//! `weissman_worker` is BYPASSRLS and can `SELECT` every queue row. A bulk dump
//! of `weissman_async_jobs.payload` must be ciphertext. The AES-256-GCM key is
//! derived per tenant from the process vault KEK
//! (`weissman-job-bus-v1|` ‖ tenant_id LE bytes).
//!
//! Decrypt only with a known tenant: the worker claim path, and the
//! tenant-scoped job API ([`reveal_job_payload_for_tenant`]). Never via a
//! bulk decrypt over the whole job table.
//!
//! The zero-trust bus envelope (`_weissman_job_bus`) stays a **plaintext
//! sibling** so `payload ? '_weissman_job_bus'` still gates claim. Indexable
//! routing keys `client_id` and `engine` are also plaintext siblings so SQL
//! filters keep working — and they are bound as GCM AAD so swapping those
//! siblings without the ciphertext fails open. Secrets, `target`, and
//! `validated_scope` stay inside `_weissman_job_enc`.
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
/// Indexable, non-secret JSON keys copied next to the ciphertext.
const ROUTING_KEYS: &[&str] = &["client_id", "engine"];

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

/// AEAD associated data for envelope v2: tenant (from the row, not JSON) plus
/// the plaintext routing siblings. Changing `client_id` / `engine` next to the
/// ciphertext makes GCM open fail.
fn routing_aad(tenant_id: i64, payload: &Value) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(b"weissman-job-aad-v2|");
    aad.extend_from_slice(&tenant_id.to_le_bytes());
    aad.push(0);
    push_canonical_atom(&mut aad, payload.get("client_id"));
    aad.push(0);
    push_canonical_atom(&mut aad, payload.get("engine"));
    aad
}

fn push_canonical_atom(out: &mut Vec<u8>, v: Option<&Value>) {
    match v {
        Some(Value::String(s)) => {
            out.push(b's');
            out.extend_from_slice(s.as_bytes());
        }
        Some(Value::Number(n)) => {
            out.push(b'n');
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Some(Value::Bool(b)) => {
            out.push(b'b');
            out.extend_from_slice(if *b { b"1" } else { b"0" });
        }
        Some(Value::Null) | None => out.push(b'-'),
        Some(other) => {
            out.push(b'j');
            if let Ok(bytes) = serde_json::to_vec(other) {
                out.extend_from_slice(&bytes);
            }
        }
    }
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

/// Tenant-scoped API/UI read: plaintext for the owning tenant, never ciphertext.
/// On decrypt failure, only routing siblings are returned.
#[must_use]
pub fn reveal_job_payload_for_tenant(payload: &Value, tenant_id: i64) -> Value {
    match open_job_payload(payload, tenant_id) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut() {
                obj.remove(ENC_KEY);
            }
            v
        }
        Err(e) => {
            tracing::error!(
                target: "job_envelope",
                tenant_id,
                error = %e,
                "tenant job payload reveal failed"
            );
            routing_only_view(payload)
        }
    }
}

fn routing_only_view(payload: &Value) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(bus) = payload.get(PAYLOAD_BUS_KEY) {
        out.insert(PAYLOAD_BUS_KEY.to_string(), bus.clone());
    }
    for k in ROUTING_KEYS {
        if let Some(v) = payload.get(*k) {
            out.insert((*k).to_string(), v.clone());
        }
    }
    Value::Object(out)
}

fn copy_routing_siblings(plain: &Value, out: &mut Value) {
    for k in ROUTING_KEYS {
        if let Some(v) = plain.get(*k) {
            out[*k] = v.clone();
        }
    }
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
    let aad = routing_aad(tenant_id, &inner);
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
            "v": 2,
            "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce.as_slice()),
            "ct": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ct),
        }
    });
    if let Some(bus) = bus {
        out[PAYLOAD_BUS_KEY] = bus;
    }
    copy_routing_siblings(&inner, &mut out);
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
    let aad_owned: Vec<u8> = match v {
        1 => {
            // Pre-routing AAD: tenant_id only. Still accepted so in-flight v1
            // rows from this branch's first envelope commit can be claimed.
            tenant_aad(tenant_id).to_vec()
        }
        2 => routing_aad(tenant_id, payload),
        other => return Err(format!("unsupported job envelope version {other}")),
    };
    let aad = aad_owned.as_slice();
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
    let pt = cipher
        .decrypt(nonce, Payload { msg: &ct, aad })
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
        assert!(prod.contains("reveal_job_payload_for_tenant"));
        assert!(prod.contains("const ROUTING_KEYS: &[&str] = &[\"client_id\", \"engine\"]"));
        assert!(
            !prod.contains("ROUTING_KEYS: &[&str] = &[\"client_id\", \"engine\", \"target\"]")
                && !prod.contains("\"validated_scope\"]"),
            "target and validated_scope must stay inside ciphertext"
        );
    }

    #[test]
    fn sealed_row_exposes_routing_siblings_not_secrets() {
        let kek = [0x33u8; 32];
        let plain = json!({
            "client_id": "c-1",
            "engine": "osint_payload_engine",
            "target": "secret.example",
            "validated_scope": {"cidr": "10.0.0.0/8"},
            "api_token": "tok_live",
            PAYLOAD_BUS_KEY: {"v": 1, "tenant_id": 9, "sig": "x"}
        });
        let sealed = seal_with_kek(&plain, 9, &kek).expect("seal");
        assert_eq!(
            sealed.get("client_id").and_then(|v| v.as_str()),
            Some("c-1")
        );
        assert_eq!(
            sealed.get("engine").and_then(|v| v.as_str()),
            Some("osint_payload_engine")
        );
        assert!(sealed.get("target").is_none());
        assert!(sealed.get("validated_scope").is_none());
        assert!(sealed.get("api_token").is_none());
        assert!(sealed.get(ENC_KEY).is_some());
        assert!(sealed.get(PAYLOAD_BUS_KEY).is_some());
        let dump = serde_json::to_string(&sealed).unwrap();
        assert!(!dump.contains("secret.example"));
        assert!(!dump.contains("10.0.0.0/8"));
        assert!(!dump.contains("tok_live"));
    }

    #[test]
    fn reveal_with_kek_returns_plaintext_without_ciphertext() {
        let kek = [0x44u8; 32];
        let plain = json!({
            "engine": "osint",
            "target": "t",
            "validated_scope": {"host": "example.com"},
            PAYLOAD_BUS_KEY: {"v": 1, "tenant_id": 2, "sig": "s"}
        });
        let sealed = seal_with_kek(&plain, 2, &kek).expect("seal");
        let mut view = open_with_kek(&sealed, 2, &kek).expect("open");
        if let Some(obj) = view.as_object_mut() {
            obj.remove(ENC_KEY);
        }
        assert_eq!(view.get("engine").and_then(|v| v.as_str()), Some("osint"));
        assert_eq!(view.get("target").and_then(|v| v.as_str()), Some("t"));
        assert_eq!(
            view.get("validated_scope")
                .and_then(|v| v.get("host"))
                .and_then(|v| v.as_str()),
            Some("example.com")
        );
        assert!(view.get(ENC_KEY).is_none());
        assert!(view.get(PAYLOAD_BUS_KEY).is_some());
    }

    #[test]
    fn reveal_without_kek_returns_only_routing_siblings() {
        let kek = [0x55u8; 32];
        let plain = json!({
            "engine": "osint",
            "client_id": 7,
            "target": "must-not-leak",
            "validated_scope": {"host": "example.com"}
        });
        let sealed = seal_with_kek(&plain, 4, &kek).expect("seal");
        let view = reveal_job_payload_for_tenant(&sealed, 4);
        assert_eq!(view.get("engine").and_then(|v| v.as_str()), Some("osint"));
        assert_eq!(view.get("client_id").and_then(|v| v.as_i64()), Some(7));
        assert!(view.get("target").is_none());
        assert!(view.get("validated_scope").is_none());
        assert!(view.get(ENC_KEY).is_none());
    }

    #[test]
    fn handlers_source_pin_reveal_before_redact() {
        let jobs = include_str!("server_handlers_jobs.inc");
        let status_fn = jobs
            .split("async fn api_async_job_status")
            .nth(1)
            .expect("GET /api/jobs/:id handler");
        let compact: String = status_fn.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            compact.contains(
                "scan_payload_redaction::redact_for_api(&crate::job_envelope::reveal_job_payload_for_tenant"
            ),
            "GET /api/jobs/:id must redact(reveal(payload)) so validated_scope/engine reach the client"
        );
        let list_fn = jobs
            .split("async fn api_async_jobs_list")
            .nth(1)
            .expect("GET /api/jobs list handler");
        assert!(
            list_fn.contains("reveal_job_payload_for_tenant"),
            "jobs list must decrypt per row so target/engine remain visible"
        );
        let sqlx = include_str!("server_handlers_sqlx.inc");
        assert!(
            sqlx.matches("reveal_job_payload_for_tenant").count() >= 3,
            "engine history + both selected_job export paths"
        );
    }

    #[test]
    fn api_shape_matches_scan_pipeline_e2e() {
        let kek = [0x66u8; 32];
        let plain = json!({
            "engine": "osint",
            "validated_scope": {"host": "example.com"},
            "github_token": "ghp_e2e_hydration_test_token_not_real",
            "aws_external_id": "ext-secret"
        });
        let sealed = seal_with_kek(&plain, 1, &kek).expect("seal");
        let dumped = serde_json::to_string(&sealed).unwrap();
        assert!(
            !dumped.contains("example.com"),
            "validated_scope must not appear in the stored JSON dump"
        );
        assert_eq!(sealed.get("engine").and_then(|v| v.as_str()), Some("osint"));
        let opened = open_with_kek(&sealed, 1, &kek).expect("open");
        let api = crate::scan_payload_redaction::redact_for_api(&opened);
        assert_eq!(api.get("engine").and_then(|v| v.as_str()), Some("osint"));
        assert_eq!(
            api.get("validated_scope")
                .and_then(|v| v.get("host"))
                .and_then(|v| v.as_str()),
            Some("example.com")
        );
        assert_eq!(
            api.get("github_token").and_then(|v| v.as_str()),
            Some(crate::scan_payload_redaction::MASKED_SECRET)
        );
        assert_eq!(
            api.get("aws_external_id").and_then(|v| v.as_str()),
            Some(crate::scan_payload_redaction::MASKED_SECRET)
        );
        assert!(api.get(ENC_KEY).is_none());
    }

    #[test]
    fn tampered_routing_sibling_fails_open() {
        let kek = [0x77u8; 32];
        let plain = json!({
            "engine": "osint",
            "client_id": 5,
            "target": "https://example.com"
        });
        let mut sealed = seal_with_kek(&plain, 3, &kek).expect("seal");
        assert_eq!(
            sealed
                .get(ENC_KEY)
                .and_then(|e| e.get("v"))
                .and_then(|v| v.as_i64()),
            Some(2)
        );
        sealed["engine"] = json!("timing");
        assert!(
            open_with_kek(&sealed, 3, &kek).is_err(),
            "changing plaintext engine must fail GCM AAD"
        );
        sealed["engine"] = json!("osint");
        sealed["client_id"] = json!(99);
        assert!(
            open_with_kek(&sealed, 3, &kek).is_err(),
            "changing plaintext client_id must fail GCM AAD"
        );
        sealed["client_id"] = json!(5);
        let opened = open_with_kek(&sealed, 3, &kek).expect("untampered");
        assert_eq!(
            opened.get("target").and_then(|v| v.as_str()),
            Some("https://example.com")
        );
    }

    #[test]
    fn seal_with_kek_is_the_only_encrypt_entry() {
        let src = include_str!("job_envelope.rs");
        let prod = src.split("#[cfg(test)]").next().expect("production source");
        assert!(prod.contains("weissman-job-aad-v2|"));
        assert_eq!(
            prod.matches(".encrypt(").count(),
            1,
            "single encrypt site — no bulk helper"
        );
        assert!(prod.contains("cipher.encrypt") || prod.contains(".encrypt("));
    }
}
