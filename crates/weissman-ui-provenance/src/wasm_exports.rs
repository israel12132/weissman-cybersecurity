//! WASM exports for browser forensic terminal.

use crate::belief::{collapse_belief, FusionMode};
use crate::manifest::{verify_capabilities_manifest, ManifestVerifyStatus, ProvenanceManifest};
use crate::telemetry::{verify_telemetry_event, VerifyStatus};
use serde_json::Value;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn verify_capabilities_integrity(body_json: &str, manifest_json: &str) -> String {
    let result = match (
        serde_json::from_str::<Value>(body_json),
        serde_json::from_str::<ProvenanceManifest>(manifest_json),
    ) {
        (Ok(body), Ok(manifest)) => {
            let bytes = crate::manifest::canonical_capabilities_bytes(&body);
            let hash = crate::manifest::sha256_hex(&bytes);
            let ok = hash == manifest.payload_sha256;
            serde_json::json!({
                "ok": ok,
                "status": if ok { "integrity_valid" } else { "hash_mismatch_tamper" },
                "computed_hash": hash,
                "manifest_hash": manifest.payload_sha256,
            })
        }
        _ => serde_json::json!({
            "ok": false,
            "status": "parse_error",
        }),
    };
    result.to_string()
}

#[wasm_bindgen]
pub fn verify_capabilities_json(body_json: &str, manifest_json: &str, secret: &str) -> String {
    let result = match (
        serde_json::from_str::<Value>(body_json),
        serde_json::from_str::<ProvenanceManifest>(manifest_json),
    ) {
        (Ok(body), Ok(manifest)) => {
            let status = verify_capabilities_manifest(&body, &manifest, secret);
            serde_json::json!({
                "ok": status == ManifestVerifyStatus::Valid,
                "status": format!("{status:?}"),
            })
        }
        _ => serde_json::json!({
            "ok": false,
            "status": "parse_error",
        }),
    };
    result.to_string()
}

#[wasm_bindgen]
pub fn verify_telemetry_json(
    event_json: &str,
    manifest_hash: &str,
    secret: &str,
    belief_probs_json: &str,
    fusion_mode: &str,
    reported_collapse: f64,
) -> String {
    let event: Value = match serde_json::from_str(event_json) {
        Ok(v) => v,
        Err(_) => {
            return serde_json::json!({"ok": false, "status": "parse_error"}).to_string();
        }
    };
    let probs: Vec<f64> = serde_json::from_str(belief_probs_json).unwrap_or_default();
    let mode = FusionMode::parse(fusion_mode);
    let reported = if reported_collapse.is_nan() {
        None
    } else {
        Some(reported_collapse)
    };
    let r = verify_telemetry_event(&event, manifest_hash, secret, &probs, mode, reported);
    serde_json::json!({
        "ok": r.status == VerifyStatus::Valid,
        "status": format!("{:?}", r.status),
        "event_hash": r.event_hash,
        "collapse_belief": r.collapse_belief,
        "detail": r.detail,
    })
    .to_string()
}

#[wasm_bindgen]
pub fn collapse_belief_json(probs_json: &str, fusion_mode: &str) -> f64 {
    let probs: Vec<f64> = serde_json::from_str(probs_json).unwrap_or_default();
    collapse_belief(&probs, FusionMode::parse(fusion_mode))
}
