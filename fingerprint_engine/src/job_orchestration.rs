//! Integration helpers for [`weissman_job_bus`] — envelope embedding in job payloads.

use serde_json::{json, Value};
use weissman_job_bus::SignedJobEnvelope;

pub const PAYLOAD_BUS_KEY: &str = "_weissman_job_bus";

pub fn attach_signed_envelope(payload: &mut Value, envelope: SignedJobEnvelope) {
    if let Some(obj) = payload.as_object_mut() {
        obj.insert(PAYLOAD_BUS_KEY.to_string(), json!({ "envelope": envelope }));
    }
}

pub fn extract_signed_envelope(payload: &Value) -> Option<SignedJobEnvelope> {
    payload
        .get(PAYLOAD_BUS_KEY)
        .and_then(|b| b.get("envelope"))
        .and_then(|e| serde_json::from_value(e.clone()).ok())
}

pub fn strip_bus_metadata(payload: &Value) -> Value {
    let mut clone = payload.clone();
    if let Some(obj) = clone.as_object_mut() {
        obj.remove(PAYLOAD_BUS_KEY);
    }
    clone
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> SignedJobEnvelope {
        SignedJobEnvelope {
            v: 1,
            job_id: uuid::Uuid::nil(),
            tenant_id: 5,
            kind: "command_center_engine".to_string(),
            payload: json!({ "target": "https://example.com" }),
            issued_at: 1_700_000_000,
            nonce: "nonce-abc".to_string(),
            signature: "sig-xyz".to_string(),
        }
    }

    #[test]
    fn payload_bus_key_is_stable() {
        assert_eq!(PAYLOAD_BUS_KEY, "_weissman_job_bus");
    }

    #[test]
    fn attach_then_extract_round_trips() {
        let mut payload = json!({ "target": "x" });
        let env = sample_envelope();
        attach_signed_envelope(&mut payload, env.clone());
        // Original keys are preserved; bus key is added.
        assert_eq!(payload["target"], "x");
        assert!(payload.get(PAYLOAD_BUS_KEY).is_some());
        let extracted = extract_signed_envelope(&payload).expect("envelope present");
        assert_eq!(extracted, env);
    }

    #[test]
    fn attach_is_noop_on_non_object() {
        let mut payload = json!([1, 2, 3]);
        attach_signed_envelope(&mut payload, sample_envelope());
        assert_eq!(payload, json!([1, 2, 3]));
        assert!(extract_signed_envelope(&payload).is_none());
    }

    #[test]
    fn extract_none_when_key_absent() {
        assert!(extract_signed_envelope(&json!({ "target": "x" })).is_none());
    }

    #[test]
    fn extract_none_when_envelope_malformed() {
        let payload = json!({ "_weissman_job_bus": { "envelope": { "not": "valid" } } });
        assert!(extract_signed_envelope(&payload).is_none());
    }

    #[test]
    fn extract_none_when_bus_key_has_no_envelope_field() {
        let payload = json!({ "_weissman_job_bus": { "other": true } });
        assert!(extract_signed_envelope(&payload).is_none());
    }

    #[test]
    fn strip_removes_only_bus_key_and_leaves_original_untouched() {
        let mut payload = json!({ "target": "x", "client_id": 7 });
        attach_signed_envelope(&mut payload, sample_envelope());
        let stripped = strip_bus_metadata(&payload);
        assert_eq!(stripped, json!({ "target": "x", "client_id": 7 }));
        // strip clones; the input keeps its bus metadata.
        assert!(payload.get(PAYLOAD_BUS_KEY).is_some());
    }

    #[test]
    fn strip_is_noop_when_no_bus_key() {
        let payload = json!({ "target": "x" });
        assert_eq!(strip_bus_metadata(&payload), payload);
    }

    #[test]
    fn strip_is_noop_on_non_object() {
        let payload = json!("just-a-string");
        assert_eq!(strip_bus_metadata(&payload), payload);
    }
}
