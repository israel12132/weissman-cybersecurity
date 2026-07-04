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
