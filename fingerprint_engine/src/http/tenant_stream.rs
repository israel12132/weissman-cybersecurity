//! Tenant scoping for realtime broadcast channels (SSE/WS).
//!
//! Every SSE/WS telemetry channel (`telemetry`, `timing`, `redteam`, `radar`, `swarm`)
//! is a **process-global** `tokio::sync::broadcast` fanned out across replicas by
//! [`crate::telemetry_bus`]. Without scoping, a socket owned by tenant B receives
//! tenant A's live scan/containment telemetry — the one place that bypasses the
//! Postgres RLS model.
//!
//! This module stamps every payload with its owning tenant (`_tid`) at publish time and
//! filters per-subscriber at delivery time. The stamp is a JSON field, so it survives the
//! opaque string round-trip through the Redis cross-replica bridge with no bus changes.
//!
//! **Fail-closed:** a payload with no `_tid` is dropped by [`visible_to`] — a producer that
//! forgets to stamp cannot leak. Genuinely platform-wide system events must opt in
//! explicitly with [`SYSTEM_TENANT`] (`_tid = 0`), which every subscriber receives.

use serde_json::Value;

/// Sentinel tenant id for platform-wide system events every tenant may see.
/// Producers must set this **explicitly** — the absence of a stamp is never treated as system-wide.
pub const SYSTEM_TENANT: i64 = 0;

/// Stamp a broadcast payload with the owning tenant so subscribers can filter it.
///
/// If `raw` is a JSON object the `_tid` field is inserted in place; otherwise the payload
/// is wrapped as `{"_tid":N,"_raw":"<original>"}` and unwrapped on delivery.
#[must_use]
pub fn stamp(tenant_id: i64, raw: &str) -> String {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(mut m)) => {
            m.insert("_tid".to_string(), Value::from(tenant_id));
            Value::Object(m).to_string()
        }
        _ => serde_json::json!({ "_tid": tenant_id, "_raw": raw }).to_string(),
    }
}

/// Convenience: stamp `value` (already a JSON value) for `tenant_id`.
#[must_use]
pub fn stamp_value(tenant_id: i64, mut value: Value) -> String {
    if let Value::Object(ref mut m) = value {
        m.insert("_tid".to_string(), Value::from(tenant_id));
        return value.to_string();
    }
    serde_json::json!({ "_tid": tenant_id, "_raw": value.to_string() }).to_string()
}

/// Return the deliverable payload iff it belongs to `viewer_tid` (or is a [`SYSTEM_TENANT`]
/// event). Fail-closed: unstamped payloads and cross-tenant payloads return `None`.
#[must_use]
pub fn visible_to(raw: &str, viewer_tid: i64) -> Option<String> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let tid = v.get("_tid").and_then(Value::as_i64)?;
    if tid != SYSTEM_TENANT && tid != viewer_tid {
        return None;
    }
    // If we wrapped a non-object payload, hand back the original string.
    if let Some(inner) = v.get("_raw").and_then(Value::as_str) {
        return Some(inner.to_string());
    }
    Some(raw.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamped_object_visible_only_to_owner() {
        let msg = stamp(42, r#"{"event":"containment","client_id":"7"}"#);
        assert!(visible_to(&msg, 42).is_some());
        assert!(visible_to(&msg, 43).is_none());
    }

    #[test]
    fn unstamped_is_dropped_fail_closed() {
        assert!(visible_to(r#"{"event":"x"}"#, 42).is_none());
        assert!(visible_to("not json", 42).is_none());
    }

    #[test]
    fn system_tenant_visible_to_all() {
        let msg = stamp(SYSTEM_TENANT, r#"{"event":"maintenance"}"#);
        assert!(visible_to(&msg, 1).is_some());
        assert!(visible_to(&msg, 999).is_some());
    }

    #[test]
    fn non_object_payload_roundtrips() {
        let msg = stamp(5, "plain-text-progress");
        assert_eq!(visible_to(&msg, 5).as_deref(), Some("plain-text-progress"));
        assert!(visible_to(&msg, 6).is_none());
    }
}
