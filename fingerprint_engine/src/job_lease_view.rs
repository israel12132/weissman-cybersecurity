//! Live job-lease diagnostics for `/api/jobs` and the Jobs dashboard.
//!
//! Combines Postgres lock/heartbeat columns with Redis TTL so operators can see *why* a
//! `tenant_full_scan` is stuck instead of a silent `running` forever.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use uuid::Uuid;
use weissman_db::job_queue::{
    compute_stuck_reason, heartbeat_stale_secs, lock_remaining_secs, RedisLeaseView,
};
use weissman_job_bus::{inspect_job_leases, LeaseInspectBatch, LeaseInspection};

/// Snapshot of the Redis lease backend for one API response.
#[derive(Debug, Clone)]
pub struct LeaseBackendStatus {
    pub redis_configured: bool,
    pub error: Option<String>,
}

impl LeaseBackendStatus {
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.error.is_none(),
            "redis_configured": self.redis_configured,
            "detail": self.error,
        })
    }
}

/// Inspect Redis for `job_ids`. Failures are returned in `LeaseBackendStatus`, never faked as
/// "no leases".
pub async fn inspect_leases(
    job_ids: &[Uuid],
) -> (
    LeaseBackendStatus,
    std::collections::HashMap<Uuid, LeaseInspection>,
) {
    let batch: LeaseInspectBatch = inspect_job_leases(job_ids).await;
    (
        LeaseBackendStatus {
            redis_configured: batch.redis_configured,
            error: batch.error,
        },
        batch.leases,
    )
}

fn redis_view(backend: &LeaseBackendStatus, lease: Option<&LeaseInspection>) -> RedisLeaseView {
    match lease {
        Some(l) => RedisLeaseView {
            configured: backend.redis_configured,
            error: backend.error.is_some(),
            exists: l.exists,
            ttl_secs: l.ttl_secs,
            holder: l.holder_worker_id.clone(),
        },
        None => RedisLeaseView {
            configured: backend.redis_configured,
            error: backend.error.is_some(),
            exists: false,
            ttl_secs: -2,
            holder: None,
        },
    }
}

/// Attach live lease/stuck fields onto a job JSON object (mutates in place).
pub fn attach_diagnostics(
    job: &mut Value,
    now: DateTime<Utc>,
    backend: &LeaseBackendStatus,
    lease: Option<&LeaseInspection>,
) {
    let status = job.get("status").and_then(Value::as_str).unwrap_or("");
    let worker_id = job
        .get("worker_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let last_error = job
        .get("last_error")
        .and_then(Value::as_str)
        .map(str::to_string);
    let locked_until = job
        .get("locked_until")
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc));
    let heartbeat_at = job
        .get("heartbeat_at")
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc));

    let redis = redis_view(backend, lease);
    let stuck = compute_stuck_reason(
        status,
        locked_until,
        heartbeat_at,
        worker_id.as_deref(),
        last_error.as_deref(),
        now,
        Some(&redis),
    );

    if let Some(obj) = job.as_object_mut() {
        obj.insert(
            "heartbeat_stale_secs".into(),
            json!(heartbeat_stale_secs(heartbeat_at, now)),
        );
        obj.insert(
            "lock_remaining_secs".into(),
            json!(lock_remaining_secs(locked_until, now)),
        );
        obj.insert("stuck_reason".into(), json!(stuck));
        obj.insert(
            "lease".into(),
            json!({
                "exists": redis.exists,
                "ttl_secs": if redis.exists { json!(redis.ttl_secs) } else { Value::Null },
                "holder": redis.holder,
                "immortal": redis.exists && redis.ttl_secs == -1,
            }),
        );
    }
}

pub fn parse_job_uuid(job: &Value) -> Option<Uuid> {
    job.get("id").and_then(|v| match v {
        Value::String(s) => Uuid::parse_str(s).ok(),
        _ => None,
    })
}
