//! Orchestrator job dispatch — **enqueue only**, never execute engines in-process.
//!
//! Scheduled scans, API-triggered full scans, and emergency intel triggers all
//! enqueue `tenant_full_scan` jobs. The worker is the sole executor.

use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

/// Enqueue a durable `tenant_full_scan` job for one tenant.
pub async fn enqueue_tenant_full_scan(
    pool: &PgPool,
    tenant_id: i64,
    trace_id: Option<String>,
    trigger: &str,
    extra: Option<Value>,
) -> Result<Uuid, sqlx::Error> {
    let mut payload = json!({
        "trigger": trigger,
        "tenant_id": tenant_id,
    });
    if let Some(obj) = payload.as_object_mut() {
        if let Some(Value::Object(extra_fields)) = extra {
            for (k, v) in extra_fields {
                obj.insert(k, v);
            }
        }
    }
    crate::async_jobs::enqueue(pool, tenant_id, "tenant_full_scan", payload, trace_id).await
}

/// List active tenants and enqueue one `tenant_full_scan` per tenant.
pub async fn dispatch_all_tenant_scans(
    app_pool: &PgPool,
    auth_pool: &PgPool,
    trigger: &str,
) -> Result<usize, sqlx::Error> {
    let tenant_ids: Vec<i64> =
        sqlx::query_scalar::<_, i64>("SELECT id FROM tenants WHERE active = true")
            .fetch_all(auth_pool)
            .await?;
    let mut enqueued = 0usize;
    for tenant_id in tenant_ids {
        match enqueue_tenant_full_scan(app_pool, tenant_id, None, trigger, None).await {
            Ok(job_id) => {
                enqueued += 1;
                tracing::info!(
                    target: "orchestrator_dispatch",
                    tenant_id,
                    %job_id,
                    trigger,
                    "tenant_full_scan enqueued"
                );
            }
            Err(e) => {
                tracing::error!(
                    target: "orchestrator_dispatch",
                    tenant_id,
                    error = %e,
                    "tenant_full_scan enqueue failed"
                );
            }
        }
    }
    Ok(enqueued)
}

/// Fire-and-forget: enqueue a single-tenant scan (API / manual trigger).
pub fn spawn_tenant_full_scan_job(app_pool: Arc<PgPool>, tenant_id: i64, trigger: &str) {
    let trigger = trigger.to_string();
    tokio::spawn(async move {
        match enqueue_tenant_full_scan(app_pool.as_ref(), tenant_id, None, &trigger, None).await {
            Ok(job_id) => tracing::info!(
                target: "orchestrator_dispatch",
                tenant_id,
                %job_id,
                trigger = %trigger,
                "single-tenant scan job enqueued"
            ),
            Err(e) => tracing::error!(
                target: "orchestrator_dispatch",
                tenant_id,
                error = %e,
                "single-tenant scan enqueue failed"
            ),
        }
    });
}
