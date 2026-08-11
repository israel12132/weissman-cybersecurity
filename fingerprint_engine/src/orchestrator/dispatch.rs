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
    let mut skipped = 0usize;
    for tenant_id in tenant_ids {
        // Coalesce: one outstanding scheduled full scan per tenant is enough. This loop runs on a
        // fixed interval (default 60s) regardless of whether anything is draining the queue, so
        // without this check a stalled worker turns into unbounded growth — 2111 identical
        // `tenant_full_scan` rows accumulated over the four-day 2026-08-06 outage, none of which
        // carried information the first one did not. Executing that backlog after recovery would
        // also mean 2111 redundant scans against the customer's estate.
        //
        // Only the *scheduled* path coalesces. `enqueue_tenant_full_scan` stays unconditional so
        // an operator-triggered or API-triggered scan is never silently dropped.
        match has_inflight_full_scan(app_pool, tenant_id).await {
            Ok(true) => {
                skipped += 1;
                tracing::debug!(
                    target: "orchestrator_dispatch",
                    tenant_id,
                    trigger,
                    "tenant_full_scan already pending/running — not enqueuing another"
                );
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                // Fail closed: if we cannot tell whether one is in flight, do not pile another on.
                tracing::warn!(
                    target: "orchestrator_dispatch",
                    tenant_id,
                    error = %e,
                    "in-flight scan check failed — skipping this tenant for now"
                );
                skipped += 1;
                continue;
            }
        }
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
    if skipped > 0 {
        tracing::info!(
            target: "orchestrator_dispatch",
            skipped,
            enqueued,
            trigger,
            "coalesced scheduled full scans for tenants with one already in flight"
        );
    }
    Ok(enqueued)
}

/// True when this tenant already has a `tenant_full_scan` queued or executing.
async fn has_inflight_full_scan(pool: &PgPool, tenant_id: i64) -> Result<bool, sqlx::Error> {
    let mut tx = weissman_db::begin_tenant_tx(pool, tenant_id).await?;
    let exists: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1 FROM weissman_async_jobs
                WHERE tenant_id = $1
                  AND kind = 'tenant_full_scan'
                  AND status IN ('pending', 'running')
           )"#,
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    let _ = tx.rollback().await;
    Ok(exists)
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
