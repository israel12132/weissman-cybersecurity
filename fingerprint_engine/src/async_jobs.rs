//! Enqueue durable jobs with HTTP trace correlation when present.
//! When Redis + orchestrator secret are configured, dispatches via military-grade [`JobBus`].

use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use weissman_job_bus::JobBus;

use crate::job_orchestration::attach_signed_envelope;

/// Enqueue `weissman_async_jobs` row; `trace_id` taken from request extensions when set.
pub async fn enqueue(
    pool: &PgPool,
    tenant_id: i64,
    kind: &str,
    payload: Value,
    trace_id: Option<String>,
) -> Result<Uuid, sqlx::Error> {
    let bus = JobBus::from_env(pool.clone()).await;
    let bus_on = bus.is_enabled();

    // When the zero-trust bus is enabled, the row must NOT be claimable until its signed envelope
    // has been attached below. If it were inserted as an immediately-runnable `pending` row, a
    // worker polling in the window before the envelope UPDATE lands would claim a still-unsigned
    // job, `on_worker_claimed` would reject it as "missing signed envelope", and it would be
    // permanently dead-lettered. Insert it with a short claim-hold; the envelope UPDATE releases it.
    let id = if bus_on {
        weissman_db::job_queue::enqueue_hold(
            pool,
            tenant_id,
            kind,
            payload.clone(),
            trace_id.as_deref(),
            30,
        )
        .await?
    } else {
        weissman_db::job_queue::enqueue(pool, tenant_id, kind, payload.clone(), trace_id.as_deref())
            .await?
    };

    if bus_on {
        match bus
            .on_job_dispatched(id, tenant_id, kind, &payload, trace_id.as_deref())
            .await
        {
            Ok(Some(envelope)) => {
                let mut enriched = payload;
                attach_signed_envelope(&mut enriched, envelope);
                // Attach the envelope AND release the claim-hold (run_after = now()) atomically so
                // the job only becomes claimable once it carries a valid signed envelope.
                let _ = sqlx::query(
                    "UPDATE weissman_async_jobs SET payload = $2, run_after = now() WHERE id = $1",
                )
                .bind(id)
                .bind(sqlx::types::Json(enriched))
                .execute(pool)
                .await;
            }
            Ok(None) => {
                if weissman_core::tls_policy::is_production_environment() {
                    let _ = sqlx::query(
                        "UPDATE weissman_async_jobs SET status = 'failed', last_error = $2 WHERE id = $1",
                    )
                    .bind(id)
                    .bind("job bus dispatch produced no signed envelope in production")
                    .execute(pool)
                    .await;
                    return Err(sqlx::Error::Protocol(
                        "job bus dispatch produced no signed envelope".into(),
                    ));
                }
            }
            Err(e) => {
                if weissman_core::tls_policy::is_production_environment() {
                    let _ = sqlx::query(
                        "UPDATE weissman_async_jobs SET status = 'failed', last_error = $2 WHERE id = $1",
                    )
                    .bind(id)
                    .bind(format!("job bus dispatch failed: {e}"))
                    .execute(pool)
                    .await;
                    return Err(sqlx::Error::Protocol(format!(
                        "job bus dispatch failed: {e}"
                    )));
                }
                tracing::warn!(
                    target: "async_jobs",
                    job_id = %id,
                    error = %e,
                    "job bus dispatch event failed (row enqueued)"
                );
            }
        }
    } else if weissman_core::tls_policy::is_production_environment()
        && crate::http::rate_limit_redis::is_enabled()
    {
        let _ = sqlx::query(
            "UPDATE weissman_async_jobs SET status = 'failed', last_error = $2 WHERE id = $1",
        )
        .bind(id)
        .bind("zero-trust job bus not enabled despite production Redis + orchestrator policy")
        .execute(pool)
        .await;
        return Err(sqlx::Error::Protocol(
            "zero-trust job bus not enabled in production".into(),
        ));
    }

    Ok(id)
}

/// Every 5 minutes, orphan recovery via swarm coordinator (sub-second) + legacy reclaim fallback.
pub fn spawn_stale_lock_reclaim_loop(pool: Arc<PgPool>) {
    weissman_job_bus::spawn_coordinator_if_enabled((*pool).clone());

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match weissman_db::job_queue::reclaim_stale_running_locks(pool.as_ref()).await {
                Ok(n) if n > 0 => tracing::info!(
                    target: "async_jobs",
                    reclaimed = n,
                    "legacy stale lock reclaim (fallback)"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    target: "async_jobs",
                    error = %e,
                    "stale lock reclaim failed"
                ),
            }
        }
    });
}
