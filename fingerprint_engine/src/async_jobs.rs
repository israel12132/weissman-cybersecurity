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
    let bus_enabled = bus.is_enabled();

    // Zero-trust path: the worker rejects (permanently dead-letters) any job it
    // claims without a valid signed envelope. The envelope can only be attached
    // AFTER the row exists (on_job_dispatched appends an event keyed by job_id),
    // so insert the job HELD (future run_after -> not claimable) and only make
    // it claimable once the envelope is attached — otherwise a fast worker can
    // claim the still-envelopeless `pending` row in the insert->UPDATE window
    // and kill it ("missing signed envelope"). Non-bus path keeps the plain
    // immediately-`pending` insert.
    let id = if bus_enabled {
        weissman_db::job_queue::enqueue_held(
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

    if bus_enabled {
        match bus
            .on_job_dispatched(id, tenant_id, kind, &payload, trace_id.as_deref())
            .await
        {
            Ok(Some(envelope)) => {
                let mut enriched = payload;
                attach_signed_envelope(&mut enriched, envelope);
                // Atomic: attach envelope AND release the hold (run_after=NULL)
                // so the worker only ever sees this job claimable WITH its
                // envelope present.
                let _ = weissman_db::job_queue::release_hold(pool, id, enriched).await;
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

    // Supervise the reclaim loop (crate::supervised): a panic would otherwise silently stop legacy
    // stale-lock reclaim — the fallback that frees jobs orphaned by a crashed worker — for the rest
    // of the process lifetime. Supervision restarts it with bounded backoff and a
    // `weissman_supervised_restart_total{task="stale_lock_reclaim"}` signal. Panic/exit restart is
    // always safe: reclaim is idempotent (it only frees locks already past their lease). The one-time
    // swarm-coordinator spawn above stays OUTSIDE supervision — it is setup, not the restart-able loop.
    //
    // Stuck-detection (abort+restart a tick wedged on an unreachable Postgres) is OPT-IN via
    // WEISSMAN_SUPERVISOR_STUCK_DEADLINE_SECS. That knob is a single GLOBAL deadline shared by every
    // supervised loop, and this loop has the LONGEST cadence (300s) — so a correct value must exceed
    // 300s, otherwise this loop (which legitimately beats only once per 300s tick) would be
    // false-flagged stuck and abort-restarted every cycle. A deadline above 300s catches a genuinely
    // wedged tick in any of the loops (health 10s / cron ~60s / reclaim 300s) without false positives.
    let cfg = crate::supervised::SupervisorConfig::from_env();
    let hb = crate::supervised::Heartbeat::new();
    tokio::spawn(async move {
        crate::supervised::supervise("stale_lock_reclaim", cfg, Some(hb), move |hb| {
            let pool = pool.clone();
            async move {
                let mut tick = tokio::time::interval(Duration::from_secs(300));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    // Liveness beat for the watchdog — before the (blocking) reclaim query.
                    if let Some(ref h) = hb {
                        h.beat();
                    }
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
            }
        })
        .await;
    });
}
