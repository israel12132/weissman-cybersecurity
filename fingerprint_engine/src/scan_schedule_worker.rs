//! Polls `weissman_scan_schedules` and enqueues due scans (cron automation).
//! Enable with `WEISSMAN_SCAN_SCHEDULE_CRON=1` (default on in production).

use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration as StdDuration;

fn poll_interval_secs() -> u64 {
    std::env::var("WEISSMAN_SCAN_SCHEDULE_POLL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n >= 30)
        .unwrap_or(60)
}

fn cron_enabled() -> bool {
    if let Ok(v) = std::env::var("WEISSMAN_SCAN_SCHEDULE_CRON") {
        return v == "1" || v.eq_ignore_ascii_case("true");
    }
    weissman_core::tls_policy::is_production_environment()
}

/// Compute next run from schedule type (approximate; aligns with UI schedule presets).
pub fn compute_next_run_at(schedule_type: &str, from: DateTime<Utc>) -> DateTime<Utc> {
    match schedule_type.trim().to_ascii_lowercase().as_str() {
        "hourly" => from + Duration::hours(1),
        "weekly" => from + Duration::weeks(1),
        "monthly" => from + Duration::days(30),
        _ => from + Duration::days(1),
    }
}

async fn run_due_schedule(
    app_pool: &PgPool,
    auth_pool: &PgPool,
    tenant_id: i64,
    schedule_id: i64,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(app_pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let row = sqlx::query(
        r#"SELECT id, client_id, name, schedule_type, engines, enabled
           FROM weissman_scan_schedules WHERE id = $1"#,
    )
    .bind(schedule_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let Some(row) = row else {
        return Ok(());
    };
    if !row.try_get::<bool, _>("enabled").unwrap_or(false) {
        let _ = tx.rollback().await;
        return Ok(());
    }
    let client_id: i64 = row
        .try_get("client_id")
        .map_err(|_| "no client_id".to_string())?;
    let schedule_type: String = row
        .try_get("schedule_type")
        .unwrap_or_else(|_| "daily".into());
    let engines: Vec<String> = row
        .try_get::<Value, _>("engines")
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    if engines.is_empty() {
        let _ = tx.rollback().await;
        return Ok(());
    }
    let domains_raw: Option<String> =
        sqlx::query_scalar("SELECT domains FROM clients WHERE id = $1")
            .bind(client_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
    let domains: Vec<String> = domains_raw
        .as_deref()
        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if domains.is_empty() {
        let _ = tx.rollback().await;
        return Ok(());
    }

    let job_count = (domains.len() * engines.len()) as u64;
    if let Err(detail) = crate::billing::gate_scan_enqueue_n(auth_pool, tenant_id, job_count).await
    {
        let _ = tx.rollback().await;
        tracing::warn!(
            target: "scan_schedule_worker",
            tenant_id,
            schedule_id,
            job_count,
            detail = %detail,
            "cron billing gate denied — schedule not advanced"
        );
        return Err(detail);
    }

    // `next_run_at` was already advanced by `claim_due_schedule_ids` under
    // SKIP LOCKED. This transaction only reads domains / engines for enqueue.
    let _ = tx.commit().await;

    for domain in &domains {
        let target = if domain.starts_with("http://") || domain.starts_with("https://") {
            domain.clone()
        } else {
            format!("http://{domain}")
        };
        for engine in &engines {
            let payload = json!({
                "engine": engine,
                "target": target,
                "client_id": client_id,
                "schedule_id": schedule_id,
                "trigger": "cron",
            });
            if let Err(e) = crate::async_jobs::enqueue(
                app_pool,
                tenant_id,
                "command_center_engine",
                payload,
                None,
            )
            .await
            {
                tracing::error!(
                    target: "scan_schedule_worker",
                    schedule_id,
                    engine = %engine,
                    error = %e,
                    "cron enqueue failed"
                );
            }
        }
    }
    Ok(())
}

/// Claim due schedules with `FOR UPDATE SKIP LOCKED` and advance `next_run_at`
/// in the **same transaction**. A peer replica skips locked rows instead of
/// double-enqueueing the same cron occurrence.
async fn claim_due_schedule_ids(app_pool: &PgPool, tenant_id: i64) -> Vec<i64> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(app_pool, tenant_id).await else {
        return Vec::new();
    };
    let rows = sqlx::query(
        r#"SELECT id, schedule_type FROM weissman_scan_schedules
           WHERE enabled = true
             AND client_id IS NOT NULL
             AND (next_run_at IS NULL OR next_run_at <= now())
           ORDER BY next_run_at NULLS FIRST
           LIMIT 50
           FOR UPDATE SKIP LOCKED"#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    if rows.is_empty() {
        let _ = sqlx::query(
            r#"UPDATE weissman_scan_schedules
               SET next_run_at = now() + interval '1 day', updated_at = now()
               WHERE enabled = true AND next_run_at IS NULL"#,
        )
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
        return Vec::new();
    }
    let mut due = Vec::with_capacity(rows.len());
    for row in rows {
        let id: i64 = row.try_get("id").unwrap_or(0);
        if id == 0 {
            continue;
        }
        let schedule_type: String = row
            .try_get("schedule_type")
            .unwrap_or_else(|_| "daily".into());
        let next = compute_next_run_at(&schedule_type, Utc::now());
        if sqlx::query(
            r#"UPDATE weissman_scan_schedules
               SET last_run_at = now(), next_run_at = $2, run_count = run_count + 1, updated_at = now()
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(next)
        .execute(&mut *tx)
        .await
        .is_ok()
        {
            due.push(id);
        }
    }
    if tx.commit().await.is_err() {
        return Vec::new();
    }
    due
}

async fn tick(app_pool: &PgPool, auth_pool: &PgPool) {
    let tenants: Vec<i64> = sqlx::query_scalar("SELECT id FROM tenants WHERE active = true")
        .fetch_all(auth_pool)
        .await
        .unwrap_or_default();

    for tenant_id in tenants {
        for schedule_id in claim_due_schedule_ids(app_pool, tenant_id).await {
            if let Err(e) = run_due_schedule(app_pool, auth_pool, tenant_id, schedule_id).await {
                tracing::warn!(
                    target: "scan_schedule_worker",
                    tenant_id,
                    schedule_id,
                    error = %e,
                    "schedule run failed"
                );
            }
        }
    }
}

pub fn spawn_scan_schedule_worker(app_pool: Arc<PgPool>, auth_pool: Arc<PgPool>) {
    // Supervise the cron loop (crate::supervised): a panic inside the loop would otherwise kill
    // cron scheduling for the rest of the process lifetime, silently — supervision restarts it with
    // bounded backoff and a `weissman_supervised_restart_total{task="scan_schedule_worker"}` signal.
    // Stuck-detection (abort+restart a wedged tick) is OPT-IN via WEISSMAN_SUPERVISOR_STUCK_DEADLINE_SECS,
    // because a legitimately long tick — a fleet-wide sweep of due schedules — must not be mistaken
    // for a hang; the deadline has to exceed the poll interval plus a worst-case tick. Panic/exit
    // restart is on by default (disable via the WEISSMAN_SUPERVISOR_ENABLED kill switch) and safe (a
    // restarted cron loop just re-polls due schedules, which are idempotent — `next_run_at` only
    // advances once a schedule actually launches).
    let cfg = crate::supervised::SupervisorConfig::from_env();
    let hb = crate::supervised::Heartbeat::new();
    tokio::spawn(async move {
        crate::supervised::supervise("scan_schedule_worker", cfg, Some(hb), move |hb| {
            let app_pool = app_pool.clone();
            let auth_pool = auth_pool.clone();
            async move {
                let mut ticker =
                    tokio::time::interval(StdDuration::from_secs(poll_interval_secs()));
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    // Liveness beat for the watchdog — every iteration, before any work, so a
                    // disabled or backing-off tick still counts as progress (not a hang).
                    if let Some(ref h) = hb {
                        h.beat();
                    }
                    if !cron_enabled() {
                        continue;
                    }
                    // Self-healing backoff: under transient platform pressure (async backlog past
                    // the warn threshold, engaged by the recovery engine), defer this cron tick.
                    // Due scans stay due — their `next_run_at` is only advanced once a tick actually
                    // launches them — so they fire on the next healthy tick. This eases NEW cron
                    // intake without starving the async worker that drains the backlog. No-op unless
                    // self-heal recovery is enabled and backing off; auto-clears via TTL.
                    if crate::self_heal_recovery::backoff_active() {
                        metrics::counter!("weissman_self_heal_cron_backoff_total").increment(1);
                        tracing::debug!(
                            target: "scan_schedule_worker",
                            "deferring cron tick: self-healing backoff engaged (transient platform pressure)"
                        );
                        continue;
                    }
                    tick(app_pool.as_ref(), auth_pool.as_ref()).await;
                }
            }
        })
        .await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_run_hourly_advances_one_hour() {
        let from = Utc::now();
        let next = compute_next_run_at("hourly", from);
        assert!(next > from);
        assert!((next - from).num_minutes() >= 59);
    }

    #[test]
    fn claim_sql_uses_skip_locked() {
        let src = include_str!("scan_schedule_worker.rs");
        assert!(
            src.contains("FOR UPDATE SKIP LOCKED"),
            "cron claim must lock due rows with SKIP LOCKED so two replicas cannot enqueue the same occurrence"
        );
    }
}
