//! Background worker — closed-loop SOAR verification with Redis leader election + Prometheus metrics.

use redis::AsyncCommands;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use super::adapters::verify_probe;
use super::verification::{claim_due_tasks, mark_verified, reschedule_or_fail};

const LEADER_KEY: &str = "weissman:soar:verify:leader";

fn poll_interval_secs() -> u64 {
    std::env::var("WEISSMAN_SOAR_VERIFY_POLL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n >= 5)
        .unwrap_or(15)
}

fn leader_ttl_secs() -> i64 {
    (poll_interval_secs() * 2).max(20) as i64
}

fn replica_id() -> String {
    std::env::var("WEISSMAN_REPLICA_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("soar-verify-{}", Uuid::new_v4()))
}

fn worker_enabled() -> bool {
    !matches!(
        std::env::var("WEISSMAN_SOAR_VERIFY_WORKER").as_deref(),
        Ok("0") | Ok("false") | Ok("no")
    )
}

fn record_cycle_metric(outcome: &str) {
    metrics::counter!("weissman_soar_verify_cycles_total", "outcome" => outcome.to_string())
        .increment(1);
}

fn record_task_metric(outcome: &str) {
    metrics::counter!("weissman_soar_verify_tasks_total", "outcome" => outcome.to_string())
        .increment(1);
}

fn set_leader_gauge(is_leader: bool) {
    metrics::gauge!("weissman_soar_verify_leader").set(if is_leader { 1.0 } else { 0.0 });
}

async fn try_acquire_leader(replica: &str) -> bool {
    let Some(url) = std::env::var("REDIS_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
    else {
        // Single-node: always leader.
        return true;
    };
    let Ok(client) = redis::Client::open(url) else {
        return false;
    };
    let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
        return false;
    };
    let acquired: bool = conn.set_nx(LEADER_KEY, replica).await.ok().unwrap_or(false);
    if acquired {
        let _: Result<(), _> = conn.expire(LEADER_KEY, leader_ttl_secs()).await;
        return true;
    }
    let current: Option<String> = conn.get(LEADER_KEY).await.ok();
    if current.as_deref() == Some(replica) {
        let _: Result<(), _> = conn.expire(LEADER_KEY, leader_ttl_secs()).await;
        return true;
    }
    false
}

pub fn spawn_soar_verification_worker(app_pool: Arc<PgPool>, auth_pool: Arc<PgPool>) {
    if !worker_enabled() {
        tracing::info!(target: "soar_worker", "SOAR verification worker disabled");
        return;
    }
    let replica = replica_id();
    tokio::spawn(async move {
        tracing::info!(
            target: "soar_worker",
            replica_id = %replica,
            "SOAR verification worker started (Redis leader election when REDIS_URL set)"
        );
        let mut ticker = tokio::time::interval(Duration::from_secs(poll_interval_secs()));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let is_leader = try_acquire_leader(&replica).await;
            set_leader_gauge(is_leader);
            if !is_leader {
                record_cycle_metric("follower_skip");
                continue;
            }
            match run_cycle(app_pool.as_ref(), auth_pool.as_ref()).await {
                Ok(n) => {
                    record_cycle_metric("ok");
                    metrics::gauge!("weissman_soar_verify_last_cycle_tasks").set(n as f64);
                }
                Err(e) => {
                    record_cycle_metric("error");
                    tracing::warn!(target: "soar_worker", error = %e, "verification cycle error");
                }
            }
        }
    });
}

async fn run_cycle(app_pool: &PgPool, auth_pool: &PgPool) -> Result<u64, String> {
    let tenants: Vec<i64> = sqlx::query_scalar("SELECT id FROM tenants WHERE active = true")
        .fetch_all(auth_pool)
        .await
        .unwrap_or_default();
    let mut processed = 0u64;
    for tenant_id in tenants {
        let tasks = claim_due_tasks(app_pool, tenant_id, 8).await;
        for task in tasks {
            processed += 1;
            let ok = match task.probe_type.as_str() {
                "pr_exists" => verify_heal_job(app_pool, tenant_id, &task.target).await,
                _ => verify_probe(
                    &task.probe_type,
                    &task.target,
                    &task.ports,
                    &task.payload,
                    &task.provider,
                )
                .await
                .unwrap_or(false),
            };
            if ok {
                let detail = format!("verified via {} probe on {}", task.probe_type, task.target);
                if mark_verified(app_pool, &task, &detail).await.is_ok() {
                    record_task_metric("verified");
                } else {
                    record_task_metric("mark_failed");
                }
            } else {
                let detail = format!(
                    "probe {} not satisfied (attempt {}/{})",
                    task.probe_type, task.attempts, task.max_attempts
                );
                if reschedule_or_fail(app_pool, &task, &detail).await.is_ok() {
                    record_task_metric(if task.attempts >= task.max_attempts {
                        "failed"
                    } else {
                        "rescheduled"
                    });
                } else {
                    record_task_metric("reschedule_failed");
                }
            }
        }
    }
    Ok(processed)
}

async fn verify_heal_job(pool: &PgPool, tenant_id: i64, spec_id_str: &str) -> bool {
    let Ok(spec_id) = Uuid::parse_str(spec_id_str) else {
        return false;
    };
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return false;
    };
    let row = sqlx::query("SELECT status FROM auto_heal_job_specs WHERE id = $1")
        .bind(spec_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let _ = tx.commit().await;
    row.and_then(|r| r.try_get::<String, _>("status").ok())
        .map(|s| s == "completed")
        .unwrap_or(false)
}
