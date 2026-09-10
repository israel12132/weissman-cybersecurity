//! Continuous CNAPP graph refresh — enqueues `cnapp_continuous` for tenant clients.
//!
//! Enable with `WEISSMAN_CNAPP_SCHEDULE=1` (default on in production, same pattern as
//! scan cron). Missing clients or enqueue failures are logged; success is never faked.

use serde_json::json;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration as StdDuration;

fn poll_interval_secs() -> u64 {
    std::env::var("WEISSMAN_CNAPP_REFRESH_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n >= 300)
        .unwrap_or(6 * 60 * 60)
}

fn cron_enabled() -> bool {
    if let Ok(v) = std::env::var("WEISSMAN_CNAPP_SCHEDULE") {
        return v == "1" || v.eq_ignore_ascii_case("true");
    }
    weissman_core::tls_policy::is_production_environment()
}

async fn enqueue_tenant(app_pool: &PgPool, tenant_id: i64) -> usize {
    let Ok(mut tx) = crate::db::begin_tenant_tx(app_pool, tenant_id).await else {
        return 0;
    };
    let rows = sqlx::query("SELECT id, name, domains FROM clients ORDER BY id LIMIT 50")
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();
    let _ = tx.commit().await;
    let mut queued = 0usize;
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        if id <= 0 {
            continue;
        }
        let domains_raw: String = r.try_get("domains").unwrap_or_else(|_| "[]".into());
        let domains: Vec<String> = serde_json::from_str(&domains_raw).unwrap_or_default();
        let name: String = r.try_get("name").unwrap_or_default();
        let target = domains
            .iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or(name);
        if target.trim().is_empty() {
            continue;
        }
        let payload = json!({
            "engine": "cnapp_continuous",
            "target": target,
            "client_id": id,
            "trigger": "cnapp_scheduler",
        });
        match crate::async_jobs::enqueue(
            app_pool,
            tenant_id,
            "command_center_engine",
            payload,
            None,
        )
        .await
        {
            Ok(_) => queued += 1,
            Err(e) => tracing::warn!(
                target: "cnapp_scheduler",
                tenant_id,
                client_id = id,
                error = %e,
                "cnapp_continuous enqueue failed"
            ),
        }
    }
    queued
}

async fn tick(app_pool: &PgPool, auth_pool: &PgPool) {
    let tenants: Vec<i64> = sqlx::query_scalar("SELECT id FROM tenants WHERE active = true")
        .fetch_all(auth_pool)
        .await
        .unwrap_or_default();
    for tenant_id in tenants {
        let n = enqueue_tenant(app_pool, tenant_id).await;
        if n > 0 {
            tracing::info!(
                target: "cnapp_scheduler",
                tenant_id,
                jobs = n,
                "queued cnapp_continuous refresh"
            );
        }
    }
}

pub fn spawn_cnapp_scheduler(app_pool: Arc<PgPool>, auth_pool: Arc<PgPool>) {
    let cfg = crate::supervised::SupervisorConfig::from_env();
    let hb = crate::supervised::Heartbeat::new();
    tokio::spawn(async move {
        crate::supervised::supervise("cnapp_scheduler", cfg, Some(hb), move |hb| {
            let app_pool = app_pool.clone();
            let auth_pool = auth_pool.clone();
            async move {
                let mut ticker = tokio::time::interval(StdDuration::from_secs(poll_interval_secs()));
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    if let Some(ref h) = hb {
                        h.beat();
                    }
                    if !cron_enabled() {
                        continue;
                    }
                    tick(app_pool.as_ref(), auth_pool.as_ref()).await;
                }
            }
        })
        .await;
    });
}
