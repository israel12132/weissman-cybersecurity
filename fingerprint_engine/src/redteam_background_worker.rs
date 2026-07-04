//! Scheduled AI red-team: every `WEISSMAN_REDTEAM_INTERVAL_SECS` (default 86400),
//! enqueue `command_center_engine` jobs per client — worker is the sole executor.

use crate::db;
use sqlx::PgPool;
use sqlx::Row;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::Sender;

fn interval_secs() -> u64 {
    std::env::var("WEISSMAN_REDTEAM_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n >= 60)
        .unwrap_or(86_400)
}

/// Enable with `WEISSMAN_REDTEAM_CRON=1`.
pub fn spawn_cron_worker(
    app_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    _telemetry_tx: Arc<Sender<String>>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs()));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if std::env::var("WEISSMAN_REDTEAM_CRON")
                .map(|v| v != "1" && v != "true")
                .unwrap_or(true)
            {
                continue;
            }
            let tenants: Vec<i64> = sqlx::query_scalar::<_, i64>(
                "SELECT id FROM tenants WHERE active = true ORDER BY id",
            )
            .fetch_all(auth_pool.as_ref())
            .await
            .unwrap_or_default();
            for tid in tenants {
                if let Err(e) = dispatch_redteam_jobs(&app_pool, tid).await {
                    eprintln!("[Weissman][RedteamCron] tenant {}: {}", tid, e);
                }
            }
        }
    });
}

async fn dispatch_redteam_jobs(app_pool: &PgPool, tenant_id: i64) -> Result<(), String> {
    let mut tx = db::begin_tenant_tx(app_pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rows = sqlx::query(
        r#"SELECT DISTINCT ON (client_id) client_id, label
            FROM asm_graph_nodes
            WHERE label LIKE 'http://%' OR label LIKE 'https://%'
            ORDER BY client_id, id DESC"#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;

    for r in rows {
        let client_id: i64 = r.try_get("client_id").unwrap_or(0);
        let target: String = r.try_get("label").unwrap_or_default();
        if client_id == 0 || target.is_empty() {
            continue;
        }
        let payload = serde_json::json!({
            "engine": "ai_adversarial_redteam",
            "target": target,
            "client_id": client_id,
            "trigger": "redteam_cron",
        });
        crate::async_jobs::enqueue(app_pool, tenant_id, "command_center_engine", payload, None)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
