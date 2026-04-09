//! Scheduled AI red-team: every `WEISSMAN_REDTEAM_INTERVAL_SECS` (default 86400), run
//! `ai_redteam_engine` against the latest HTTP(S) ASM node per client and persist findings.

use crate::ai_redteam_engine::{self, AiRedteamConfig};
use crate::db;
use crate::orchestrator::{
    broadcast_finding_created, finding_description, finding_title_and_severity, infer_poc_exploit,
};
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

async fn cfg_string_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    key: &str,
) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = $2",
    )
    .bind(tenant_id)
    .bind(key)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten()
}

/// Enable with `WEISSMAN_REDTEAM_CRON=1`.
pub fn spawn_cron_worker(
    app_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    telemetry_tx: Arc<Sender<String>>,
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
                if let Err(e) = run_cycle_for_tenant(&app_pool, tid, &telemetry_tx).await {
                    eprintln!("[Weissman][RedteamCron] tenant {}: {}", tid, e);
                }
            }
        }
    });
}

async fn run_cycle_for_tenant(
    app_pool: &PgPool,
    tenant_id: i64,
    telemetry_tx: &Arc<Sender<String>>,
) -> Result<(), String> {
    let mut tx = db::begin_tenant_tx(app_pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let llm_base_url = cfg_string_tx(&mut tx, tenant_id, "llm_base_url")
        .await
        .unwrap_or_else(|| "http://127.0.0.1:8000/v1".to_string());
    let temp: f64 = cfg_string_tx(&mut tx, tenant_id, "llm_temperature")
        .await
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.3);
    let llm_model = cfg_string_tx(&mut tx, tenant_id, "llm_model")
        .await
        .unwrap_or_default();
    let ai_redteam_endpoint = cfg_string_tx(&mut tx, tenant_id, "ai_redteam_endpoint")
        .await
        .unwrap_or_default();
    let adversarial_strategy = cfg_string_tx(&mut tx, tenant_id, "adversarial_strategy")
        .await
        .unwrap_or_else(|| "data_leak".to_string());
    let cfg = AiRedteamConfig {
        llm_base_url,
        llm_temperature: temp,
        llm_model,
        ai_redteam_endpoint,
        adversarial_strategy,
    };
    let rows = sqlx::query(
        r#"SELECT DISTINCT ON (client_id) client_id, label
            FROM asm_graph_nodes
            WHERE label LIKE 'http://%' OR label LIKE 'https://%'
            ORDER BY client_id, id DESC"#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    if rows.is_empty() {
        let _ = tx.commit().await;
        return Ok(());
    }
    let run_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO report_runs (tenant_id, region, findings_json, summary)
           VALUES ($1, 'cron_ai_redteam', '[]', '{}') RETURNING id"#,
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await.map_err(|e| e.to_string())?;

    for r in rows {
        let client_id: i64 = r.try_get("client_id").unwrap_or(0);
        let target: String = r.try_get("label").unwrap_or_default();
        if client_id == 0 || target.is_empty() {
            continue;
        }
        let result =
            ai_redteam_engine::run_ai_redteam_attack(&target, None, &cfg, None, Some(tenant_id))
                .await;
        if result.findings.is_empty() {
            continue;
        }
        let mut tx2 = db::begin_tenant_tx(app_pool, tenant_id)
            .await
            .map_err(|e| e.to_string())?;
        for (i, f) in result.findings.iter().enumerate() {
            if let Some(obj) = f.as_object() {
                let (title, severity) = finding_title_and_severity(obj);
                let desc = finding_description(obj);
                let poc = infer_poc_exploit(obj, &target);
                let fid = format!("cron-redteam-{}-{}-{}", run_id, client_id, i);
                if sqlx::query(
                    r#"INSERT INTO vulnerabilities (run_id, tenant_id, client_id, finding_id, title, severity, source, description, status, poc_exploit, discovered_at)
                       VALUES ($1, $2, $3, $4, $5, $6, 'ai_adversarial_redteam', $7, 'OPEN', $8, now())"#,
                )
                .bind(run_id)
                .bind(tenant_id)
                .bind(client_id)
                .bind(&fid)
                .bind(&title)
                .bind(&severity)
                .bind(&desc)
                .bind(&poc)
                .execute(&mut *tx2)
                .await
                .is_ok()
                {
                    broadcast_finding_created(
                        Some(telemetry_tx),
                        &client_id.to_string(),
                        &fid,
                        &title,
                        &severity,
                        &desc,
                        &poc,
                        None,
                    );
                }
            }
        }
        let _ = tx2.commit().await.map_err(|e| e.to_string())?;
    }
    Ok(())
}
