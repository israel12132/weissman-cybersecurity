//! Persist last discovery-phase sizes for CEO God Mode (per-tenant, RLS-safe).

use serde_json::json;
use sqlx::PgPool;

const KEY: &str = "orchestrator_discovery_snapshot";

/// Called after ASM-path discovery merges paths (live counts for dashboard).
pub async fn publish(
    pool: PgPool,
    tenant_id: i64,
    client_id: i64,
    client_name: &str,
    primary_target: &str,
    target_list_len: usize,
    discovered_paths_len: usize,
) {
    let mut tx = match crate::db::begin_tenant_tx(&pool, tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(target: "orchestrator", error = %e, "discovery_ui_snapshot: begin_tenant_tx failed");
            return;
        }
    };
    let v = json!({
        "client_id": client_id,
        "client_name": client_name,
        "primary_target": primary_target,
        "target_list_count": target_list_len,
        "discovered_paths_count": discovered_paths_len,
        "updated_at": chrono::Utc::now().to_rfc3339(),
    });
    let s = v.to_string();
    let res = sqlx::query(
        r#"INSERT INTO system_configs (tenant_id, key, value, description)
           VALUES ($1, $2, $3, 'Last ASM/discovery phase stats for God Mode dashboard')
           ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value"#,
    )
    .bind(tenant_id)
    .bind(KEY)
    .bind(&s)
    .execute(&mut *tx)
    .await;
    if let Err(e) = res {
        tracing::warn!(target: "orchestrator", error = %e, "discovery_ui_snapshot: upsert failed");
        let _ = tx.rollback().await;
        return;
    }
    let _ = tx.commit().await;
}
