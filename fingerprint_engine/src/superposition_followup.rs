//! Auto-enqueue **Risk Superposition Collapse** when live prerequisites are satisfied.
//!
//! After any engine persists findings, we check whether the tenant has enough open
//! finding-clusters to fuse. If so, a `command_center_engine` job for
//! `risk_superposition_collapse` is queued (deduplicated). No LLM, no polling loops.

use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

const ENGINE_ID: &str = "risk_superposition_collapse";
const MIN_OPEN_CLUSTERS: i64 = 2;
const DEDUP_MINUTES: i64 = 5;

#[must_use]
pub fn auto_superposition_enabled() -> bool {
    match std::env::var("WEISSMAN_AUTO_SUPERPOSITION_COLLAPSE").as_deref() {
        Ok("0") | Ok("false") | Ok("no") => false,
        _ => true,
    }
}

fn skip_source_engine(engine: &str) -> bool {
    matches!(
        engine.trim(),
        ENGINE_ID | "pipeline" | "zero_day_radar" | "poe_synthesis"
    )
}

/// Fire-and-forget after `findings_persist` commits rows.
pub fn spawn_after_persist(
    pool: Arc<PgPool>,
    tenant_id: i64,
    client_id: i64,
    target: String,
    source_engine: String,
) {
    if !auto_superposition_enabled() || skip_source_engine(&source_engine) {
        return;
    }
    let t = target.trim().to_string();
    if t.is_empty() {
        return;
    }
    tokio::spawn(async move {
        match maybe_enqueue(&pool, tenant_id, client_id, &t, &source_engine, false).await {
            Ok(Some(id)) => {
                tracing::info!(
                    target: "superposition_followup",
                    %id,
                    tenant_id,
                    client_id,
                    source_engine,
                    "auto superposition collapse enqueued"
                );
            }
            Ok(None) => {}
            Err(e) => tracing::debug!(target: "superposition_followup", error = %e, "skip"),
        }
    });
}

/// Explicit synthesis pass (e.g. after `scan_all_engines` batch).
pub async fn enqueue_after_batch(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    target: &str,
    source_label: &str,
) -> Result<Option<Uuid>, String> {
    if !auto_superposition_enabled() {
        return Ok(None);
    }
    maybe_enqueue(pool, tenant_id, client_id, target, source_label, true).await
}

async fn maybe_enqueue(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    target: &str,
    source_engine: &str,
    force_batch: bool,
) -> Result<Option<Uuid>, String> {
    if target.trim().is_empty() {
        return Ok(None);
    }
    if !force_batch && skip_source_engine(source_engine) {
        return Ok(None);
    }

    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;

    let cluster_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint
             FROM weissman_finding_clusters
            WHERE client_id = $1 AND UPPER(status) = 'OPEN'"#,
    )
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("cluster count: {e}"))?;

    if cluster_count < MIN_OPEN_CLUSTERS {
        let _ = tx.commit().await;
        return Ok(None);
    }

    let inflight: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint
             FROM weissman_async_jobs
            WHERE tenant_id = $1
              AND kind = 'command_center_engine'
              AND payload->>'engine' = $2
              AND (payload->>'client_id')::bigint = $3
              AND status IN ('pending', 'running')
              AND created_at > now() - make_interval(mins => $4)"#,
    )
    .bind(tenant_id)
    .bind(ENGINE_ID)
    .bind(client_id)
    .bind(DEDUP_MINUTES as i32)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("dedup: {e}"))?;

    let _ = tx.commit().await;

    if inflight > 0 {
        return Ok(None);
    }

    let payload = json!({
        "engine": ENGINE_ID,
        "target": target.trim(),
        "client_id": client_id,
        "auto_triggered": true,
        "trigger_source_engine": source_engine,
        "fusion_mode": "hybrid",
        "include_belief_fusion": true,
        "include_toxic_combinations": true,
        "include_strips_collapse": true,
        "include_temporal_correlation": true,
        "include_attack_paths": true,
        "include_financial_ale": true,
    });

    let id = crate::async_jobs::enqueue(
        pool,
        tenant_id,
        "command_center_engine",
        payload,
        Some("auto-superposition-collapse".to_string()),
    )
    .await
    .map_err(|e| format!("enqueue: {e}"))?;

    Ok(Some(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_self_and_meta_engines() {
        assert!(skip_source_engine("risk_superposition_collapse"));
        assert!(skip_source_engine("pipeline"));
        assert!(!skip_source_engine("asm"));
    }
}
