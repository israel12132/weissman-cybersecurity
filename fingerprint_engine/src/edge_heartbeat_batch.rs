//! Batched `edge_swarm_nodes` heartbeats: edge workers POST frequently; we coalesce writes every 30s
//! to protect the Postgres pool. Flushes run under per-tenant RLS transactions.

use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct PendingHeartbeat {
    pub tenant_id: i64,
    pub region_code: String,
    pub pop_label: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub wasm_revision: String,
    pub provider: String,
    pub active_jobs: i32,
}

#[derive(Clone)]
pub struct EdgeHeartbeatBatcher {
    tx: mpsc::UnboundedSender<PendingHeartbeat>,
}

impl EdgeHeartbeatBatcher {
    pub fn enqueue(&self, p: PendingHeartbeat) {
        let _ = self.tx.send(p);
    }
}

async fn upsert_heartbeat(pool: &sqlx::PgPool, p: &PendingHeartbeat) -> Result<(), sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, p.tenant_id).await?;
    let region = p.region_code.trim();
    let pop = p.pop_label.trim();
    if region.is_empty() || pop.is_empty() {
        let _ = tx.rollback().await;
        return Ok(());
    }
    let _ = sqlx::query(
        "DELETE FROM edge_swarm_nodes WHERE tenant_id = $1 AND region_code = $2 AND pop_label = $3",
    )
    .bind(p.tenant_id)
    .bind(region)
    .bind(pop)
    .execute(&mut *tx)
    .await;
    let meta = json!({});
    sqlx::query(
        r#"INSERT INTO edge_swarm_nodes (tenant_id, region_code, pop_label, latitude, longitude, wasm_revision, provider, last_heartbeat, active_jobs, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8, $9)"#,
    )
    .bind(p.tenant_id)
    .bind(region)
    .bind(pop)
    .bind(p.latitude)
    .bind(p.longitude)
    .bind(p.wasm_revision.trim())
    .bind(p.provider.trim())
    .bind(p.active_jobs)
    .bind(sqlx::types::Json(meta))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn flush_batch(
    pool: &sqlx::PgPool,
    batch: Vec<PendingHeartbeat>,
    telemetry: Option<&Arc<tokio::sync::broadcast::Sender<String>>>,
) {
    let mut merged: HashMap<(i64, String, String), PendingHeartbeat> = HashMap::new();
    for h in batch {
        let key = (
            h.tenant_id,
            h.region_code.trim().to_string(),
            h.pop_label.trim().to_string(),
        );
        merged.insert(key, h);
    }
    let tenants: std::collections::HashSet<i64> = merged.values().map(|p| p.tenant_id).collect();
    for (_, p) in merged {
        if let Err(e) = upsert_heartbeat(pool, &p).await {
            tracing::warn!(
                target: "edge_swarm",
                error = %e,
                tenant_id = p.tenant_id,
                "batched heartbeat upsert failed"
            );
        }
    }
    for tid in tenants {
        if let Err(e) =
            crate::observability::evaluate_regional_edge_blast_radius(pool, tid, telemetry).await
        {
            tracing::debug!(target: "edge_swarm", error = %e, tenant_id = tid, "blast radius check skipped");
        }
    }
}

pub fn spawn(
    pool: Arc<sqlx::PgPool>,
    telemetry: Option<Arc<tokio::sync::broadcast::Sender<String>>>,
) -> EdgeHeartbeatBatcher {
    let (tx, mut rx) = mpsc::unbounded_channel::<PendingHeartbeat>();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let mut batch = Vec::new();
            while let Ok(h) = rx.try_recv() {
                batch.push(h);
            }
            if batch.is_empty() {
                continue;
            }
            flush_batch(pool.as_ref(), batch, telemetry.as_ref()).await;
        }
    });
    EdgeHeartbeatBatcher { tx }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(region: &str, pop: &str) -> PendingHeartbeat {
        PendingHeartbeat {
            tenant_id: 1,
            region_code: region.to_string(),
            pop_label: pop.to_string(),
            latitude: Some(51.5),
            longitude: Some(-0.12),
            wasm_revision: "rev-1".to_string(),
            provider: "cloudflare".to_string(),
            active_jobs: 3,
        }
    }

    #[test]
    fn enqueue_forwards_message_to_channel() {
        let (tx, mut rx) = mpsc::unbounded_channel::<PendingHeartbeat>();
        let batcher = EdgeHeartbeatBatcher { tx };
        batcher.enqueue(sample("eu-west", "lhr"));
        let got = rx.try_recv().expect("message should be queued");
        assert_eq!(got.tenant_id, 1);
        assert_eq!(got.region_code, "eu-west");
        assert_eq!(got.pop_label, "lhr");
        assert_eq!(got.active_jobs, 3);
        assert_eq!(got.provider, "cloudflare");
    }

    #[test]
    fn enqueue_preserves_order_of_multiple_sends() {
        let (tx, mut rx) = mpsc::unbounded_channel::<PendingHeartbeat>();
        let batcher = EdgeHeartbeatBatcher { tx };
        batcher.enqueue(sample("us-east", "iad"));
        batcher.enqueue(sample("ap-south", "bom"));
        assert_eq!(rx.try_recv().unwrap().pop_label, "iad");
        assert_eq!(rx.try_recv().unwrap().pop_label, "bom");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn pending_heartbeat_clone_matches_source() {
        let p = sample("eu-central", "fra");
        let c = p.clone();
        assert_eq!(c.region_code, p.region_code);
        assert_eq!(c.pop_label, p.pop_label);
        assert_eq!(c.latitude, p.latitude);
        assert_eq!(c.longitude, p.longitude);
        assert_eq!(c.wasm_revision, p.wasm_revision);
    }
}
