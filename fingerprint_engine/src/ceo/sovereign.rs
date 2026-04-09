//! CEO APIs for `sovereign_learning_buffer` + manual `sovereign_learning_feedback` enqueue.

use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct SovereignBufferRowOut {
    pub id: i64,
    pub target_fingerprint: String,
    pub failure_context: Value,
    pub critic_waf_analysis: Option<Value>,
    pub hacker_polymorphic_payload: Option<Value>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

pub async fn list_sovereign_buffer(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> Result<Vec<SovereignBufferRowOut>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, target_fingerprint, failure_context, critic_waf_analysis,
                  hacker_polymorphic_payload, status, created_at, updated_at
           FROM sovereign_learning_buffer
           ORDER BY id DESC
           LIMIT $1"#,
    )
    .bind(limit.min(500).max(1))
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let ca: chrono::DateTime<chrono::Utc> = r.try_get("created_at")?;
        let ua: chrono::DateTime<chrono::Utc> = r.try_get("updated_at")?;
        out.push(SovereignBufferRowOut {
            id: r.try_get("id")?,
            target_fingerprint: r.try_get("target_fingerprint")?,
            failure_context: r.try_get("failure_context")?,
            critic_waf_analysis: r.try_get("critic_waf_analysis").ok(),
            hacker_polymorphic_payload: r.try_get("hacker_polymorphic_payload").ok(),
            status: r.try_get("status")?,
            created_at: ca.to_rfc3339(),
            updated_at: ua.to_rfc3339(),
        });
    }
    Ok(out)
}

/// Enqueue `sovereign_learning_feedback` from an existing buffer row (CEO “Shadow Preflight”).
pub async fn enqueue_sovereign_from_buffer_row(
    pool: &PgPool,
    tenant_id: i64,
    buffer_id: i64,
    trace: Option<&str>,
) -> Result<Uuid, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let row = sqlx::query(
        r#"SELECT target_fingerprint, failure_context
           FROM sovereign_learning_buffer
           WHERE id = $1"#,
    )
    .bind(buffer_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let Some(r) = row else {
        return Err("buffer row not found".into());
    };
    let fp: String = r.try_get("target_fingerprint").map_err(|e| e.to_string())?;
    let ctx: Value = r.try_get("failure_context").map_err(|e| e.to_string())?;
    let _ = tx.commit().await.map_err(|e| e.to_string())?;
    let payload = json!({
        "target_seed": fp.trim(),
        "failure_context": ctx,
    });
    crate::async_jobs::enqueue(
        pool,
        tenant_id,
        "sovereign_learning_feedback",
        payload,
        trace.map(|s| s.to_string()),
    )
    .await
    .map_err(|e| e.to_string())
}
