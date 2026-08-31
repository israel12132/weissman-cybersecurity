//! Closed-loop verification task queue.

use serde_json::json;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::types::{ExecutionStatus, VerifyProbeSpec};

pub async fn enqueue_verification(
    pool: &PgPool,
    tenant_id: i64,
    execution_id: Uuid,
    probe: &VerifyProbeSpec,
) -> Result<i64, String> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Err("tenant tx".into());
    };
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO soar_verification_tasks
           (tenant_id, execution_id, probe_type, target, status)
           VALUES ($1, $2, $3, $4, 'pending')
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(execution_id)
    .bind(&probe.probe_type)
    .bind(&probe.target)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    sqlx::query(
        r#"UPDATE soar_action_executions SET status = $3, updated_at = now()
           WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(execution_id)
    .bind(tenant_id)
    .bind(ExecutionStatus::Verifying.as_str())
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(id)
}

#[derive(Debug, Clone)]
pub struct PendingVerifyTask {
    pub id: i64,
    pub tenant_id: i64,
    pub execution_id: Uuid,
    pub probe_type: String,
    pub target: String,
    pub attempts: i32,
    pub max_attempts: i32,
    pub provider: String,
    pub payload: serde_json::Value,
    pub ports: Vec<u16>,
}

/// Claim due verification tasks for one tenant.
///
/// The `FOR UPDATE SKIP LOCKED` transaction only marks rows `running` and
/// **commits before returning**. Network probes (`verify_probe`, webhooks, TCP
/// scans) run in the caller *after* this function, so a slow probe cannot hold
/// row locks or stall the worker queue.
pub async fn claim_due_tasks(pool: &PgPool, tenant_id: i64, limit: i64) -> Vec<PendingVerifyTask> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Vec::new();
    };
    let rows = sqlx::query(
        r#"SELECT t.id, t.tenant_id, t.execution_id, t.probe_type, t.target,
                  t.attempts, t.max_attempts,
                  COALESCE(e.provider, 'unknown') AS provider,
                  e.execution_payload
           FROM soar_verification_tasks t
           JOIN soar_action_executions e ON e.id = t.execution_id AND e.tenant_id = t.tenant_id
           WHERE t.tenant_id = $2
             AND t.status IN ('pending', 'running')
             AND t.next_attempt_at <= now()
           ORDER BY t.next_attempt_at
           LIMIT $1
           FOR UPDATE SKIP LOCKED"#,
    )
    .bind(limit)
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let task_id: i64 = r.try_get("id").unwrap_or(0);
        let _ = sqlx::query(
            "UPDATE soar_verification_tasks SET status = 'running', attempts = attempts + 1 WHERE id = $1",
        )
        .bind(task_id)
        .execute(&mut *tx)
        .await;
        let payload: serde_json::Value = r.try_get("execution_payload").unwrap_or(json!({}));
        let ports: Vec<u16> = payload
            .get("ports")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|p| p.as_u64().map(|n| n as u16))
                    .collect()
            })
            .unwrap_or_else(|| super::adapters::default_verify_ports());
        out.push(PendingVerifyTask {
            id: task_id,
            tenant_id: r.try_get("tenant_id").unwrap_or(0),
            execution_id: r.try_get("execution_id").unwrap_or_else(|_| Uuid::nil()),
            probe_type: r.try_get("probe_type").unwrap_or_default(),
            target: r.try_get("target").unwrap_or_default(),
            attempts: r.try_get("attempts").unwrap_or(0),
            max_attempts: r.try_get("max_attempts").unwrap_or(8),
            provider: r.try_get("provider").unwrap_or_else(|_| "unknown".into()),
            payload,
            ports,
        });
    }
    let _ = tx.commit().await;
    out
}

pub async fn mark_verified(
    pool: &PgPool,
    task: &PendingVerifyTask,
    detail: &str,
) -> Result<(), String> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, task.tenant_id).await else {
        return Err("tenant tx".into());
    };
    sqlx::query(
        r#"UPDATE soar_verification_tasks
           SET status = 'verified', last_result = $2, verified_at = now()
           WHERE id = $1"#,
    )
    .bind(task.id)
    .bind(detail)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    sqlx::query(
        r#"UPDATE soar_action_executions
           SET status = $3, result_detail = $4, resolved_at = now(), updated_at = now()
           WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(task.execution_id)
    .bind(task.tenant_id)
    .bind(ExecutionStatus::Resolved.as_str())
    .bind(detail)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(())
}

pub async fn reschedule_or_fail(
    pool: &PgPool,
    task: &PendingVerifyTask,
    detail: &str,
) -> Result<(), String> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, task.tenant_id).await else {
        return Err("tenant tx".into());
    };
    if task.attempts >= task.max_attempts {
        sqlx::query(
            r#"UPDATE soar_verification_tasks SET status = 'failed', last_result = $2 WHERE id = $1"#,
        )
        .bind(task.id)
        .bind(detail)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        sqlx::query(
            r#"UPDATE soar_action_executions SET status = $3, result_detail = $4, updated_at = now()
               WHERE id = $1 AND tenant_id = $2"#,
        )
        .bind(task.execution_id)
        .bind(task.tenant_id)
        .bind(ExecutionStatus::Failed.as_str())
        .bind(detail)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    } else {
        let backoff_secs = (2_i64)
            .saturating_pow(task.attempts.saturating_sub(1) as u32)
            .min(300);
        sqlx::query(
            r#"UPDATE soar_verification_tasks
               SET status = 'pending', last_result = $2,
                   next_attempt_at = now() + ($3 || ' seconds')::interval
               WHERE id = $1"#,
        )
        .bind(task.id)
        .bind(detail)
        .bind(backoff_secs)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }
    let _ = tx.commit().await;
    Ok(())
}
