//! Immutable forensic audit for every SOAR decision and execution payload.

use serde_json::{json, Value};
use sqlx::PgPool;

use super::types::{ExecuteActionCommand, ThreatEvidence};

pub async fn log_decision(
    pool: &PgPool,
    tenant_id: i64,
    action: &str,
    detail: &str,
    evidence: &ThreatEvidence,
    payload: &Value,
) {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return;
    };
    let body = json!({
        "action": action,
        "detail": detail,
        "evidence": evidence,
        "payload": payload,
    });
    let _ = crate::audit_log::insert_audit(
        &mut tx,
        tenant_id,
        None,
        "soar_engine",
        "soar_forensic",
        &body.to_string(),
        "0.0.0.0",
    )
    .await;
    let _ = tx.commit().await;
}

pub async fn log_execution(
    pool: &PgPool,
    cmd: &ExecuteActionCommand,
    status: &str,
    detail: &str,
    execution_id: Option<uuid::Uuid>,
) {
    let payload = json!({
        "execution_id": execution_id,
        "action_kind": cmd.action_kind,
        "target_id": cmd.target_id,
        "status": status,
        "detail": detail,
        "params": cmd.params,
        "evidence": cmd.evidence,
    });
    log_decision(
        pool,
        cmd.tenant_id,
        &format!("soar_execute_{}", cmd.action_kind),
        detail,
        &cmd.evidence,
        &payload,
    )
    .await;
}
