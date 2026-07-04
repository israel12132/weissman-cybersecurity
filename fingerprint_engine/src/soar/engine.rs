//! SOAR execution orchestrator — state machine, idempotency, adapter dispatch.

use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::time::Duration;
use uuid::Uuid;

use super::adapters::{dispatch, probe_from_outcome};
use super::audit;
use super::blast_radius::{evaluate, BlastRadiusInput};
use super::idempotency::{self, idempotency_key, mark_completed};
use super::integrations::{load_integrations, pick_provider};
use super::revert::persist_runbook;
use super::types::{ActionOutcome, ExecuteActionCommand, ExecutionStatus, ThreatEvidence};
use super::verification::enqueue_verification;

/// Destructive SOAR actions routed through the armored engine.
const ARMORED_KINDS: &[&str] = &[
    "isolate_host",
    "open_pr",
    "page_oncall",
    "slack_notify",
    "create_incident",
];

#[must_use]
pub fn is_armored_action(kind: &str) -> bool {
    ARMORED_KINDS.contains(&kind.trim().to_ascii_lowercase().as_str())
}

/// Build command from playbook action dispatch.
#[must_use]
pub fn build_command(
    action_kind: &str,
    tenant_id: i64,
    client_id: Option<i64>,
    playbook_id: Option<i64>,
    target_id: String,
    params: Value,
    evidence: ThreatEvidence,
    dry_run: bool,
) -> ExecuteActionCommand {
    ExecuteActionCommand {
        action_kind: action_kind.to_string(),
        tenant_id,
        client_id,
        playbook_id,
        target_id,
        params,
        evidence,
        dry_run,
    }
}

/// Main entry — idempotent, blast-radius gated, verification queued.
pub async fn execute_armored_action(pool: &PgPool, cmd: ExecuteActionCommand) -> ActionOutcome {
    let vuln_sig = cmd.evidence.vulnerability_signature();
    let idem = idempotency_key(&cmd.action_kind, &cmd.target_id, &vuln_sig);

    if let Some(existing) = find_existing_execution(pool, cmd.tenant_id, &idem).await {
        if existing.status == ExecutionStatus::Resolved.as_str()
            || existing.status == ExecutionStatus::DuplicateSkipped.as_str()
        {
            return ActionOutcome {
                status: "ok".into(),
                detail: format!(
                    "duplicate_skipped: prior execution {} ({})",
                    existing.id, existing.status
                ),
                execution_id: Some(existing.id),
            };
        }
    }

    let _lock = match idempotency::try_acquire_lock(&idem).await {
        Some(g) => g,
        None => {
            audit::log_execution(
                pool,
                &cmd,
                "duplicate_skipped",
                "redis lock held or done marker",
                None,
            )
            .await;
            return ActionOutcome {
                status: "ok".into(),
                detail: "duplicate_skipped: action already in-flight or completed".into(),
                execution_id: None,
            };
        }
    };

    let force = cmd
        .params
        .get("pre_approved")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || cmd
            .params
            .get("blast_radius_override")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
    let expected_vpc = cmd
        .params
        .get("expected_vpc_tag")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let blast = evaluate(
        pool,
        &BlastRadiusInput {
            tenant_id: cmd.tenant_id,
            client_id: cmd.client_id,
            target_id: cmd.target_id.clone(),
            force_approved: force,
            expected_vpc_tag: expected_vpc,
        },
    )
    .await;

    let execution_id = match insert_execution(pool, &cmd, &idem, &blast).await {
        Ok(id) => id,
        Err(e) => {
            return ActionOutcome {
                status: "failed".into(),
                detail: format!("persist execution: {e}"),
                execution_id: None,
            };
        }
    };

    if blast.blocked {
        let _ = update_status(
            pool,
            cmd.tenant_id,
            execution_id,
            ExecutionStatus::BlockedBlastRadius,
            &blast.block_reason,
        )
        .await;
        audit::log_execution(
            pool,
            &cmd,
            "blocked_blast_radius",
            &blast.block_reason,
            Some(execution_id),
        )
        .await;
        return ActionOutcome {
            status: "skipped".into(),
            detail: blast.block_reason,
            execution_id: Some(execution_id),
        };
    }

    let _ = update_status(
        pool,
        cmd.tenant_id,
        execution_id,
        ExecutionStatus::Executing,
        "dispatching adapter",
    )
    .await;

    let integrations = load_integrations(pool, cmd.tenant_id).await;
    let prefer: Vec<&str> = match cmd.action_kind.to_ascii_lowercase().as_str() {
        "isolate_host" => vec![
            "aws_ec2",
            "aws",
            "azure_vm",
            "azure",
            "crowdstrike_falcon",
            "crowdstrike",
        ],
        "open_pr" => vec!["github", "gitlab"],
        "page_oncall" => vec!["pagerduty", "opsgenie"],
        "slack_notify" => vec!["slack"],
        "create_incident" => vec!["servicenow"],
        _ => vec![],
    };
    let integration = match pick_provider(&integrations, &prefer) {
        Some(i) => i,
        None => {
            let msg = format!("no integration registered for {}", cmd.action_kind);
            let _ = update_status(
                pool,
                cmd.tenant_id,
                execution_id,
                ExecutionStatus::Failed,
                &msg,
            )
            .await;
            audit::log_execution(pool, &cmd, "failed", &msg, Some(execution_id)).await;
            return ActionOutcome {
                status: "skipped".into(),
                detail: msg,
                execution_id: Some(execution_id),
            };
        }
    };

    match dispatch(&cmd, pool, &integration).await {
        Ok(outcome) => {
            let _ = update_execution_result(
                pool,
                cmd.tenant_id,
                execution_id,
                &outcome,
                ExecutionStatus::Verifying,
            )
            .await;
            let steps = if outcome.revert_steps.is_empty() {
                vec![]
            } else {
                outcome.revert_steps.clone()
            };
            if !steps.is_empty() {
                let _ =
                    persist_runbook(pool, cmd.tenant_id, execution_id, &cmd.action_kind, &steps)
                        .await;
            }
            if let Some(probe) = probe_from_outcome(&outcome, &cmd) {
                let _ = enqueue_verification(pool, cmd.tenant_id, execution_id, &probe).await;
            } else {
                let _ = update_status(
                    pool,
                    cmd.tenant_id,
                    execution_id,
                    ExecutionStatus::Resolved,
                    &outcome.detail,
                )
                .await;
            }
            mark_completed(&idem, Duration::from_secs(86_400)).await;
            audit::log_execution(pool, &cmd, "verifying", &outcome.detail, Some(execution_id))
                .await;
            ActionOutcome {
                status: "ok".into(),
                detail: outcome.detail,
                execution_id: Some(execution_id),
            }
        }
        Err(e) => {
            let msg = e.to_string();
            let terminal = matches!(e, super::adapters::AdapterError::Skipped(_));
            let exec_status = if terminal {
                ExecutionStatus::DuplicateSkipped
            } else {
                ExecutionStatus::Failed
            };
            let status_str = if terminal { "skipped" } else { "failed" };
            let _ = update_status(pool, cmd.tenant_id, execution_id, exec_status, &msg).await;
            audit::log_execution(pool, &cmd, status_str, &msg, Some(execution_id)).await;
            ActionOutcome {
                status: status_str.into(),
                detail: msg,
                execution_id: Some(execution_id),
            }
        }
    }
}

struct ExistingExecution {
    id: Uuid,
    status: String,
}

async fn find_existing_execution(
    pool: &PgPool,
    tenant_id: i64,
    idem: &str,
) -> Option<ExistingExecution> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return None;
    };
    let row = sqlx::query(
        "SELECT id, status FROM soar_action_executions WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(tenant_id)
    .bind(idem)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    row.map(|r| ExistingExecution {
        id: r.try_get("id").unwrap_or_else(|_| Uuid::nil()),
        status: r.try_get("status").unwrap_or_default(),
    })
}

async fn insert_execution(
    pool: &PgPool,
    cmd: &ExecuteActionCommand,
    idem: &str,
    blast: &super::types::BlastRadiusReport,
) -> Result<Uuid, String> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, cmd.tenant_id).await else {
        return Err("tenant tx".into());
    };
    let id = Uuid::new_v4();
    let evidence = serde_json::to_value(&cmd.evidence).unwrap_or(json!({}));
    let res = sqlx::query(
        r#"INSERT INTO soar_action_executions
           (id, tenant_id, client_id, playbook_id, action_kind, idempotency_key,
            target_id, status, blast_radius, evidence, execution_payload)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
           ON CONFLICT (tenant_id, idempotency_key) DO NOTHING"#,
    )
    .bind(id)
    .bind(cmd.tenant_id)
    .bind(cmd.client_id)
    .bind(cmd.playbook_id)
    .bind(&cmd.action_kind)
    .bind(idem)
    .bind(&cmd.target_id)
    .bind(ExecutionStatus::Acquired.as_str())
    .bind(blast.to_json())
    .bind(evidence)
    .bind(&cmd.params)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    if res.rows_affected() == 0 {
        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM soar_action_executions WHERE tenant_id = $1 AND idempotency_key = $2",
        )
        .bind(cmd.tenant_id)
        .bind(idem)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        let _ = tx.commit().await;
        return existing.ok_or_else(|| "conflict without row".into());
    }
    let _ = tx.commit().await;
    Ok(id)
}

async fn update_status(
    pool: &PgPool,
    tenant_id: i64,
    id: Uuid,
    status: ExecutionStatus,
    detail: &str,
) -> Result<(), String> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Err("tenant tx".into());
    };
    let resolved = if status == ExecutionStatus::Resolved {
        Some(chrono::Utc::now())
    } else {
        None
    };
    sqlx::query(
        r#"UPDATE soar_action_executions
           SET status = $3, result_detail = $4, updated_at = now(),
               resolved_at = COALESCE($5, resolved_at)
           WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(status.as_str())
    .bind(detail)
    .bind(resolved)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(())
}

async fn update_execution_result(
    pool: &PgPool,
    tenant_id: i64,
    id: Uuid,
    outcome: &super::types::AdapterOutcome,
    status: ExecutionStatus,
) -> Result<(), String> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Err("tenant tx".into());
    };
    sqlx::query(
        r#"UPDATE soar_action_executions
           SET status = $3, provider = $4, result_detail = $5,
               external_ref = $6, execution_payload = execution_payload || $7::jsonb,
               updated_at = now()
           WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(status.as_str())
    .bind(&outcome.provider)
    .bind(&outcome.detail)
    .bind(&outcome.external_ref)
    .bind(outcome.payload.clone())
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(())
}

/// One-click rollback from persisted revert runbook.
pub async fn revert_execution(
    pool: &PgPool,
    tenant_id: i64,
    execution_id: Uuid,
) -> Result<String, String> {
    super::revert::execute_revert(pool, tenant_id, execution_id).await
}
