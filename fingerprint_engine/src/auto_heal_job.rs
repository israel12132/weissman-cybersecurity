//! Durable auto-heal execution for `weissman-worker` (API only inserts `auto_heal_job_specs` and enqueues `auto_heal`).

use crate::auto_heal;
use crate::db;
use crate::verification_sandbox::{verify_patch_ephemeral_docker, StepSink};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::atomic::AtomicI32;
use std::sync::Arc;
use uuid::Uuid;

async fn insert_heal_request_row(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    finding_id: &str,
    vuln_id: i64,
    branch_name: &str,
    pr_url: Option<&str>,
    pr_number: Option<i64>,
    diff_summary: &str,
    verification_status: &str,
    verification_job_id: &str,
) {
    if let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await {
        let _ = sqlx::query(
            r#"INSERT INTO heal_requests (tenant_id, client_id, finding_id, vulnerability_id, branch_name, pr_url, pr_number, diff_summary, verification_status, verification_job_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(finding_id)
        .bind(vuln_id)
        .bind(branch_name)
        .bind(pr_url)
        .bind(pr_number.map(|n| n as i32))
        .bind(diff_summary)
        .bind(verification_status)
        .bind(verification_job_id)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
    }
}

async fn finalize_spec(
    pool: &PgPool,
    tenant_id: i64,
    spec_id: Uuid,
    status: &str,
) {
    if let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await {
        let res = sqlx::query(
            r#"UPDATE auto_heal_job_specs SET status = $3, git_token = '', updated_at = now()
               WHERE id = $1 AND tenant_id = $2"#,
        )
        .bind(spec_id)
        .bind(tenant_id)
        .bind(status)
        .execute(&mut *tx)
        .await;
        if let Err(e) = res {
            tracing::error!(target: "auto_heal_job", error = %e, "finalize_spec update failed");
        }
        let _ = tx.commit().await;
    }
}

pub async fn run_auto_heal_job(
    app_pool: Arc<PgPool>,
    tenant_id: i64,
    spec_id: Uuid,
) -> Result<Value, String> {
    let jid_str = spec_id.to_string();

    let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tenant_id)
        .await
        .map_err(|e| e.to_string())?;

    let row = sqlx::query(
        r#"SELECT status, git_token, client_id, vuln_id, finding_id, repo_slug, base_branch,
                  patch_text, poc_curl, docker_socket, image, container_port
           FROM auto_heal_job_specs WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(spec_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let Some(row) = row else {
        let _ = tx.rollback().await;
        return Err("auto_heal spec not found".into());
    };

    let status: String = row.try_get("status").map_err(|e| e.to_string())?;
    let git_token: String = row.try_get("git_token").unwrap_or_default();

    if status == "completed" {
        let _ = tx.commit().await;
        return Ok(json!({
            "ok": true,
            "message": "auto_heal already completed",
            "spec_id": spec_id,
        }));
    }
    if status == "failed" && git_token.trim().is_empty() {
        let _ = tx.commit().await;
        return Ok(json!({
            "ok": true,
            "message": "auto_heal already failed",
            "spec_id": spec_id,
        }));
    }
    if git_token.trim().is_empty() {
        let _ = tx.rollback().await;
        return Err("auto_heal spec has no git credentials".into());
    }

    let client_id: i64 = row.try_get("client_id").map_err(|e| e.to_string())?;
    let vuln_id: i64 = row.try_get("vuln_id").map_err(|e| e.to_string())?;
    let finding_id: String = row.try_get("finding_id").map_err(|e| e.to_string())?;
    let repo_slug: String = row.try_get("repo_slug").map_err(|e| e.to_string())?;
    let base_branch: String = row.try_get("base_branch").map_err(|e| e.to_string())?;
    let patch_text: String = row.try_get("patch_text").map_err(|e| e.to_string())?;
    let poc_curl: String = row.try_get("poc_curl").map_err(|e| e.to_string())?;
    let docker_socket: String = row
        .try_get::<String, _>("docker_socket")
        .unwrap_or_else(|_| "/var/run/docker.sock".into());
    let image: String = row
        .try_get::<String, _>("image")
        .unwrap_or_else(|_| "node:20-bookworm".into());
    let container_port: i32 = row.try_get("container_port").unwrap_or(3000);

    sqlx::query("DELETE FROM heal_verification_steps WHERE tenant_id = $1 AND job_id = $2")
        .bind(tenant_id)
        .bind(spec_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    sqlx::query(
        "UPDATE auto_heal_job_specs SET status = 'running', updated_at = now() WHERE id = $1 AND tenant_id = $2",
    )
    .bind(spec_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let _ = tx.commit().await.map_err(|e| e.to_string())?;

    let step_sink = StepSink::Postgres {
        pool: (*app_pool).clone(),
        tenant_id,
        job_id: spec_id,
        seq: Arc::new(AtomicI32::new(0)),
    };

    let commit = auto_heal::create_branch_and_commit_only(
        &git_token,
        &repo_slug,
        &base_branch,
        &finding_id,
        vec![("PATCH.txt".to_string(), patch_text.clone())],
        None,
    )
    .await;

    if let Some(e) = &commit.error {
        insert_heal_request_row(
            app_pool.as_ref(),
            tenant_id,
            client_id,
            &finding_id,
            vuln_id,
            &commit.branch_name,
            None,
            None,
            &commit.diff_summary,
            e,
            &jid_str,
        )
        .await;
        finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "failed").await;
        return Ok(json!({
            "ok": false,
            "error": e,
            "branch_name": commit.branch_name,
            "spec_id": spec_id,
        }));
    }

    let vr = verify_patch_ephemeral_docker(
        &docker_socket,
        &image,
        container_port as u16,
        &repo_slug,
        &base_branch,
        &git_token,
        &patch_text,
        &poc_curl,
        Some(step_sink),
    )
    .await;

    if !vr.verified {
        let msg = vr
            .error
            .clone()
            .unwrap_or_else(|| "verification failed".to_string());
        insert_heal_request_row(
            app_pool.as_ref(),
            tenant_id,
            client_id,
            &finding_id,
            vuln_id,
            &commit.branch_name,
            None,
            None,
            &commit.diff_summary,
            &format!("sandbox_failed: {}", msg),
            &jid_str,
        )
        .await;
        finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "failed").await;
        return Ok(json!({
            "ok": false,
            "error": msg,
            "spec_id": spec_id,
            "branch_name": commit.branch_name,
        }));
    }

    let pr_result = auto_heal::open_pull_request(
        &git_token,
        &repo_slug,
        &base_branch,
        &commit.branch_name,
        &finding_id,
    )
    .await;

    match pr_result {
        Ok((pr_url, pr_number)) => {
            insert_heal_request_row(
                app_pool.as_ref(),
                tenant_id,
                client_id,
                &finding_id,
                vuln_id,
                &commit.branch_name,
                pr_url.as_deref(),
                pr_number,
                &commit.diff_summary,
                "verified_pr_opened",
                &jid_str,
            )
            .await;
            finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "completed").await;
            Ok(json!({
                "ok": true,
                "branch_name": commit.branch_name,
                "pr_url": pr_url,
                "pr_number": pr_number,
                "diff_summary": commit.diff_summary,
                "spec_id": spec_id,
            }))
        }
        Err(e) => {
            insert_heal_request_row(
                app_pool.as_ref(),
                tenant_id,
                client_id,
                &finding_id,
                vuln_id,
                &commit.branch_name,
                None,
                None,
                &commit.diff_summary,
                &format!("pr_failed: {}", e),
                &jid_str,
            )
            .await;
            finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "failed").await;
            Ok(json!({
                "ok": false,
                "error": e.to_string(),
                "spec_id": spec_id,
                "branch_name": commit.branch_name,
            }))
        }
    }
}
