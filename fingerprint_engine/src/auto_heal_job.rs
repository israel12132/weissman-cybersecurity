//! Durable auto-heal execution for `weissman-worker` (API only inserts `auto_heal_job_specs` and enqueues `auto_heal`).

use crate::auto_heal;
use crate::db;
use crate::verification_sandbox::{verify_patch_ephemeral_docker, StepSink};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::atomic::AtomicI32;
use std::sync::Arc;
use uuid::Uuid;

#[allow(clippy::too_many_arguments)]
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
    channel: &str,
    verdict: &str,
) {
    if let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await {
        let _ = sqlx::query(
            r#"INSERT INTO heal_requests (tenant_id, client_id, finding_id, vulnerability_id, branch_name, pr_url, pr_number, diff_summary, verification_status, verification_job_id, channel, verdict)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
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
        .bind(channel)
        .bind(verdict)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
    }
}

/// Persist the verified, deliverable artifact (unified diff, changed-file list, or virtual-patch
/// snippet) on the spec so non-repo channels and the UI can retrieve it. Never store secrets here.
async fn store_result_artifact(pool: &PgPool, tenant_id: i64, spec_id: Uuid, artifact: &Value) {
    if let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await {
        let _ = sqlx::query(
            r#"UPDATE auto_heal_job_specs SET result_artifact = $3::jsonb, updated_at = now()
               WHERE id = $1 AND tenant_id = $2"#,
        )
        .bind(spec_id)
        .bind(tenant_id)
        .bind(artifact.to_string())
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
    }
}

/// Build an honest PR title + body from the real verification result. It states the verdict,
/// the exploit before/after status, health, and the files changed — never over-claiming.
fn build_pr_text(
    finding_id: &str,
    vr: &crate::verification_sandbox::VerificationResult,
    diff_summary: &str,
) -> (String, String) {
    let title = format!(
        "[Weissman CNAPP] Auto-Heal (verdict: {}): {}",
        vr.verdict.as_str(),
        finding_id
    );
    let mut files_md = String::new();
    for (path, _content) in vr.changed_files.iter().take(40) {
        files_md.push_str(&format!("- `{}`\n", path));
    }
    if vr.changed_files.len() > 40 {
        files_md.push_str(&format!("- …and {} more\n", vr.changed_files.len() - 40));
    }
    let deletions_md = if vr.deleted_paths.is_empty() {
        String::new()
    } else {
        format!(
            "\n**⚠️ Deletions/binary changes not applied via API (apply manually):**\n{}\n",
            vr.deleted_paths
                .iter()
                .take(20)
                .map(|p| format!("- `{}`", p))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };
    let body = format!(
        "## Autonomous remediation — sandbox verified\n\n\
         **Finding:** `{finding}`\n\
         **Verdict:** `{verdict}`\n\
         **Exploit re-run:** baseline HTTP `{baseline}` → after-patch HTTP `{after}`\n\
         **App health after patch:** HTTP `{health}` ({health_ok})\n\n\
         The patch below was applied to a shallow clone in an ephemeral Docker container, the app \
         was restarted, and the original exploit was re-run. This PR contains the **actual applied \
         fix** (the changed source files), not an advisory diff.\n\n\
         **Changed files:**\n{files}{deletions}\n\
         _Diff summary:_\n```\n{summary}\n```\n\n\
         Please review and merge.",
        finding = finding_id,
        verdict = vr.verdict.as_str(),
        baseline = vr.baseline_status,
        after = vr.after_patch_status,
        health = vr.health_status,
        health_ok = if vr.health_after_ok { "healthy" } else { "unhealthy" },
        files = if files_md.is_empty() { "- (none)\n".to_string() } else { files_md },
        deletions = deletions_md,
        summary = diff_summary.chars().take(1500).collect::<String>(),
    );
    (title, body)
}

async fn finalize_spec(pool: &PgPool, tenant_id: i64, spec_id: Uuid, status: &str) {
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
                  patch_text, poc_curl, docker_socket, image, container_port,
                  COALESCE(channel, 'github_pr') AS channel, COALESCE(health_check_curl, '') AS health_check_curl
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
    let channel_id: String = row
        .try_get::<String, _>("channel")
        .unwrap_or_else(|_| "github_pr".into());
    let health_check_curl: String = row.try_get::<String, _>("health_check_curl").unwrap_or_default();
    let channel = crate::heal_channels::DeliveryChannel::from_id(&channel_id);

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

    use crate::heal_channels::DeliveryChannel;

    // 1) VERIFY FIRST. No branch is ever created unless the exploit is proven closed AND the app
    //    is still healthy (verdict == Fixed). This also captures the real applied files.
    let vr = verify_patch_ephemeral_docker(
        &docker_socket,
        &image,
        container_port as u16,
        &repo_slug,
        &base_branch,
        &git_token,
        &patch_text,
        &poc_curl,
        &health_check_curl,
        Some(step_sink),
    )
    .await;

    let verdict_str = vr.verdict.as_str();

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
            "",
            None,
            None,
            "",
            &format!("sandbox_failed: {}", msg),
            &jid_str,
            channel.id(),
            verdict_str,
        )
        .await;
        finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "failed").await;
        return Ok(json!({
            "ok": false,
            "error": msg,
            "verdict": verdict_str,
            "spec_id": spec_id,
        }));
    }

    // 2) DELIVER the verified fix via the requested channel.
    let commit_msg = format!(
        "Security remediation (verdict: {}) for finding {}",
        verdict_str, finding_id
    );

    match channel {
        DeliveryChannel::GithubPr | DeliveryChannel::GithubDirectCommit => {
            let commit = auto_heal::create_branch_and_commit_only(
                &git_token,
                &repo_slug,
                &base_branch,
                &finding_id,
                vr.changed_files.clone(),
                Some(&commit_msg),
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
                    &format!("commit_failed: {}", e),
                    &jid_str,
                    channel.id(),
                    verdict_str,
                )
                .await;
                finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "failed").await;
                return Ok(json!({
                    "ok": false,
                    "error": e,
                    "verdict": verdict_str,
                    "branch_name": commit.branch_name,
                    "spec_id": spec_id,
                }));
            }

            if channel == DeliveryChannel::GithubDirectCommit {
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
                    "verified_committed",
                    &jid_str,
                    channel.id(),
                    verdict_str,
                )
                .await;
                finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "completed").await;
                return Ok(json!({
                    "ok": true,
                    "channel": channel.id(),
                    "verdict": verdict_str,
                    "branch_name": commit.branch_name,
                    "diff_summary": commit.diff_summary,
                    "spec_id": spec_id,
                }));
            }

            let (title, body) = build_pr_text(&finding_id, &vr, &commit.diff_summary);
            match auto_heal::open_pull_request(
                &git_token,
                &repo_slug,
                &base_branch,
                &commit.branch_name,
                &title,
                &body,
            )
            .await
            {
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
                        channel.id(),
                        verdict_str,
                    )
                    .await;
                    finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "completed").await;
                    Ok(json!({
                        "ok": true,
                        "channel": channel.id(),
                        "verdict": verdict_str,
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
                        channel.id(),
                        verdict_str,
                    )
                    .await;
                    finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "failed").await;
                    Ok(json!({
                        "ok": false,
                        "error": e,
                        "verdict": verdict_str,
                        "spec_id": spec_id,
                        "branch_name": commit.branch_name,
                    }))
                }
            }
        }
        DeliveryChannel::DiffDownload => {
            // No repo mutation: expose the verified unified diff + changed-file list for download.
            let changed_paths: Vec<&str> =
                vr.changed_files.iter().map(|(p, _)| p.as_str()).collect();
            let artifact = json!({
                "kind": "diff_download",
                "verdict": verdict_str,
                "unified_diff": patch_text,
                "changed_files": changed_paths,
                "deleted_paths": vr.deleted_paths,
            });
            store_result_artifact(app_pool.as_ref(), tenant_id, spec_id, &artifact).await;
            let summary = format!("verified unified diff ready ({} files)", vr.changed_files.len());
            insert_heal_request_row(
                app_pool.as_ref(),
                tenant_id,
                client_id,
                &finding_id,
                vuln_id,
                "",
                None,
                None,
                &summary,
                "verified_diff_ready",
                &jid_str,
                channel.id(),
                verdict_str,
            )
            .await;
            finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "completed").await;
            Ok(json!({
                "ok": true,
                "channel": channel.id(),
                "verdict": verdict_str,
                "message": "verified diff ready; GET /api/heal-verify/:job_id/patch",
                "spec_id": spec_id,
            }))
        }
        DeliveryChannel::VirtualPatch => {
            // No repo mutation: render a compensating WAF/virtual-patch rule from the finding.
            let snippet = crate::heal_channels::render_virtual_patch(&finding_id, &finding_id, "");
            let artifact = json!({
                "kind": "virtual_patch",
                "verdict": verdict_str,
                "snippet": snippet,
            });
            store_result_artifact(app_pool.as_ref(), tenant_id, spec_id, &artifact).await;
            insert_heal_request_row(
                app_pool.as_ref(),
                tenant_id,
                client_id,
                &finding_id,
                vuln_id,
                "",
                None,
                None,
                "virtual patch (WAF) rendered",
                "verified_virtual_patch",
                &jid_str,
                channel.id(),
                verdict_str,
            )
            .await;
            finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "completed").await;
            Ok(json!({
                "ok": true,
                "channel": channel.id(),
                "verdict": verdict_str,
                "message": "virtual patch rendered; GET /api/heal-verify/:job_id/patch",
                "spec_id": spec_id,
            }))
        }
    }
}
