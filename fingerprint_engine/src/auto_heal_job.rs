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
    attempts: i32,
    receipt: Option<&crate::heal_attestation::HealReceipt>,
) {
    if let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await {
        let _ = sqlx::query(
            r#"INSERT INTO heal_requests (tenant_id, client_id, finding_id, vulnerability_id, branch_name, pr_url, pr_number, diff_summary, verification_status, verification_job_id, channel, verdict, attempts, verification_receipt, verification_digest)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"#,
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
        .bind(attempts)
        .bind(receipt.map(|r| r.receipt.as_str()))
        .bind(receipt.map(|r| r.digest.as_str()))
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
    attempts: i32,
    receipt: Option<&crate::heal_attestation::HealReceipt>,
) -> (String, String) {
    let title = format!(
        "[Weissman CNAPP] Auto-Heal (verdict: {}): {}",
        vr.verdict.as_str(),
        finding_id
    );
    let attempts_md = if attempts > 1 {
        format!(
            "**Self-repair:** reached a proven fix after {attempts} autonomous attempt(s).\n"
        )
    } else {
        String::new()
    };
    let receipt_md = match receipt {
        Some(r) => format!(
            "**🔏 Verified receipt:** `{}…` (HMAC-SHA256; verify at `GET /api/heal-verify/&lt;job&gt;/attestation`)\n",
            r.receipt.chars().take(16).collect::<String>()
        ),
        None => String::new(),
    };
    let tests_md = if vr.tests_ran {
        format!(
            "**Regression tests:** {} in-container.\n",
            if vr.tests_passed { "passed ✅" } else { "FAILED ❌" }
        )
    } else {
        String::new()
    };
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
         **App health after patch:** HTTP `{health}` ({health_ok})\n\
         {tests_md}{attempts_md}{receipt_md}\n\
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
        tests_md = tests_md,
        attempts_md = attempts_md,
        receipt_md = receipt_md,
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

/// Human-readable failure the self-repair loop feeds back to the LLM, derived from the verdict.
fn failure_reason(vr: &crate::verification_sandbox::VerificationResult) -> String {
    use crate::verification_sandbox::HealVerdict;
    let base = match vr.verdict {
        HealVerdict::StillVulnerable => format!(
            "The exploit STILL SUCCEEDS after the patch (HTTP {}). The vulnerability is not fixed.",
            vr.after_patch_status
        ),
        HealVerdict::BrokeApp => format!(
            "The patch BROKE the application (exploit HTTP {}, health HTTP {}). A valid fix must keep the app serving normal requests.",
            vr.after_patch_status, vr.health_status
        ),
        HealVerdict::Inconclusive => {
            "The patch could not be verified — it likely did not apply cleanly or produced no file changes.".to_string()
        }
        HealVerdict::Fixed => "fixed".to_string(),
    };
    match &vr.error {
        Some(e) if !e.is_empty() => format!("{base} Sandbox detail: {e}"),
        _ => base,
    }
}

/// Idempotency: find a verified heal PR/MR already opened for this finding within the dedup
/// window (`WEISSMAN_HEAL_DEDUP_HOURS`, default 24), so we never open a duplicate. Returns
/// `(pr_url, pr_number, branch_name)`.
async fn recent_open_pr(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    finding_id: &str,
) -> Option<(String, Option<i64>, String)> {
    let hours: i32 = std::env::var("WEISSMAN_HEAL_DEDUP_HOURS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n: &i32| *n >= 0 && *n <= 720)
        .unwrap_or(24);
    if hours == 0 {
        return None; // dedup disabled
    }
    let mut tx = db::begin_tenant_tx(pool, tenant_id).await.ok()?;
    let row = sqlx::query(
        r#"SELECT pr_url, pr_number, COALESCE(branch_name,'') AS branch_name
           FROM heal_requests
           WHERE client_id = $1 AND finding_id = $2
             AND verification_status IN ('verified_pr_opened', 'verified_mr_opened')
             AND pr_url IS NOT NULL AND pr_url <> ''
             AND created_at > now() - ($3::int * interval '1 hour')
           ORDER BY id DESC LIMIT 1"#,
    )
    .bind(client_id)
    .bind(finding_id)
    .bind(hours)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    let r = row?;
    let url: String = r.try_get::<Option<String>, _>("pr_url").ok().flatten()?;
    let num: Option<i64> = r
        .try_get::<Option<i32>, _>("pr_number")
        .ok()
        .flatten()
        .map(|n| n as i64);
    let branch: String = r.try_get("branch_name").unwrap_or_default();
    Some((url, num, branch))
}

/// Load a finding's title/description/severity for patch regeneration (empty tuple if absent).
async fn load_finding_context(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    finding_id: &str,
) -> (String, String, String) {
    if let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await {
        let row = sqlx::query(
            "SELECT title, COALESCE(description,'') AS description, severity FROM vulnerabilities WHERE client_id = $1 AND finding_id = $2 LIMIT 1",
        )
        .bind(client_id)
        .bind(finding_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
        let _ = tx.commit().await;
        if let Some(r) = row {
            return (
                r.try_get("title").unwrap_or_default(),
                r.try_get("description").unwrap_or_default(),
                r.try_get("severity").unwrap_or_default(),
            );
        }
    }
    (String::new(), String::new(), String::new())
}

/// Emit metrics (verdict/channel counter + duration histogram) and fire tenant completion
/// notifications for a terminal heal outcome. Best-effort — never affects the job result.
#[allow(clippy::too_many_arguments)]
async fn report_heal_outcome(
    pool: &PgPool,
    tenant_id: i64,
    finding_id: &str,
    verdict: &str,
    channel: &str,
    attempts: i32,
    pr_url: Option<&str>,
    ok: bool,
    started: std::time::Instant,
) {
    metrics::counter!(
        "weissman_heal_total",
        "verdict" => verdict.to_string(),
        "channel" => channel.to_string(),
        "ok" => ok.to_string(),
    )
    .increment(1);
    metrics::histogram!("weissman_heal_duration_seconds", "channel" => channel.to_string())
        .record(started.elapsed().as_secs_f64());
    crate::alert_delivery::notify_heal_completed(
        pool, tenant_id, finding_id, verdict, channel, attempts, pr_url, ok,
    )
    .await;
}

pub async fn run_auto_heal_job(
    app_pool: Arc<PgPool>,
    tenant_id: i64,
    spec_id: Uuid,
) -> Result<Value, String> {
    let jid_str = spec_id.to_string();
    let heal_started = std::time::Instant::now();

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
    use crate::verification_sandbox::record_step;

    // 1) VERIFY with an AUTONOMOUS SELF-REPAIR loop. If the fix doesn't reach `Fixed`, feed the
    //    failure back to the LLM, regenerate a corrected diff, re-validate, and re-verify — up to
    //    N attempts. A branch is only ever created once a patch is proven Fixed.
    let max_attempts: u32 = std::env::var("WEISSMAN_HEAL_MAX_ATTEMPTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n >= 1 && *n <= 10)
        .unwrap_or(3);

    // Provider host the sandbox clones from (GitLab uses oauth2 token auth, GitHub x-access-token).
    let git_host = if channel == DeliveryChannel::GitlabMr {
        std::env::var("WEISSMAN_GITLAB_HOST").unwrap_or_else(|_| "gitlab.com".into())
    } else {
        "github.com".to_string()
    };

    let mut patch_text = patch_text;
    let mut attempt: u32 = 1;
    let mut vr = verify_patch_ephemeral_docker(
        &docker_socket,
        &image,
        container_port as u16,
        &repo_slug,
        &base_branch,
        &git_token,
        &git_host,
        &patch_text,
        &poc_curl,
        &health_check_curl,
        Some(step_sink.clone()),
    )
    .await;

    // Finding context for regeneration, loaded once on first failure (empty if the row is gone).
    let mut finding_ctx: Option<(String, String, String)> = None;

    while !vr.verified && attempt < max_attempts {
        let reason = failure_reason(&vr);
        record_step(
            &step_sink,
            &format!("self_repair_attempt_{}", attempt),
            Some(format!(
                "verdict={} — regenerating a corrected patch. {}",
                vr.verdict.as_str(),
                reason
            )),
        )
        .await;

        if finding_ctx.is_none() {
            finding_ctx = Some(
                load_finding_context(app_pool.as_ref(), tenant_id, client_id, &finding_id).await,
            );
        }
        let cfg = match crate::council::CouncilConfig::load(app_pool.as_ref(), tenant_id).await {
            Ok(c) => c,
            Err(e) => {
                record_step(&step_sink, "self_repair_aborted", Some(format!("llm config: {e}"))).await;
                break;
            }
        };
        let (t, d, s) = finding_ctx.clone().unwrap_or_default();
        let changed_paths: Vec<String> = vr.changed_files.iter().map(|(p, _)| p.clone()).collect();
        match crate::remediation_patch::regenerate_patch(
            &cfg, tenant_id, attempt, &t, &d, &s, &poc_curl, &patch_text, &reason, &changed_paths,
        )
        .await
        {
            Ok(new_patch) => {
                if let Err(e) = crate::security_hardening::validate_remediation_patch(&new_patch) {
                    record_step(
                        &step_sink,
                        "self_repair_rejected",
                        Some(format!("regenerated patch rejected: {e}")),
                    )
                    .await;
                    break;
                }
                patch_text = new_patch;
                attempt += 1;
                vr = verify_patch_ephemeral_docker(
                    &docker_socket,
                    &image,
                    container_port as u16,
                    &repo_slug,
                    &base_branch,
                    &git_token,
                    &git_host,
                    &patch_text,
                    &poc_curl,
                    &health_check_curl,
                    Some(step_sink.clone()),
                )
                .await;
            }
            Err(e) => {
                record_step(&step_sink, "self_repair_failed", Some(e)).await;
                break;
            }
        }
    }

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
            &format!("sandbox_failed after {} attempt(s): {}", attempt, msg),
            &jid_str,
            channel.id(),
            verdict_str,
            attempt as i32,
            None,
        )
        .await;
        report_heal_outcome(
            app_pool.as_ref(),
            tenant_id,
            &finding_id,
            verdict_str,
            channel.id(),
            attempt as i32,
            None,
            false,
            heal_started,
        )
        .await;
        finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "failed").await;
        return Ok(json!({
            "ok": false,
            "error": msg,
            "verdict": verdict_str,
            "attempts": attempt,
            "spec_id": spec_id,
        }));
    }

    // Secret-safety gate: never commit or hand back a verified fix that itself embeds a secret.
    {
        let mut leaked: Vec<String> = Vec::new();
        for (path, content) in &vr.changed_files {
            let hits = crate::engine_probes::detect_secrets(content);
            if !hits.is_empty() {
                leaked.push(format!("{} ({})", path, hits.join(",")));
            }
        }
        if !leaked.is_empty() {
            let msg = format!("blocked: verified patch embeds secret(s): {}", leaked.join("; "));
            record_step(&step_sink, "secret_gate_blocked", Some(msg.clone())).await;
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
                &msg,
                &jid_str,
                channel.id(),
                verdict_str,
                attempt as i32,
                None,
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
    }

    // Persist the winning patch so the DiffDownload artifact and receipt reflect what actually passed.
    if attempt > 1 {
        if let Ok(mut tx) = db::begin_tenant_tx(app_pool.as_ref(), tenant_id).await {
            let _ = sqlx::query(
                "UPDATE auto_heal_job_specs SET patch_text = $3, updated_at = now() WHERE id = $1 AND tenant_id = $2",
            )
            .bind(spec_id)
            .bind(tenant_id)
            .bind(&patch_text)
            .execute(&mut *tx)
            .await;
            let _ = tx.commit().await;
        }
    }

    // Sign a tamper-evident heal receipt over the verified proof (None in dev / no attestation key).
    let heal_ts = chrono::Utc::now().timestamp();
    let receipt = crate::heal_attestation::sign_from_result(&finding_id, &poc_curl, &vr, heal_ts);
    if receipt.is_some() {
        record_step(
            &step_sink,
            "heal_attested",
            Some("signed tamper-evident verification receipt".into()),
        )
        .await;
    }
    let attempts_i32 = attempt as i32;

    // Idempotency: for repo channels, reuse an existing recent heal PR/MR instead of opening a duplicate.
    if channel.touches_repo() {
        if let Some((existing_url, existing_num, existing_branch)) =
            recent_open_pr(app_pool.as_ref(), tenant_id, client_id, &finding_id).await
        {
            record_step(
                &step_sink,
                "dedup_existing_pr",
                Some(format!("reusing existing open heal PR/MR: {}", existing_url)),
            )
            .await;
            insert_heal_request_row(
                app_pool.as_ref(),
                tenant_id,
                client_id,
                &finding_id,
                vuln_id,
                &existing_branch,
                Some(existing_url.as_str()),
                existing_num,
                "",
                "deduped_existing_pr",
                &jid_str,
                channel.id(),
                verdict_str,
                attempts_i32,
                receipt.as_ref(),
            )
            .await;
            report_heal_outcome(
                app_pool.as_ref(),
                tenant_id,
                &finding_id,
                verdict_str,
                channel.id(),
                attempts_i32,
                Some(existing_url.as_str()),
                true,
                heal_started,
            )
            .await;
            finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "completed").await;
            return Ok(json!({
                "ok": true,
                "channel": channel.id(),
                "verdict": verdict_str,
                "pr_url": existing_url,
                "pr_number": existing_num,
                "deduped": true,
                "spec_id": spec_id,
            }));
        }
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
                    attempts_i32,
                    None,
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
                    attempts_i32,
                    receipt.as_ref(),
                )
                .await;
                report_heal_outcome(
                    app_pool.as_ref(),
                    tenant_id,
                    &finding_id,
                    verdict_str,
                    channel.id(),
                    attempts_i32,
                    None,
                    true,
                    heal_started,
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

            let (title, body) = build_pr_text(&finding_id, &vr, &commit.diff_summary, attempts_i32, receipt.as_ref());
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
                        attempts_i32,
                        receipt.as_ref(),
                    )
                    .await;
                    report_heal_outcome(
                        app_pool.as_ref(),
                        tenant_id,
                        &finding_id,
                        verdict_str,
                        channel.id(),
                        attempts_i32,
                        pr_url.as_deref(),
                        true,
                        heal_started,
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
                        attempts_i32,
                        None,
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
                attempts_i32,
                receipt.as_ref(),
            )
            .await;
            report_heal_outcome(
                app_pool.as_ref(),
                tenant_id,
                &finding_id,
                verdict_str,
                channel.id(),
                attempts_i32,
                None,
                true,
                heal_started,
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
                attempts_i32,
                receipt.as_ref(),
            )
            .await;
            report_heal_outcome(
                app_pool.as_ref(),
                tenant_id,
                &finding_id,
                verdict_str,
                channel.id(),
                attempts_i32,
                None,
                true,
                heal_started,
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
        DeliveryChannel::GitlabMr => {
            let gitlab_host =
                std::env::var("WEISSMAN_GITLAB_HOST").unwrap_or_else(|_| "gitlab.com".into());
            let diff_summary: String = vr
                .changed_files
                .iter()
                .map(|(p, _)| p.as_str())
                .take(20)
                .collect::<Vec<_>>()
                .join(", ");
            let (title, body) =
                build_pr_text(&finding_id, &vr, &diff_summary, attempts_i32, receipt.as_ref());
            let outcome = crate::gitlab_heal::create_branch_commit_and_mr(
                &git_token,
                &gitlab_host,
                &repo_slug,
                &base_branch,
                &finding_id,
                vr.changed_files.clone(),
                &title,
                &body,
            )
            .await;
            if let Some(e) = &outcome.error {
                insert_heal_request_row(
                    app_pool.as_ref(),
                    tenant_id,
                    client_id,
                    &finding_id,
                    vuln_id,
                    &outcome.branch_name,
                    None,
                    None,
                    &diff_summary,
                    &format!("gitlab_mr_failed: {}", e),
                    &jid_str,
                    channel.id(),
                    verdict_str,
                    attempts_i32,
                    None,
                )
                .await;
                finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "failed").await;
                return Ok(json!({
                    "ok": false,
                    "error": e,
                    "verdict": verdict_str,
                    "branch_name": outcome.branch_name,
                    "spec_id": spec_id,
                }));
            }
            insert_heal_request_row(
                app_pool.as_ref(),
                tenant_id,
                client_id,
                &finding_id,
                vuln_id,
                &outcome.branch_name,
                outcome.mr_url.as_deref(),
                outcome.mr_iid,
                &diff_summary,
                "verified_mr_opened",
                &jid_str,
                channel.id(),
                verdict_str,
                attempts_i32,
                receipt.as_ref(),
            )
            .await;
            report_heal_outcome(
                app_pool.as_ref(),
                tenant_id,
                &finding_id,
                verdict_str,
                channel.id(),
                attempts_i32,
                outcome.mr_url.as_deref(),
                true,
                heal_started,
            )
            .await;
            finalize_spec(app_pool.as_ref(), tenant_id, spec_id, "completed").await;
            Ok(json!({
                "ok": true,
                "channel": channel.id(),
                "verdict": verdict_str,
                "branch_name": outcome.branch_name,
                "mr_url": outcome.mr_url,
                "mr_iid": outcome.mr_iid,
                "diff_summary": diff_summary,
                "spec_id": spec_id,
            }))
        }
    }
}
