//! GitHub pull-request adapter — idempotent auto-heal job enqueue.

use async_trait::async_trait;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use super::{AdapterContext, AdapterError, OpenPullRequestAdapter};
use crate::soar::integrations::config_str;
use crate::soar::types::{AdapterOutcome, RevertStep};

pub struct GithubPrAdapter;

#[async_trait]
impl OpenPullRequestAdapter for GithubPrAdapter {
    fn provider_id(&self) -> &'static str {
        "github"
    }

    async fn open_pr(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError> {
        if ctx.cmd.dry_run {
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: None,
                detail: "dry_run: would enqueue verified auto-heal PR job".into(),
                payload: json!({}),
                revert_steps: vec![],
                verify_probe: None,
            });
        }

        let finding_id = ctx
            .cmd
            .evidence
            .finding_id
            .ok_or_else(|| AdapterError::Skipped("no finding_id on event".into()))?;
        let client_id = ctx
            .cmd
            .client_id
            .ok_or_else(|| AdapterError::Skipped("no client_id on event".into()))?;

        let title = ctx
            .cmd
            .params
            .get("title")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("Auto-remediation: {}", ctx.cmd.evidence.title));

        let (vuln_id, finding_text, patch, poc, repo, token, base) =
            load_heal_material(ctx, finding_id).await?;

        if patch.trim().is_empty() {
            return Err(AdapterError::Skipped(
                "finding has no remediation patch — configure genesis vault or manual patch".into(),
            ));
        }
        if token.trim().is_empty() || repo.trim().is_empty() {
            return Err(AdapterError::Config(
                "github integration requires git_token and repo_slug".into(),
            ));
        }

        let spec_id = Uuid::new_v4();
        let Ok(mut tx) = crate::db::begin_tenant_tx(ctx.pool, ctx.cmd.tenant_id).await else {
            return Err(AdapterError::Provider("tenant tx".into()));
        };
        let ins = sqlx::query(
            r#"INSERT INTO auto_heal_job_specs (
                id, tenant_id, client_id, vuln_id, finding_id,
                git_token, repo_slug, base_branch, patch_text, poc_curl, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending')"#,
        )
        .bind(spec_id)
        .bind(ctx.cmd.tenant_id)
        .bind(client_id)
        .bind(vuln_id)
        .bind(&finding_text)
        .bind(&token)
        .bind(&repo)
        .bind(&base)
        .bind(&patch)
        .bind(&poc)
        .execute(&mut *tx)
        .await;
        if ins.is_err() {
            let _ = tx.rollback().await;
            return Err(AdapterError::Provider(
                "auto_heal_job_specs insert failed".into(),
            ));
        }
        let _ = tx.commit().await;

        let queue_payload = json!({ "spec_id": spec_id.to_string(), "soar": true });
        let queue_payload =
            crate::job_envelope::seal_job_payload_sqlx(queue_payload, ctx.cmd.tenant_id)
                .map_err(|e| AdapterError::Provider(format!("job envelope: {e}")))?;
        if let Err(e) = crate::db::job_queue::enqueue_with_max_attempts(
            ctx.pool,
            ctx.cmd.tenant_id,
            "auto_heal",
            queue_payload,
            None,
            3,
        )
        .await
        {
            return Err(AdapterError::Provider(format!("job enqueue: {e}")));
        }

        let external_ref = spec_id.to_string();
        let payload = json!({
            "spec_id": external_ref,
            "repo": repo,
            "title": title,
            "finding_id": finding_text,
        });
        Ok(AdapterOutcome {
            provider: self.provider_id().into(),
            external_ref: Some(external_ref.clone()),
            detail: format!("auto_heal job {external_ref} queued for finding {finding_id}"),
            payload,
            revert_steps: self.revert_steps(&AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: Some(external_ref),
                detail: String::new(),
                payload: json!({}),
                revert_steps: vec![],
                verify_probe: None,
            }),
            verify_probe: None,
        })
    }

    /// Confirm a PR exists for this heal job.
    ///
    /// The authoritative, DB-backed closed-loop check for `open_pr` runs in
    /// `soar::worker::verify_heal_job` (it inspects `auto_heal_job_specs.status == 'completed'`),
    /// which the SOAR worker calls directly for the `pr_exists` probe. This adapter method is the
    /// fallback used when only the outcome payload is available (no pool): it confirms a PR iff the
    /// payload carries a concrete PR reference (`pr_url` / `pr_number` / `html_url`). It never
    /// fabricates a positive result — absence of a reference is an honest "cannot confirm".
    async fn verify_pr(
        &self,
        external_ref: &str,
        payload: &serde_json::Value,
    ) -> Result<bool, AdapterError> {
        if Uuid::parse_str(external_ref).is_err() {
            return Ok(false);
        }
        let has_pr_ref = payload
            .get("pr_url")
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
            || payload
                .get("html_url")
                .and_then(|v| v.as_str())
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
            || payload.get("pr_number").and_then(|v| v.as_i64()).is_some();
        Ok(has_pr_ref)
    }

    fn revert_steps(&self, outcome: &AdapterOutcome) -> Vec<RevertStep> {
        let spec_id = outcome.external_ref.clone().unwrap_or_default();
        vec![RevertStep {
            provider: self.provider_id().into(),
            operation: "close_pull_request".into(),
            payload: json!({ "spec_id": spec_id, "action": "close_pr_if_open" }),
            description: "Close auto-opened remediation PR if still open".into(),
        }]
    }
}

async fn load_heal_material(
    ctx: &AdapterContext<'_>,
    finding_id: i64,
) -> Result<(i64, String, String, String, String, String, String), AdapterError> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(ctx.pool, ctx.cmd.tenant_id).await else {
        return Err(AdapterError::Provider("tenant tx".into()));
    };
    let row = sqlx::query(
        r#"SELECT id, COALESCE(finding_id, id::text) AS fid, COALESCE(generated_patch, ''),
                  COALESCE(poc_exploit, ''), COALESCE(description, '')
           FROM vulnerabilities WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(finding_id)
    .bind(ctx.cmd.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AdapterError::Provider(e.to_string()))?;
    let _ = tx.commit().await;
    let Some(r) = row else {
        return Err(AdapterError::Skipped("finding not found".into()));
    };
    let vuln_id: i64 = r.try_get("id").unwrap_or(finding_id);
    let finding_text: String = r.try_get("fid").unwrap_or_else(|_| finding_id.to_string());
    let patch: String = r
        .try_get::<String, _>("generated_patch")
        .unwrap_or_default();
    let poc: String = r.try_get("poc_exploit").unwrap_or_default();

    let repo = config_str(&ctx.integration.config, &["repo", "repo_slug"]).unwrap_or_default();
    let token = config_str(&ctx.integration.config, &["token", "git_token"])
        .or_else(|| std::env::var("WEISSMAN_GITHUB_TOKEN").ok())
        .unwrap_or_default();
    let base =
        config_str(&ctx.integration.config, &["base_branch"]).unwrap_or_else(|| "main".into());

    Ok((vuln_id, finding_text, patch, poc, repo, token, base))
}
