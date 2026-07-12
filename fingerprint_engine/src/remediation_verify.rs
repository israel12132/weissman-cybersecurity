//! Closed-loop remediation verification.
//!
//! When an analyst marks a finding FIXED/RESOLVED, the platform re-runs the **same
//! engine against the same target** and recomputes the stable `finding_id`. If the
//! original finding no longer appears, the vector is provably closed → the row is
//! promoted to `VERIFIED_FIXED`. If it still appears, the "fix" didn't hold → the row
//! is `REOPENED` (regression). Either way a `remediation_verification` record is stamped
//! into `raw_data`. This turns a remediation *recommendation* into a *verified outcome* —
//! a closed loop competitors don't ship out of the box.

use crate::engine_dispatch::{run_engine, EngineRunContext};
use serde_json::{json, Value};
use sqlx::PgPool;

/// Pure decision: does the original finding still appear among re-scan results?
/// Uses the exact same stable-`finding_id` computation as the persist path, so the
/// comparison is signature-accurate (volatile fields ignored).
#[must_use]
pub fn finding_still_present(
    original_finding_id: &str,
    engine: &str,
    target: &str,
    rescan_findings: &[Value],
) -> bool {
    rescan_findings.iter().any(|f| {
        crate::findings_persist::build_finding_id(engine, target, f) == original_finding_id
    })
}

#[derive(Debug, Clone)]
pub struct VerificationOutcome {
    pub closed: bool,
    pub rescan_finding_count: usize,
    pub status: &'static str,
}

/// Re-run `engine` against `target` and verify whether `original_finding_id` is gone,
/// then update the matching vulnerability row (status + `raw_data.remediation_verification`).
pub async fn run_verification(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    engine: &str,
    target: &str,
    original_finding_id: &str,
    ctx: &EngineRunContext,
) -> Result<VerificationOutcome, String> {
    if engine.trim().is_empty() || target.trim().is_empty() || original_finding_id.trim().is_empty()
    {
        return Err("engine, target and finding_id are required".into());
    }
    let result = run_engine(engine, target, ctx).await;
    let still = finding_still_present(original_finding_id, engine, target, &result.findings);
    let status = if still { "REOPENED" } else { "VERIFIED_FIXED" };
    let outcome = VerificationOutcome {
        closed: !still,
        rescan_finding_count: result.findings.len(),
        status,
    };

    let verification = json!({
        "verified_at": chrono::Utc::now().to_rfc3339(),
        "engine": engine,
        "target": target,
        "closed": outcome.closed,
        "rescan_findings": outcome.rescan_finding_count,
        "method": "live_rescan",
        "result_status": status,
    });

    // Persist the verdict. A DB failure here must NOT be swallowed: returning Ok
    // would falsely report "VERIFIED_FIXED" to the analyst while the row still says
    // the finding is open. Propagate the error so the worker marks the job failed
    // (and retries) instead of silently losing the verification outcome.
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("remediation verify: open tenant tx failed: {e}"))?;
    sqlx::query(
        r#"UPDATE vulnerabilities
              SET status = $1,
                  raw_data = jsonb_set(
                      COALESCE(raw_data, '{}'::jsonb),
                      '{remediation_verification}',
                      $2::jsonb,
                      true
                  )
            WHERE tenant_id = $3
              AND finding_id = $4
              AND ($5::bigint IS NULL OR client_id = $5)"#,
    )
    .bind(status)
    .bind(verification.to_string())
    .bind(tenant_id)
    .bind(original_finding_id)
    .bind(client_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("remediation verify: persist verdict failed: {e}"))?;
    tx.commit()
        .await
        .map_err(|e| format!("remediation verify: commit failed: {e}"))?;

    // Closed-loop regression alert: if a previously-fixed vector reopened, notify so it gets
    // re-remediated (autonomous re-heal can be wired via a SOAR playbook on this signal).
    if still
        && std::env::var("WEISSMAN_REGRESSION_ALERT")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true)
    {
        crate::alert_delivery::notify_regression(
            pool,
            tenant_id,
            original_finding_id,
            engine,
            target,
        )
        .await;
    }
    Ok(outcome)
}

/// Build the minimal engine context used for a remediation re-scan.
#[must_use]
pub fn verify_context(
    pool: std::sync::Arc<PgPool>,
    tenant_id: i64,
    client_id: Option<i64>,
) -> EngineRunContext {
    EngineRunContext {
        tenant_id: Some(tenant_id),
        client_id,
        app_pool: Some(pool),
        agents: Some(crate::endpoint_agents::AgentRegistry::global()),
        ..EngineRunContext::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_present_vs_closed() {
        let engine = "advanced_web_engines";
        let target = "https://victim.test";
        let f = json!({"title": "XSS", "signature": "reflected_xss", "cve": "CVE-2024-1"});
        let original = crate::findings_persist::build_finding_id(engine, target, &f);

        // Same signature reappears on re-scan → still present → NOT closed.
        assert!(finding_still_present(
            &original,
            engine,
            target,
            std::slice::from_ref(&f)
        ));

        // Re-scan returns a different finding → original is gone → closed.
        let other = json!({"title": "Other", "signature": "different"});
        assert!(!finding_still_present(
            &original,
            engine,
            target,
            std::slice::from_ref(&other)
        ));

        // Empty re-scan → closed.
        assert!(!finding_still_present(&original, engine, target, &[]));
    }
}
