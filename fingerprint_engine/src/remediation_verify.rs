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
    pub status: String,
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
    let scan_ok =
        crate::elite_hardening::hack_fix_verify::engine_scan_ok(&result.status, result.success);
    let still = finding_still_present(original_finding_id, engine, target, &result.findings);
    // Read current status first so a failed scan cannot mint VERIFIED_FIXED.
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("remediation verify: open tenant tx failed: {e}"))?;
    let current_status: String = sqlx::query_scalar::<_, String>(
        r#"SELECT COALESCE(status, 'OPEN') FROM vulnerabilities
            WHERE tenant_id = $1 AND finding_id = $2
              AND ($3::bigint IS NULL OR client_id = $3)"#,
    )
    .bind(tenant_id)
    .bind(original_finding_id)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "OPEN".to_string());
    let was_verified_fixed = current_status == "VERIFIED_FIXED";
    let liveness = if still {
        crate::elite_hardening::host_liveness::HostLiveness::proven("scan_findings")
    } else {
        crate::elite_hardening::host_liveness::prove_host_live(
            pool,
            tenant_id,
            client_id,
            target,
            !result.findings.is_empty(),
        )
        .await
    };
    let host_live = liveness.live;
    let transition = crate::elite_hardening::hack_fix_verify::after_rescan(
        scan_ok,
        still,
        host_live,
        &current_status,
    );
    let status = match &transition {
        crate::elite_hardening::hack_fix_verify::Transition::Apply(s) => (*s).to_string(),
        crate::elite_hardening::hack_fix_verify::Transition::Hold { reason } => {
            tracing::info!(
                target: "hack_fix_verify",
                %reason,
                scan_ok,
                still,
                current_status = %current_status,
                "HFV holding status after remediation rescan"
            );
            current_status.clone()
        }
    };
    let closed = status == crate::elite_hardening::hack_fix_verify::STATUS_VERIFIED_FIXED;
    let outcome = VerificationOutcome {
        closed,
        rescan_finding_count: result.findings.len(),
        status: status.clone(),
    };

    let verification = json!({
        "verified_at": chrono::Utc::now().to_rfc3339(),
        "engine": engine,
        "target": target,
        "closed": outcome.closed,
        "rescan_findings": outcome.rescan_finding_count,
        "method": "live_rescan",
        "scan_ok": scan_ok,
        "host_liveness": liveness.to_json(),
        "result_status": status,
        "hack_fix_verify": crate::elite_hardening::hack_fix_verify::snapshot(),
    });

    // Persist the verdict. A DB failure here must NOT be swallowed: returning Ok
    // would falsely report "VERIFIED_FIXED" to the analyst while the row still says
    // the finding is open. Propagate the error so the worker marks the job failed
    // (and retries) instead of silently losing the verification outcome.
    match transition {
        crate::elite_hardening::hack_fix_verify::Transition::Apply(next) => {
            sqlx::query(
                r#"UPDATE vulnerabilities
                      SET status = $1,
                          watermark_severity = CASE
                              WHEN $1 = 'VERIFIED_FIXED'
                                  THEN COALESCE(NULLIF(severity, ''), watermark_severity)
                              WHEN $1 = 'REOPENED'
                                  THEN COALESCE(NULLIF(severity, ''), watermark_severity)
                              ELSE watermark_severity
                          END,
                          is_cycle_closed = ($1 = 'VERIFIED_FIXED'),
                          cycle_id = CASE
                              WHEN $1 = 'REOPENED' THEN gen_random_uuid()
                              ELSE COALESCE(cycle_id, gen_random_uuid())
                          END,
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
            .bind(next)
            .bind(verification.to_string())
            .bind(tenant_id)
            .bind(original_finding_id)
            .bind(client_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("remediation verify: persist verdict failed: {e}"))?;
        }
        crate::elite_hardening::hack_fix_verify::Transition::Hold { .. } => {
            sqlx::query(
                r#"UPDATE vulnerabilities
                      SET raw_data = jsonb_set(
                              COALESCE(raw_data, '{}'::jsonb),
                              '{remediation_verification}',
                              $1::jsonb,
                              true
                          )
                    WHERE tenant_id = $2
                      AND finding_id = $3
                      AND ($4::bigint IS NULL OR client_id = $4)"#,
            )
            .bind(verification.to_string())
            .bind(tenant_id)
            .bind(original_finding_id)
            .bind(client_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("remediation verify: persist hold failed: {e}"))?;
        }
    }
    tx.commit()
        .await
        .map_err(|e| format!("remediation verify: commit failed: {e}"))?;

    // Closed-loop regression alert: if a previously-fixed vector reopened, notify so it gets
    // re-remediated (autonomous re-heal can be wired via a SOAR playbook on this signal).
    if scan_ok
        && still
        && was_verified_fixed
        && std::env::var("WEISSMAN_REGRESSION_ALERT")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true)
    {
        // Fire-and-forget: the verdict is already committed, so best-effort notification delivery
        // (config lookup + up to three 15s outbound calls) must not block the verification result.
        let pool = pool.clone();
        let finding_id = original_finding_id.to_string();
        let engine = engine.to_string();
        let target = target.to_string();
        tokio::spawn(async move {
            crate::alert_delivery::notify_regression(
                &pool,
                tenant_id,
                &finding_id,
                &engine,
                &target,
            )
            .await;
        });
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

        // Empty re-scan → finding_still_present is false, but HFV still refuses
        // VERIFIED_FIXED unless the row was already marked FIXED and the scan succeeded.
        assert!(!finding_still_present(&original, engine, target, &[]));
        assert_eq!(
            crate::elite_hardening::hack_fix_verify::after_rescan(false, false, true, "FIXED"),
            crate::elite_hardening::hack_fix_verify::Transition::Hold {
                reason: "scan_did_not_succeed"
            }
        );
        assert_eq!(
            crate::elite_hardening::hack_fix_verify::after_rescan(true, false, false, "FIXED"),
            crate::elite_hardening::hack_fix_verify::Transition::Hold {
                reason: "host_liveness_unproven"
            }
        );
        assert_eq!(
            crate::elite_hardening::hack_fix_verify::after_rescan(true, false, true, "FIXED"),
            crate::elite_hardening::hack_fix_verify::Transition::Apply("VERIFIED_FIXED")
        );
    }
}
