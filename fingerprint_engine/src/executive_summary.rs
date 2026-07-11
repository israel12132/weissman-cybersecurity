//! Unified executive summary — one call, one query, one ranking.
//!
//! The posture, projection, SLA-forecast and remediation views each independently loaded the same
//! findings and ranked them. A dashboard that shows all of them therefore fired several identical
//! full scans of `vulnerabilities` per page load. This module is the backend-for-frontend that
//! loads the findings **once**, ranks them **once**, and composes every remediation-derived view
//! from that single pass — so the exec dashboard costs one query instead of three-plus.
//!
//! It is a pure composition of already-tested engines ([`crate::remediation_priority`],
//! [`crate::posture_score`], [`crate::sla_forecast`]); no new scoring lives here.

use crate::remediation_priority::RemediationItem;
use serde_json::{json, Value};

/// How many top-ranked remediation actions to inline in the summary.
const TOP_ACTIONS: usize = 10;
/// Projection steps to include.
const PROJECTION_STEPS: usize = 10;

/// Compose the executive summary from an already-ranked program. Pure: no I/O, so the composition
/// is unit-testable and the same program always yields the same summary.
#[must_use]
pub fn build_summary(program: &[RemediationItem], total_findings: usize) -> Value {
    let posture = crate::posture_score::score(program, total_findings);
    let projection = crate::posture_score::project(program, total_findings, PROJECTION_STEPS);
    let forecast = crate::sla_forecast::forecast(program, &crate::sla_forecast::DEFAULT_HORIZONS);
    let overdue_now = crate::sla_forecast::overdue_now(program);

    let kev_actions = program.iter().filter(|i| i.kev).count();
    let crown_actions = program.iter().filter(|i| i.crown_jewel).count();
    let choke_actions = program.iter().filter(|i| i.on_choke_point).count();
    let top: Vec<&RemediationItem> = program.iter().take(TOP_ACTIONS).collect();

    json!({
        "posture": posture,
        "projection": projection,
        "sla": {
            "overdue_now": overdue_now,
            "horizon_days": crate::sla_forecast::DEFAULT_HORIZONS,
            "forecast": forecast,
        },
        "remediation": {
            "total_findings": total_findings,
            "action_count": program.len(),
            "kev_actions": kev_actions,
            "crown_jewel_actions": crown_actions,
            "choke_point_actions": choke_actions,
            "top_actions": top,
        },
    })
}

/// Load a client's findings once and compose the full executive summary. Read-only; RLS-scoped.
pub async fn load_summary(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    limit: i64,
) -> Result<Value, String> {
    let findings =
        crate::remediation_priority::load_findings(pool, tenant_id, client_id, limit).await?;
    let total_findings = findings.len();
    let program = crate::remediation_priority::rank(&findings);
    let mut summary = build_summary(&program, total_findings);
    if let Some(obj) = summary.as_object_mut() {
        obj.insert("ok".to_string(), json!(true));
        obj.insert("client_id".to_string(), json!(client_id));
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remediation_priority::{rank, FindingInput};

    fn finding(id: &str, sev: &str, er: Option<f64>, age: Option<i64>) -> FindingInput {
        FindingInput {
            finding_id: id.to_string(),
            title: format!("finding {id}"),
            severity: sev.to_string(),
            cwe: format!("CWE-{id}"),
            asset: format!("asset-{id}.example.com"),
            effective_risk: er,
            epss: None,
            kev: false,
            kev_ransomware: false,
            cluster_id: None,
            on_choke_point: false,
            crown_jewel: false,
            asset_value: 1.0,
            business_value_usd: None,
            first_seen_days: age,
        }
    }

    #[test]
    fn summary_has_all_sections() {
        let program = rank(&[finding("a", "high", Some(7.5), Some(10))]);
        let s = build_summary(&program, 1);
        assert!(s.get("posture").is_some());
        assert!(s.get("projection").is_some());
        assert!(s["sla"].get("forecast").is_some());
        assert!(s["remediation"].get("top_actions").is_some());
    }

    #[test]
    fn summary_posture_matches_the_standalone_engine() {
        let program = rank(&[
            finding("a", "high", Some(7.5), Some(10)),
            finding("b", "critical", Some(9.2), Some(40)),
        ]);
        let s = build_summary(&program, 2);
        let standalone = crate::posture_score::score(&program, 2);
        assert_eq!(s["posture"]["score"].as_f64().unwrap(), standalone.score);
        assert_eq!(
            s["posture"]["grade"]
                .as_str()
                .unwrap()
                .chars()
                .next()
                .unwrap(),
            standalone.grade
        );
    }

    #[test]
    fn top_actions_are_capped_and_rank_ordered() {
        let findings: Vec<FindingInput> = (0..15)
            .map(|i| {
                finding(
                    &format!("f{i}"),
                    "high",
                    Some(7.0 + (i as f64) * 0.05),
                    Some(5),
                )
            })
            .collect();
        let program = rank(&findings);
        let s = build_summary(&program, findings.len());
        let top = s["remediation"]["top_actions"].as_array().unwrap();
        assert_eq!(
            top.len(),
            TOP_ACTIONS,
            "top actions capped at {TOP_ACTIONS}"
        );
        // Ranks are contiguous from 1 (already rank-ordered by rank()).
        assert_eq!(top[0]["rank"].as_u64().unwrap(), 1);
        assert_eq!(top[1]["rank"].as_u64().unwrap(), 2);
    }

    #[test]
    fn empty_program_summary_is_well_formed() {
        let s = build_summary(&[], 0);
        assert_eq!(s["remediation"]["action_count"].as_u64().unwrap(), 0);
        assert_eq!(s["posture"]["grade"].as_str().unwrap(), "A");
        assert!(s["projection"].as_array().unwrap().is_empty());
    }
}
