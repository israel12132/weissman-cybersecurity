//! Per-client compliance-framework posture.
//!
//! Wave 18 attached a control crosswalk to each remediation *action*. Auditors ask the inverse,
//! framework-first question: "for PCI DSS / NIST / OWASP, which controls do our open findings touch,
//! and how many findings sit behind each?" This module rolls the same [`crate::remediation_priority`]
//! CWE→control crosswalk up across a client's live findings into per-framework control exposure.
//!
//! It reuses `controls_for_cwe`, so the compliance view and the remediation view can never disagree.
//! Scoring is pure/deterministic; the DB loader reads only live rows (RLS-scoped).

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn norm_severity(sev: &str) -> &'static str {
    match sev.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "info" | "informational" => "info",
        _ => "other",
    }
}

/// A finding as consumed here: just its CWE and severity.
#[derive(Debug, Clone)]
pub struct FindingLite {
    pub cwe: String,
    pub severity: String,
}

/// Open-finding exposure against one framework control.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ControlExposure {
    pub control: String,
    pub title: String,
    pub finding_count: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub other: usize,
}

/// A framework and the controls its client's open findings touch.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FrameworkGroup {
    pub framework: String,
    pub control_count: usize,
    pub finding_count: usize,
    pub controls: Vec<ControlExposure>,
}

#[derive(Debug, Default)]
struct Acc {
    title: String,
    finding_count: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    other: usize,
}

impl Acc {
    fn bump(&mut self, sev: &str) {
        self.finding_count += 1;
        match sev {
            "critical" => self.critical += 1,
            "high" => self.high += 1,
            "medium" => self.medium += 1,
            "low" => self.low += 1,
            "info" => self.info += 1,
            _ => self.other += 1,
        }
    }
}

/// Aggregate findings into per-framework control exposure via the CWE→control crosswalk.
/// Deterministic: frameworks sorted by finding-count desc then name; controls by count desc then id.
/// A finding touching the same control twice (duplicate CWE→control) counts once, since
/// `controls_for_cwe` is deduped by (framework, control).
#[must_use]
pub fn aggregate(findings: &[FindingLite]) -> Vec<FrameworkGroup> {
    // framework -> control -> Acc
    let mut by_fw: BTreeMap<String, BTreeMap<String, Acc>> = BTreeMap::new();
    for f in findings {
        let sev = norm_severity(&f.severity);
        for ctrl in crate::remediation_priority::controls_for_cwe(&f.cwe) {
            let fw = by_fw.entry(ctrl.framework.to_string()).or_default();
            let acc = fw.entry(ctrl.control.to_string()).or_default();
            if acc.title.is_empty() {
                acc.title = ctrl.title.to_string();
            }
            acc.bump(sev);
        }
    }

    let mut groups: Vec<FrameworkGroup> = by_fw
        .into_iter()
        .map(|(framework, controls)| {
            let mut ctrls: Vec<ControlExposure> = controls
                .into_iter()
                .map(|(control, a)| ControlExposure {
                    control,
                    title: a.title,
                    finding_count: a.finding_count,
                    critical: a.critical,
                    high: a.high,
                    medium: a.medium,
                    low: a.low,
                    info: a.info,
                    other: a.other,
                })
                .collect();
            ctrls.sort_by(|a, b| {
                b.finding_count
                    .cmp(&a.finding_count)
                    .then(a.control.cmp(&b.control))
            });
            let finding_count = ctrls.iter().map(|c| c.finding_count).sum();
            FrameworkGroup {
                framework,
                control_count: ctrls.len(),
                finding_count,
                controls: ctrls,
            }
        })
        .collect();
    groups.sort_by(|a, b| {
        b.finding_count
            .cmp(&a.finding_count)
            .then(a.framework.cmp(&b.framework))
    });
    groups
}

/// Load a client's live findings and aggregate compliance-framework posture. Read-only; RLS-scoped.
pub async fn load_and_aggregate(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    limit: i64,
) -> Result<Value, String> {
    use sqlx::Row;

    let limit = limit.clamp(1, 5000);
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;

    let rows = sqlx::query(
        r#"SELECT COALESCE(raw_data->>'cwe', '') AS cwe,
                  COALESCE(severity, '')         AS severity
             FROM vulnerabilities
            WHERE tenant_id = $1
              AND client_id = $2
              AND COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE', 'VERIFIED_FIXED')
            ORDER BY id DESC
            LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;

    let findings: Vec<FindingLite> = rows
        .iter()
        .map(|r| FindingLite {
            cwe: r.try_get("cwe").unwrap_or_default(),
            severity: r.try_get("severity").unwrap_or_default(),
        })
        .collect();

    let frameworks = aggregate(&findings);
    let mapped_findings = findings
        .iter()
        .filter(|f| !crate::remediation_priority::controls_for_cwe(&f.cwe).is_empty())
        .count();

    Ok(json!({
        "ok": true,
        "client_id": client_id,
        "findings_analyzed": findings.len(),
        "findings_mapped_to_controls": mapped_findings,
        "framework_count": frameworks.len(),
        "frameworks": frameworks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(cwe: &str, sev: &str) -> FindingLite {
        FindingLite {
            cwe: cwe.to_string(),
            severity: sev.to_string(),
        }
    }

    #[test]
    fn sqli_findings_roll_up_under_injection_frameworks() {
        let groups = aggregate(&[f("CWE-89", "critical"), f("CWE-89", "high")]);
        let owasp = groups
            .iter()
            .find(|g| g.framework == "OWASP Top 10 2021")
            .expect("OWASP framework present");
        let a03 = owasp
            .controls
            .iter()
            .find(|c| c.control == "A03:2021")
            .expect("injection control present");
        assert_eq!(a03.finding_count, 2);
        assert_eq!(a03.critical, 1);
        assert_eq!(a03.high, 1);
    }

    #[test]
    fn unmapped_cwe_contributes_no_frameworks() {
        assert!(aggregate(&[f("CWE-99999", "high"), f("", "low")]).is_empty());
    }

    #[test]
    fn frameworks_and_controls_are_ordered_by_finding_count() {
        // 3 SQLi (injection-heavy) + 1 weak-crypto finding.
        let groups = aggregate(&[
            f("CWE-89", "high"),
            f("CWE-89", "high"),
            f("CWE-89", "medium"),
            f("CWE-327", "low"),
        ]);
        // Frameworks are ordered by finding-count, non-increasing.
        for w in groups.windows(2) {
            assert!(w[0].finding_count >= w[1].finding_count);
        }
        // Within OWASP, the injection control (3 findings) leads crypto-failure (1).
        let owasp = groups
            .iter()
            .find(|g| g.framework == "OWASP Top 10 2021")
            .expect("OWASP present");
        assert_eq!(owasp.controls[0].control, "A03:2021");
        assert!(owasp.controls[0].finding_count >= owasp.controls.last().unwrap().finding_count);
    }

    #[test]
    fn framework_finding_count_sums_its_controls() {
        let groups = aggregate(&[f("CWE-89", "high"), f("CWE-79", "high")]);
        for g in &groups {
            let sum: usize = g.controls.iter().map(|c| c.finding_count).sum();
            assert_eq!(g.finding_count, sum);
            assert_eq!(g.control_count, g.controls.len());
        }
    }
}
