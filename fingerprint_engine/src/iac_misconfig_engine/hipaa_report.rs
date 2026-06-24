//! HIPAA Security Rule executive report — maps observed findings to 164.312 safeguard families.

use super::model::{Finding, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const HIPAA_FAMILIES: &[(&str, &str)] = &[
    ("a", "Access Control (164.312(a))"),
    ("b", "Audit Controls (164.312(b))"),
    ("c", "Integrity (164.312(c))"),
    ("d", "Person/Entity Authentication (164.312(d))"),
    ("e", "Transmission Security (164.312(e))"),
];

#[must_use]
pub fn build(findings: &[Finding], compliance_rows: &[Value]) -> Value {
    let mut fam_failed: BTreeMap<String, u64> = BTreeMap::new();
    let mut fam_controls: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for f in findings {
        for tag in f.policy.compliance {
            if let Some(fam) = hipaa_family_of(tag) {
                *fam_failed.entry(fam.to_string()).or_insert(0) += 1;
                fam_controls.entry(fam.to_string()).or_default().push(tag.to_string());
            }
        }
    }

    let hipaa_row = compliance_rows.iter().find(|r| r.get("pack").and_then(Value::as_str) == Some("HIPAA"));
    let total_controls = hipaa_row.and_then(|r| r.get("controls_covered").and_then(Value::as_u64)).unwrap_or(0);
    let failed_controls = hipaa_row.and_then(|r| r.get("controls_failed").and_then(Value::as_u64)).unwrap_or(0);
    let pass_pct = if total_controls > 0 {
        ((total_controls.saturating_sub(failed_controls)) * 100 / total_controls.max(1)) as u64
    } else {
        100
    };

    let crit = findings.iter().filter(|f| f.policy.severity == Severity::Critical).count() as u64;
    let phi_risk = crit > 0 || failed_controls > 2;

    let families: Vec<Value> = HIPAA_FAMILIES
        .iter()
        .map(|(id, title)| {
            let failed = fam_failed.get(*id).copied().unwrap_or(0);
            let mut controls = fam_controls.get(*id).cloned().unwrap_or_default();
            controls.sort();
            controls.dedup();
            json!({
                "family": id,
                "title": title,
                "findings_linked": failed,
                "failed_controls": controls,
                "status": if failed == 0 { "pass" } else { "fail" },
            })
        })
        .collect();

    let narrative = if phi_risk {
        format!(
            "HIPAA ePHI risk: {crit} critical IaC findings affect access/transmission safeguards. Pass rate {pass_pct}% — remediate before handling PHI workloads."
        )
    } else {
        format!(
            "HIPAA IaC posture at {pass_pct}% — technical safeguards largely satisfied in scanned artifacts."
        )
    };

    json!({
        "framework": "HIPAA",
        "pass_pct": pass_pct,
        "controls_covered": total_controls,
        "controls_failed": failed_controls,
        "critical_findings": crit,
        "phi_risk": phi_risk,
        "safeguard_families": families,
        "narrative": narrative,
        "baa_ready": pass_pct >= 90 && crit == 0,
    })
}

fn hipaa_family_of(tag: &str) -> Option<&'static str> {
    let t = tag.trim();
    if !t.starts_with("HIPAA-164.312") {
        return None;
    }
    // HIPAA-164.312(a)(1) -> a
    let rest = t.strip_prefix("HIPAA-164.312(")?;
    let fam = rest.chars().next()?;
    match fam {
        'a' => Some("a"),
        'b' => Some("b"),
        'c' => Some("c"),
        'd' => Some("d"),
        'e' => Some("e"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::terraform::S3_PUBLIC_ACL;

    #[test]
    fn maps_hipaa_tags() {
        let findings = vec![Finding::new(S3_PUBLIC_ACL, "main.tf", "b")];
        let compliance = vec![json!({"pack": "HIPAA", "controls_covered": 8, "controls_failed": 1})];
        let r = build(&findings, &compliance);
        assert_eq!(r["framework"], "HIPAA");
    }
}
