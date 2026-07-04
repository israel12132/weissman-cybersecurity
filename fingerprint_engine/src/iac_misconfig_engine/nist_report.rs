//! NIST 800-53 control family executive report — maps compliance tags to AC/SC/IA/AU/CM families.

use super::model::{Finding, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const NIST_FAMILIES: &[(&str, &str)] = &[
    ("AC", "Access Control"),
    ("AU", "Audit & Accountability"),
    ("CM", "Configuration Management"),
    ("IA", "Identification & Authentication"),
    ("SC", "System & Communications Protection"),
    ("SI", "System & Information Integrity"),
    ("CP", "Contingency Planning"),
    ("SA", "System & Services Acquisition"),
];

#[must_use]
pub fn build(findings: &[Finding], compliance_rows: &[Value]) -> Value {
    let mut fam_failed: BTreeMap<String, u64> = BTreeMap::new();
    let mut fam_controls: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for f in findings {
        for tag in f.policy.compliance {
            if let Some(fam) = nist_family_of(tag) {
                *fam_failed.entry(fam.to_string()).or_insert(0) += 1;
                fam_controls
                    .entry(fam.to_string())
                    .or_default()
                    .push(tag.to_string());
            }
        }
    }

    let nist_row = compliance_rows
        .iter()
        .find(|r| r.get("pack").and_then(Value::as_str) == Some("NIST"));
    let total_controls = nist_row
        .and_then(|r| r.get("controls_covered").and_then(Value::as_u64))
        .unwrap_or(0);
    let failed_controls = nist_row
        .and_then(|r| r.get("controls_failed").and_then(Value::as_u64))
        .unwrap_or(0);
    let pass_pct = if total_controls > 0 {
        ((total_controls.saturating_sub(failed_controls)) * 100 / total_controls.max(1)) as u64
    } else {
        100
    };

    let crit = findings
        .iter()
        .filter(|f| f.policy.severity == Severity::Critical)
        .count() as u64;

    let families: Vec<Value> = NIST_FAMILIES
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

    let fedramp_ready = pass_pct >= 92 && crit == 0;
    let narrative = if fedramp_ready {
        format!("NIST 800-53 IaC alignment at {pass_pct}% — suitable baseline for FedRAMP moderate technical controls review.")
    } else {
        format!(
            "NIST posture {pass_pct}% with {failed_controls} failed controls — prioritize AC/SC/IA families ({crit} critical findings)."
        )
    };

    json!({
        "framework": "NIST",
        "pass_pct": pass_pct,
        "controls_covered": total_controls,
        "controls_failed": failed_controls,
        "critical_findings": crit,
        "control_families": families,
        "narrative": narrative,
        "fedramp_ready": fedramp_ready,
    })
}

fn nist_family_of(tag: &str) -> Option<&'static str> {
    let t = tag.trim();
    if !t.starts_with("NIST-") {
        return None;
    }
    let rest = t.strip_prefix("NIST-")?;
    let fam: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    match fam.as_str() {
        "AC" => Some("AC"),
        "AU" => Some("AU"),
        "CM" => Some("CM"),
        "IA" => Some("IA"),
        "SC" => Some("SC"),
        "SI" => Some("SI"),
        "CP" => Some("CP"),
        "SA" => Some("SA"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::terraform::S3_PUBLIC_ACL;

    #[test]
    fn maps_nist_families() {
        let findings = vec![Finding::new(S3_PUBLIC_ACL, "main.tf", "b")];
        let compliance =
            vec![json!({"pack": "NIST", "controls_covered": 30, "controls_failed": 2})];
        let r = build(&findings, &compliance);
        assert_eq!(r["framework"], "NIST");
    }
}
