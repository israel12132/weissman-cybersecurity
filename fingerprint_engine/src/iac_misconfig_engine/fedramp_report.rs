//! FedRAMP Moderate executive report — derives authorization readiness from NIST 800-53
//! family posture observed in IaC scans (real findings only).

use super::model::{Finding, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const BASELINE_FAMILIES: &[(&str, &str, u64)] = &[
    ("AC", "Access Control", 25),
    ("AU", "Audit & Accountability", 12),
    ("CM", "Configuration Management", 18),
    ("IA", "Identification & Authentication", 11),
    ("SC", "System & Communications Protection", 22),
    ("SI", "System & Information Integrity", 15),
    ("CP", "Contingency Planning", 8),
    ("SA", "System & Services Acquisition", 9),
];

#[must_use]
pub fn build(findings: &[Finding], compliance_rows: &[Value], nist_report: &Value) -> Value {
    let mut fam_failed: BTreeMap<String, u64> = BTreeMap::new();
    for f in findings {
        for tag in f.policy.compliance {
            if let Some(fam) = nist_family_of(tag) {
                *fam_failed.entry(fam.to_string()).or_insert(0) += 1;
            }
        }
    }

    let nist_pass = nist_report
        .get("pass_pct")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let crit = findings
        .iter()
        .filter(|f| f.policy.severity == Severity::Critical)
        .count() as u64;
    let nist_row = compliance_rows
        .iter()
        .find(|r| r.get("pack").and_then(Value::as_str) == Some("NIST"));
    let failed_controls = nist_row
        .and_then(|r| r.get("controls_failed").and_then(Value::as_u64))
        .unwrap_or(0);

    let families: Vec<Value> = BASELINE_FAMILIES
        .iter()
        .map(|(id, title, baseline)| {
            let failed = fam_failed.get(*id).copied().unwrap_or(0);
            let status = if failed == 0 {
                "pass"
            } else if failed <= 2 {
                "partial"
            } else {
                "fail"
            };
            json!({
                "family": id,
                "title": title,
                "baseline_controls": baseline,
                "findings_linked": failed,
                "status": status,
            })
        })
        .collect();

    let families_failed = families.iter().filter(|f| f["status"] == "fail").count() as u64;
    let ato_ready = nist_pass >= 90 && crit == 0 && families_failed == 0;

    let narrative = if ato_ready {
        format!(
            "FedRAMP Moderate IaC baseline at {nist_pass}% — {failed_controls} NIST control gaps; suitable for 3PAO technical evidence package."
        )
    } else {
        format!(
            "FedRAMP authorization risk: {families_failed} families failing, {crit} critical findings — remediate AC/SC/IA before ATO submission."
        )
    };

    json!({
        "framework": "FedRAMP",
        "baseline": "Moderate",
        "pass_pct": nist_pass,
        "controls_failed": failed_controls,
        "critical_findings": crit,
        "families": families,
        "families_failing": families_failed,
        "narrative": narrative,
        "ato_ready": ato_ready,
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
    fn builds_fedramp_report() {
        let findings = vec![Finding::new(S3_PUBLIC_ACL, "main.tf", "main.tf")];
        let compliance =
            vec![json!({"pack": "NIST", "controls_covered": 30, "controls_failed": 2})];
        let nist = json!({"pass_pct": 93, "control_families": []});
        let r = build(&findings, &compliance, &nist);
        assert_eq!(r["framework"], "FedRAMP");
    }
}
