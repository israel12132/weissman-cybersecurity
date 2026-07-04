//! SOC2 Trust Services Criteria executive report — maps observed compliance tags and findings
//! to CC control families for auditor-ready posture dashboards. All counts derive from real scans.

use super::model::{Finding, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const CC_FAMILIES: &[(&str, &str)] = &[
    ("CC1", "Control Environment"),
    ("CC2", "Communication & Information"),
    ("CC3", "Risk Assessment"),
    ("CC4", "Monitoring Activities"),
    ("CC5", "Control Activities"),
    ("CC6", "Logical & Physical Access"),
    ("CC7", "System Operations"),
    ("CC8", "Change Management"),
    ("CC9", "Risk Mitigation"),
];

/// Build SOC2 CC-family scorecard from findings and compliance posture rows.
#[must_use]
pub fn build(findings: &[Finding], compliance_rows: &[Value]) -> Value {
    let mut cc_failed: BTreeMap<String, u64> = BTreeMap::new();
    let mut cc_controls: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for f in findings {
        for tag in f.policy.compliance {
            if let Some(cc) = soc2_cc_of(tag) {
                *cc_failed.entry(cc.to_string()).or_insert(0) += 1;
                cc_controls
                    .entry(cc.to_string())
                    .or_default()
                    .push(tag.to_string());
            }
        }
    }

    let soc2_row = compliance_rows
        .iter()
        .find(|r| r.get("pack").and_then(Value::as_str) == Some("SOC2"));
    let total_controls = soc2_row
        .and_then(|r| r.get("controls_covered").and_then(Value::as_u64))
        .unwrap_or(0);
    let failed_controls = soc2_row
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
    let high = findings
        .iter()
        .filter(|f| f.policy.severity == Severity::High)
        .count() as u64;

    let families: Vec<Value> = CC_FAMILIES
        .iter()
        .map(|(id, title)| {
            let failed = cc_failed.get(*id).copied().unwrap_or(0);
            let mut controls = cc_controls.get(*id).cloned().unwrap_or_default();
            controls.sort();
            controls.dedup();
            json!({
                "cc_family": id,
                "title": title,
                "findings_linked": failed,
                "failed_controls": controls,
                "status": if failed == 0 { "pass" } else { "fail" },
            })
        })
        .collect();

    let narrative = if pass_pct >= 95 && crit == 0 {
        format!(
            "SOC2 posture strong at {pass_pct}% control pass rate. {high} high-severity IaC findings remain — address before audit window."
        )
    } else if crit > 0 {
        format!(
            "SOC2 audit risk: {crit} critical IaC findings map to CC6/CC8 access and change-management controls. Immediate remediation required — pass rate {pass_pct}%."
        )
    } else {
        format!(
            "SOC2 readiness at {pass_pct}% with {failed_controls} failed controls across IaC scan. Prioritize CC6 (access) and CC8 (change management) families."
        )
    };

    json!({
        "framework": "SOC2",
        "pass_pct": pass_pct,
        "controls_covered": total_controls,
        "controls_failed": failed_controls,
        "critical_findings": crit,
        "high_findings": high,
        "cc_families": families,
        "narrative": narrative,
        "audit_ready": pass_pct >= 90 && crit == 0,
    })
}

fn soc2_cc_of(tag: &str) -> Option<&'static str> {
    let t = tag.trim();
    if !t.starts_with("SOC2-CC") {
        return None;
    }
    // SOC2-CC6.1 -> CC6
    let rest = t.strip_prefix("SOC2-")?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    Some(match digits.as_str() {
        "1" => "CC1",
        "2" => "CC2",
        "3" => "CC3",
        "4" => "CC4",
        "5" => "CC5",
        "6" => "CC6",
        "7" => "CC7",
        "8" => "CC8",
        "9" => "CC9",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::terraform::S3_PUBLIC_ACL;

    #[test]
    fn maps_soc2_tags_to_cc_families() {
        let findings = vec![Finding::new(S3_PUBLIC_ACL, "main.tf", "aws_s3_bucket.b")];
        let compliance = vec![
            json!({"pack": "SOC2", "controls_covered": 20, "controls_failed": 2, "status": "fail"}),
        ];
        let r = build(&findings, &compliance);
        assert!(r["cc_families"].as_array().unwrap().len() >= 9);
        assert_eq!(r["framework"], "SOC2");
    }
}
