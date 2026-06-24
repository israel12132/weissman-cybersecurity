//! PCI-DSS v4 executive report — maps observed compliance tags and findings to PCI requirement
//! families for cardholder-data environment (CDE) audit readiness.

use super::model::{Finding, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const PCI_REQS: &[(&str, &str)] = &[
    ("1", "Install and Maintain Network Security Controls"),
    ("2", "Apply Secure Configurations"),
    ("3", "Protect Stored Account Data"),
    ("4", "Protect Data with Strong Cryptography During Transmission"),
    ("6", "Develop and Maintain Secure Systems"),
    ("7", "Restrict Access by Business Need to Know"),
    ("8", "Identify Users and Authenticate Access"),
    ("10", "Log and Monitor Access"),
    ("11", "Test Security Regularly"),
    ("12", "Support Information Security with Policies"),
];

/// Build PCI-DSS requirement-family scorecard from findings and compliance posture rows.
#[must_use]
pub fn build(findings: &[Finding], compliance_rows: &[Value]) -> Value {
    let mut req_failed: BTreeMap<String, u64> = BTreeMap::new();
    let mut req_controls: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for f in findings {
        for tag in f.policy.compliance {
            if let Some(req) = pci_req_of(tag) {
                *req_failed.entry(req.to_string()).or_insert(0) += 1;
                req_controls.entry(req.to_string()).or_default().push(tag.to_string());
            }
        }
    }

    let pci_row = compliance_rows.iter().find(|r| r.get("pack").and_then(Value::as_str) == Some("PCI-DSS"));
    let total_controls = pci_row
        .and_then(|r| r.get("controls_covered").and_then(Value::as_u64))
        .unwrap_or(0);
    let failed_controls = pci_row
        .and_then(|r| r.get("controls_failed").and_then(Value::as_u64))
        .unwrap_or(0);
    let pass_pct = if total_controls > 0 {
        ((total_controls.saturating_sub(failed_controls)) * 100 / total_controls.max(1)) as u64
    } else {
        100
    };

    let crit = findings.iter().filter(|f| f.policy.severity == Severity::Critical).count() as u64;
    let high = findings.iter().filter(|f| f.policy.severity == Severity::High).count() as u64;

    let requirements: Vec<Value> = PCI_REQS
        .iter()
        .map(|(id, title)| {
            let failed = req_failed.get(*id).copied().unwrap_or(0);
            let mut controls = req_controls.get(*id).cloned().unwrap_or_default();
            controls.sort();
            controls.dedup();
            json!({
                "requirement": id,
                "title": title,
                "findings_linked": failed,
                "failed_controls": controls,
                "status": if failed == 0 { "pass" } else { "fail" },
            })
        })
        .collect();

    let cde_ready = pass_pct >= 95 && crit == 0;
    let narrative = if cde_ready {
        format!(
            "PCI-DSS IaC posture at {pass_pct}% — CDE configuration controls largely satisfied. Remediate {high} high findings before QSA review."
        )
    } else if crit > 0 {
        format!(
            "PCI-DSS CDE risk: {crit} critical IaC findings affect Req 1/3/6 (network, data protection, secure development). Pass rate {pass_pct}% — not audit-ready."
        )
    } else {
        format!(
            "PCI-DSS readiness {pass_pct}% with {failed_controls} failed controls in IaC scan. Focus Req 1 (firewall), Req 3 (stored data), Req 6 (secure SDLC)."
        )
    };

    json!({
        "framework": "PCI-DSS",
        "pass_pct": pass_pct,
        "controls_covered": total_controls,
        "controls_failed": failed_controls,
        "critical_findings": crit,
        "high_findings": high,
        "requirements": requirements,
        "narrative": narrative,
        "cde_ready": cde_ready,
    })
}

fn pci_req_of(tag: &str) -> Option<&'static str> {
    let t = tag.trim();
    if !t.starts_with("PCI-DSS-") {
        return None;
    }
    let rest = t.strip_prefix("PCI-DSS-")?;
    let req: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if req.is_empty() {
        return None;
    }
    match req.as_str() {
        "1" => Some("1"),
        "2" => Some("2"),
        "3" => Some("3"),
        "4" => Some("4"),
        "6" => Some("6"),
        "7" => Some("7"),
        "8" => Some("8"),
        "10" => Some("10"),
        "11" => Some("11"),
        "12" => Some("12"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::terraform::S3_PUBLIC_ACL;

    #[test]
    fn maps_pci_tags() {
        let findings = vec![Finding::new(S3_PUBLIC_ACL, "main.tf", "aws_s3_bucket.b")];
        let compliance = vec![json!({"pack": "PCI-DSS", "controls_covered": 15, "controls_failed": 1, "status": "fail"})];
        let r = build(&findings, &compliance);
        assert_eq!(r["framework"], "PCI-DSS");
        assert!(r["requirements"].as_array().unwrap().len() >= 10);
    }
}
