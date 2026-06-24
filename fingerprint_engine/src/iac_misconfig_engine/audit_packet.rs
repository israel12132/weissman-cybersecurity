//! Master auditor compliance packet — single deterministic export bundling every executive report,
//! gate evidence, readiness, and remediation queue for SOC2/PCI/HIPAA/NIST/ISO/FedRAMP reviews.

use super::attack_chains::SynthesizedChain;
use super::model::Finding;
use serde_json::{json, Value};

#[must_use]
pub fn build(
    target: &str,
    findings: &[Finding],
    chains: &[SynthesizedChain],
    gate_passed: bool,
    gate_profile: &str,
    readiness: &Value,
    cis_scorecard: &Value,
    compliance: &[Value],
    soc2_report: &Value,
    pci_report: &Value,
    hipaa_report: &Value,
    nist_report: &Value,
    iso27001_report: &Value,
    fedramp_report: &Value,
    gate_evidence: &Value,
    remediation_queue: &[Value],
    playbooks: &[Value],
    live_blast: Option<&Value>,
    real_live_risk_score: Option<u64>,
) -> Value {
    let crit = findings.iter().filter(|f| f.policy.severity == super::model::Severity::Critical).count();
    let high = findings.iter().filter(|f| f.policy.severity == super::model::Severity::High).count();

    let compliance_matrix: Vec<Value> = compliance
        .iter()
        .map(|row| {
            json!({
                "pack": row.get("pack"),
                "controls_covered": row.get("controls_covered"),
                "controls_failed": row.get("controls_failed"),
                "status": row.get("status"),
                "pass_pct": row.get("controls_covered").and_then(Value::as_u64).map(|c| {
                    let f = row.get("controls_failed").and_then(Value::as_u64).unwrap_or(0);
                    if c > 0 { ((c.saturating_sub(f)) * 100 / c.max(1)) as u64 } else { 100 }
                }),
            })
        })
        .collect();

    let audit_ready = gate_passed
        && crit == 0
        && soc2_report.get("audit_ready").and_then(Value::as_bool).unwrap_or(false)
        && pci_report.get("cde_ready").and_then(Value::as_bool).unwrap_or(true)
        && hipaa_report.get("baa_ready").and_then(Value::as_bool).unwrap_or(true)
        && iso27001_report.get("certification_ready").and_then(Value::as_bool).unwrap_or(true)
        && fedramp_report.get("ato_ready").and_then(Value::as_bool).unwrap_or(true);

    json!({
        "target": target,
        "packet_type": "weissman-iac-audit-packet-v1",
        "deterministic": true,
        "generated_engine": "weissman-iac-security",
        "gate_profile": gate_profile,
        "gate_passed": gate_passed,
        "audit_ready": audit_ready,
        "findings_total": findings.len(),
        "critical_findings": crit,
        "high_findings": high,
        "attack_chains_total": chains.len(),
        "readiness_score": readiness.get("readiness_score"),
        "real_live_risk_score": real_live_risk_score,
        "live_blast_engine": live_blast.cloned().unwrap_or(Value::Null),
        "compliance_matrix": compliance_matrix,
        "cis_scorecard": cis_scorecard,
        "executive_reports": {
            "soc2": soc2_report,
            "pci_dss": pci_report,
            "hipaa": hipaa_report,
            "nist_800_53": nist_report,
            "iso_27001": iso27001_report,
            "fedramp_moderate": fedramp_report,
        },
        "gate_evidence": gate_evidence,
        "remediation_queue_top": remediation_queue.iter().take(25).collect::<Vec<_>>(),
        "compliance_playbooks_top": playbooks.iter().take(20).collect::<Vec<_>>(),
        "narrative": if audit_ready {
            "All compliance gates passed — IaC artifacts meet enterprise audit readiness across SOC2, PCI, HIPAA, NIST, ISO 27001 and FedRAMP Moderate baselines."
        } else {
            "Audit gaps remain — review executive_reports and gate_evidence for blocking findings before production authorization."
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_has_type() {
        let p = build(
            "t",
            &[],
            &[],
            true,
            "ci",
            &json!({"readiness_score": 80}),
            &json!({}),
            &[],
            &json!({"audit_ready": true}),
            &json!({"cde_ready": true}),
            &json!({"baa_ready": true}),
            &json!({}),
            &json!({"certification_ready": true}),
            &json!({"ato_ready": true}),
            &json!({"evidence_type": "iac_gate_audit"}),
            &[],
            &[],
            None,
            None,
        );
        assert_eq!(p["packet_type"], "weissman-iac-audit-packet-v1");
    }
}
