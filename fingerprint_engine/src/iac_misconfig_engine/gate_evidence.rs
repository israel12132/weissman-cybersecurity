//! Gate audit evidence bundle — deterministic artifact proving why a CI gate passed or failed,
//! suitable for SOC2 CC8 change-management and PCI-DSS evidence lockers.

use super::attack_chains::SynthesizedChain;
use super::model::{Finding, Severity};
use serde_json::{json, Value};

/// Build an auditor-ready gate evidence packet from observed scan results.
#[must_use]
pub fn build(
    target: &str,
    findings: &[Finding],
    chains: &[SynthesizedChain],
    fail_severity: Severity,
    gate_passed: bool,
    gate_profile: &str,
    waived: &[Value],
    live_blast: Option<&Value>,
) -> Value {
    let blocking: Vec<Value> = findings
        .iter()
        .filter(|f| f.policy.severity >= fail_severity)
        .map(|f| {
            json!({
                "policy_id": f.policy.id,
                "severity": f.policy.severity.as_str(),
                "framework": f.policy.framework,
                "file": f.file,
                "resource": f.resource,
                "observed": f.observed,
            })
        })
        .collect();

    let blocking_chains: Vec<Value> = chains
        .iter()
        .filter(|c| c.severity() >= fail_severity)
        .map(|c| c.summary_json())
        .collect();

    let policy_ids: Vec<&str> = findings.iter().map(|f| f.policy.id).collect();
    let unique_frameworks: Vec<String> = {
        let mut s = std::collections::BTreeSet::new();
        for f in findings {
            s.insert(f.policy.framework.to_string());
        }
        s.into_iter().collect()
    };

    json!({
        "target": target,
        "gate_profile": gate_profile,
        "gate_passed": gate_passed,
        "fail_severity": fail_severity.as_str(),
        "blocking_findings_count": blocking.len(),
        "blocking_chains_count": blocking_chains.len(),
        "blocking_findings": blocking,
        "blocking_chains": blocking_chains,
        "waivers_applied": waived.len(),
        "waivers": waived,
        "frameworks_with_findings": unique_frameworks,
        "policies_triggered": policy_ids.len(),
        "evidence_type": "iac_gate_audit",
        "deterministic": true,
        "live_blast": live_blast.cloned().unwrap_or(Value::Null),
    })
}
