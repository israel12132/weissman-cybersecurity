//! MITRE ATT&CK technique rollup and executive posture narrative — derived only from observed
//! finding and attack-chain metadata (no invented techniques).

use super::attack_chains::SynthesizedChain;
use super::model::{Finding, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[must_use]
pub fn mitre_rollup(findings: &[Finding], chains: &[SynthesizedChain]) -> Vec<Value> {
    let mut map: BTreeMap<String, (u64, Severity)> = BTreeMap::new();

    for f in findings {
        let tech = normalize_mitre(f.policy.mitre);
        if tech.is_empty() {
            continue;
        }
        let e = map.entry(tech).or_insert((0, Severity::Info));
        e.0 += 1;
        if f.policy.severity > e.1 {
            e.1 = f.policy.severity;
        }
    }
    for c in chains {
        for t in c.mitre_path() {
            let tech = normalize_mitre(t);
            if tech.is_empty() {
                continue;
            }
            let e = map.entry(tech).or_insert((0, Severity::Info));
            e.0 += 1;
            if c.severity() > e.1 {
                e.1 = c.severity();
            }
        }
    }

    let mut rows: Vec<Value> = map
        .into_iter()
        .map(|(technique, (count, max_sev))| {
            json!({
                "technique": technique,
                "findings": count,
                "max_severity": max_sev.as_str(),
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        let sa = a["max_severity"].as_str().unwrap_or("");
        let sb = b["max_severity"].as_str().unwrap_or("");
        severity_rank(sb).cmp(&severity_rank(sa)).then_with(|| {
            b["findings"]
                .as_u64()
                .unwrap_or(0)
                .cmp(&a["findings"].as_u64().unwrap_or(0))
        })
    });
    rows.truncate(25);
    rows
}

#[must_use]
pub fn executive_summary(
    findings: &[Finding],
    chains: &[SynthesizedChain],
    exploitability: u64,
    grade: &str,
    gate_passed: bool,
) -> Value {
    let crit = findings
        .iter()
        .filter(|f| f.policy.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.policy.severity == Severity::High)
        .count();
    let top_frameworks: BTreeMap<String, u64> =
        findings.iter().fold(BTreeMap::new(), |mut m, f| {
            *m.entry(f.policy.framework.to_string()).or_insert(0) += 1;
            m
        });
    let mut fw_sorted: Vec<_> = top_frameworks.into_iter().collect();
    fw_sorted.sort_by(|a, b| b.1.cmp(&a.1));
    let dominant = fw_sorted
        .first()
        .map(|(k, v)| format!("{k} ({v})"))
        .unwrap_or_else(|| "none".to_string());

    let narrative = if !gate_passed && !chains.is_empty() {
        format!(
            "Posture grade {grade} with exploitability {exploitability}/100. {crit} critical and {high} high findings plus {} attack chains — immediate remediation required on correlated toxic combinations.",
            chains.len()
        )
    } else if crit > 0 {
        format!(
            "Posture grade {grade}. {crit} critical misconfigurations detected; dominant exposure in {dominant}. Prioritize critical fixes before deployment."
        )
    } else if findings.is_empty() {
        "No policy violations observed in scanned artifacts.".to_string()
    } else {
        format!(
            "Posture grade {grade} with {high} high-severity items. Dominant framework: {dominant}. Gate {}",
            if gate_passed { "passed" } else { "failed" }
        )
    };

    json!({
        "narrative": narrative,
        "grade": grade,
        "exploitability_index": exploitability,
        "critical_count": crit,
        "high_count": high,
        "attack_chain_count": chains.len(),
        "gate_passed": gate_passed,
        "dominant_framework": dominant,
    })
}

fn normalize_mitre(s: &str) -> String {
    let t = s.trim();
    if t.is_empty() {
        return String::new();
    }
    if t.starts_with("T") {
        t.split('.').next().unwrap_or(t).to_string()
    } else if t.starts_with("MITRE-") {
        t.strip_prefix("MITRE-").unwrap_or(t).to_string()
    } else {
        String::new()
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::terraform::{IAM_WILDCARD, S3_PUBLIC_ACL};

    #[test]
    fn rollup_includes_techniques() {
        let f = vec![
            Finding::new(IAM_WILDCARD, "a", "f.tf"),
            Finding::new(S3_PUBLIC_ACL, "b", "f.tf"),
        ];
        let rows = mitre_rollup(&f, &[]);
        assert!(!rows.is_empty());
    }
}
