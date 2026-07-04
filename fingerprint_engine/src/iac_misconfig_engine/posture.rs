//! Advanced posture engine — exploitability index, remediation priority queue, and optional full
//! policy catalog for operator dashboards. All scores derive from observed severities and chains.

use super::attack_chains::SynthesizedChain;
use super::model::{Finding, Severity};
use super::policies;
use serde_json::{json, Value};

/// Compute 0–100 exploitability index from severity mix + attack chains.
#[must_use]
pub fn exploitability_index(findings: &[Finding], chains: &[SynthesizedChain]) -> u64 {
    let crit = findings
        .iter()
        .filter(|f| f.policy.severity == Severity::Critical)
        .count() as u64;
    let high = findings
        .iter()
        .filter(|f| f.policy.severity == Severity::High)
        .count() as u64;
    let chain_boost = chains
        .iter()
        .filter(|c| c.severity() == Severity::Critical)
        .count() as u64
        * 8
        + chains
            .iter()
            .filter(|c| c.severity() == Severity::High)
            .count() as u64
            * 4;
    (crit * 12 + high * 5 + chain_boost).min(100)
}

/// Rank findings for remediation — critical first, then attack-chain correlated policies.
#[must_use]
pub fn remediation_queue(findings: &[Finding], chains: &[SynthesizedChain]) -> Vec<Value> {
    let mut chain_policies: std::collections::HashSet<String> = std::collections::HashSet::new();
    for c in chains {
        for p in &c.matched_policies {
            chain_policies.insert(p.clone());
        }
    }
    let mut ranked: Vec<&Finding> = findings.iter().collect();
    ranked.sort_by(|a, b| {
        let a_chain = chain_policies.contains(a.policy.id);
        let b_chain = chain_policies.contains(b.policy.id);
        b_chain
            .cmp(&a_chain)
            .then(b.policy.severity.cmp(&a.policy.severity))
            .then(a.file.cmp(&b.file))
    });
    ranked
        .into_iter()
        .take(50)
        .map(|f| {
            json!({
                "policy_id": f.policy.id,
                "title": f.policy.title,
                "severity": f.policy.severity.as_str(),
                "file": f.file,
                "resource": f.resource,
                "in_attack_chain": chain_policies.contains(f.policy.id),
                "remediation": f.policy.remediation,
                "code_fix": f.code_fix,
            })
        })
        .collect()
}

/// Full policy catalog with triggered flag for GUI browser.
#[must_use]
pub fn policy_catalog(triggered: &std::collections::HashSet<&str>) -> Vec<Value> {
    policies::all_policies()
        .iter()
        .map(|p| {
            json!({
                "id": p.id,
                "title": p.title,
                "severity": p.severity.as_str(),
                "framework": p.framework,
                "provider": p.provider,
                "mitre": p.mitre,
                "triggered": triggered.contains(p.id),
            })
        })
        .collect()
}

/// Framework coverage: policies available vs triggered per framework.
#[must_use]
pub fn framework_coverage(triggered: &std::collections::HashSet<&str>) -> Value {
    let catalog = policies::all_policies();
    let mut avail: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut hit: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for p in &catalog {
        *avail.entry(p.framework.to_string()).or_insert(0) += 1;
        if triggered.contains(p.id) {
            *hit.entry(p.framework.to_string()).or_insert(0) += 1;
        }
    }
    let rows: Vec<Value> = avail
        .iter()
        .map(|(fw, total)| {
            let triggered_n = hit.get(fw).copied().unwrap_or(0);
            let pct = if *total > 0 { (triggered_n * 100) / total } else { 0 };
            json!({ "framework": fw, "policies_total": total, "policies_triggered": triggered_n, "hit_rate_pct": pct })
        })
        .collect();
    json!({ "frameworks": rows })
}

/// CIS / compliance readiness scorecard from observed compliance posture rows.
#[must_use]
pub fn cis_scorecard(compliance_rows: &[Value]) -> Value {
    let mut packs = Vec::new();
    let mut total_covered = 0u64;
    let mut total_failed = 0u64;
    for row in compliance_rows {
        let pack = row.get("pack").and_then(Value::as_str).unwrap_or("?");
        let covered = row
            .get("controls_covered")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let failed = row
            .get("controls_failed")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        total_covered += covered;
        total_failed += failed;
        let pass_pct = if covered > 0 {
            ((covered.saturating_sub(failed)) * 100 / covered.max(1)) as u64
        } else {
            100
        };
        packs.push(json!({
            "pack": pack,
            "controls_covered": covered,
            "controls_failed": failed,
            "pass_pct": pass_pct,
            "status": row.get("status").and_then(Value::as_str).unwrap_or("unknown"),
        }));
    }
    let overall = if total_covered > 0 {
        ((total_covered.saturating_sub(total_failed)) * 100 / total_covered.max(1)) as u64
    } else {
        100
    };
    json!({
        "overall_pass_pct": overall,
        "packs": packs,
        "maturity": maturity_level(overall),
    })
}

fn maturity_level(pass_pct: u64) -> &'static str {
    match pass_pct {
        95..=100 => "optimized",
        80..=94 => "managed",
        60..=79 => "defined",
        40..=59 => "developing",
        _ => "initial",
    }
}

/// Executive readiness rollup — exploitability, fixability, drift and chain pressure.
#[must_use]
pub fn readiness_report(
    findings: &[Finding],
    chains: &[SynthesizedChain],
    exploit: u64,
    fix_count: u64,
    drift_count: u64,
    waived_count: u64,
) -> Value {
    let crit = findings
        .iter()
        .filter(|f| f.policy.severity == Severity::Critical)
        .count() as u64;
    let with_fix = findings.iter().filter(|f| f.code_fix.is_some()).count() as u64;
    let fixability_pct = if findings.is_empty() {
        100
    } else {
        let n = findings.len().max(1) as u64;
        (with_fix * 100 / n) as u64
    };
    let chain_pressure = chains.len() as u64 * 5 + crit * 3;
    let readiness = 100u64
        .saturating_sub(exploit / 2)
        .saturating_sub(chain_pressure)
        .saturating_sub(drift_count * 4)
        .saturating_sub(waived_count);
    let est_hours = crit * 4
        + findings
            .iter()
            .filter(|f| f.policy.severity == Severity::High)
            .count() as u64
            * 2
        + findings.len() as u64 / 3;
    json!({
        "readiness_score": readiness,
        "fixability_pct": fixability_pct,
        "automated_fixes_available": fix_count,
        "drift_findings": drift_count,
        "waived_findings": waived_count,
        "attack_chain_pressure": chain_pressure,
        "estimated_remediation_hours": est_hours.max(1),
    })
}

/// Framework × severity heatmap for SOC dashboards.
#[must_use]
pub fn risk_heatmap(findings: &[Finding]) -> Value {
    let mut grid: std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>> =
        std::collections::BTreeMap::new();
    for f in findings {
        *grid
            .entry(f.policy.framework.to_string())
            .or_default()
            .entry(f.policy.severity.as_str().to_string())
            .or_insert(0) += 1;
    }
    let rows: Vec<Value> = grid
        .iter()
        .map(|(fw, sevs)| {
            json!({
                "framework": fw,
                "critical": sevs.get("critical").copied().unwrap_or(0),
                "high": sevs.get("high").copied().unwrap_or(0),
                "medium": sevs.get("medium").copied().unwrap_or(0),
                "low": sevs.get("low").copied().unwrap_or(0),
                "info": sevs.get("info").copied().unwrap_or(0),
                "total": sevs.values().sum::<u64>(),
            })
        })
        .collect();
    json!({ "rows": rows, "frameworks": rows.len() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::terraform::{IAM_WILDCARD, S3_PUBLIC_ACL};

    #[test]
    fn exploitability_rises_with_criticals() {
        let findings = vec![
            Finding::new(IAM_WILDCARD, "a", "main.tf"),
            Finding::new(S3_PUBLIC_ACL, "b", "main.tf"),
        ];
        assert!(exploitability_index(&findings, &[]) >= 20);
    }
}
