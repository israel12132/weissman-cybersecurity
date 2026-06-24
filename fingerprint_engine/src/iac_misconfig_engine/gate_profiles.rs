//! CI/CD gate profiles — preset strictness tiers (development / ci / production / pci) applied to
//! scan configuration before analysis. Operators pick a profile from the GUI; overrides still win.

use super::model::Severity;
use serde_json::Value;

pub struct GatePreset {
    pub fail_severity: Severity,
    pub min_severity: Severity,
    pub secret_scan: bool,
    pub attack_path_synthesis: bool,
    pub cross_file_correlation: bool,
    pub dedupe: bool,
}

#[must_use]
pub fn preset(name: &str) -> GatePreset {
    match name.trim().to_ascii_lowercase().as_str() {
        "development" | "dev" => GatePreset {
            fail_severity: Severity::Critical,
            min_severity: Severity::Info,
            secret_scan: true,
            attack_path_synthesis: true,
            cross_file_correlation: true,
            dedupe: true,
        },
        "ci" | "pipeline" => GatePreset {
            fail_severity: Severity::High,
            min_severity: Severity::Low,
            secret_scan: true,
            attack_path_synthesis: true,
            cross_file_correlation: true,
            dedupe: true,
        },
        "production" | "prod" => GatePreset {
            fail_severity: Severity::High,
            min_severity: Severity::Medium,
            secret_scan: true,
            attack_path_synthesis: true,
            cross_file_correlation: true,
            dedupe: true,
        },
        "pci" | "regulated" | "hipaa" => GatePreset {
            fail_severity: Severity::Medium,
            min_severity: Severity::Low,
            secret_scan: true,
            attack_path_synthesis: true,
            cross_file_correlation: true,
            dedupe: true,
        },
        "fedramp" | "ato" | "government" => GatePreset {
            fail_severity: Severity::Medium,
            min_severity: Severity::Low,
            secret_scan: true,
            attack_path_synthesis: true,
            cross_file_correlation: true,
            dedupe: true,
        },
        _ => GatePreset {
            fail_severity: Severity::High,
            min_severity: Severity::Info,
            secret_scan: true,
            attack_path_synthesis: true,
            cross_file_correlation: true,
            dedupe: true,
        },
    }
}

/// Apply profile defaults only where the operator did not explicitly set a value in job_params.
pub fn apply_profile(params: &mut Value, profile: &str) {
    let p = preset(profile);
    let obj = params.as_object_mut();
    if obj.is_none() {
        return;
    }
    let obj = obj.unwrap();
    if !obj.contains_key("fail_severity") {
        obj.insert("fail_severity".to_string(), Value::String(p.fail_severity.as_str().to_string()));
    }
    if !obj.contains_key("min_severity") {
        obj.insert("min_severity".to_string(), Value::String(p.min_severity.as_str().to_string()));
    }
    for (k, v) in [
        ("secret_scan", p.secret_scan),
        ("attack_path_synthesis", p.attack_path_synthesis),
        ("cross_file_correlation", p.cross_file_correlation),
        ("drift_analysis", true),
        ("resource_graph", true),
        ("live_blast", true),
        ("dedupe", p.dedupe),
    ] {
        if !obj.contains_key(k) {
            obj.insert(k.to_string(), Value::Bool(v));
        }
    }
    obj.insert("gate_profile_applied".to_string(), Value::String(profile.to_string()));
}

#[must_use]
pub fn asset_tier_multiplier(tier: &str) -> f64 {
    match tier.trim().to_ascii_lowercase().as_str() {
        "tier1" | "critical" | "production" | "p0" => 1.35,
        "tier2" | "important" | "p1" => 1.15,
        _ => 1.0,
    }
}
