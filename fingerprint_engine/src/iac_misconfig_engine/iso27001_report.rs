//! ISO/IEC 27001:2022 Annex A executive report — maps compliance tags to control themes
//! (organizational, people, physical, technological) for auditor-ready dashboards.

use super::model::{Finding, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const ISO_THEMES: &[(&str, &str)] = &[
    ("A.5", "Organizational controls"),
    ("A.6", "People controls"),
    ("A.7", "Physical controls"),
    ("A.8", "Technological controls"),
];

#[must_use]
pub fn build(findings: &[Finding], compliance_rows: &[Value]) -> Value {
    let mut theme_failed: BTreeMap<String, u64> = BTreeMap::new();
    let mut theme_controls: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for f in findings {
        for tag in f.policy.compliance {
            if let Some(theme) = iso_theme_of(tag) {
                *theme_failed.entry(theme.to_string()).or_insert(0) += 1;
                theme_controls
                    .entry(theme.to_string())
                    .or_default()
                    .push(tag.to_string());
            }
        }
    }

    let iso_row = compliance_rows
        .iter()
        .find(|r| r.get("pack").and_then(Value::as_str) == Some("ISO27001"));
    let total_controls = iso_row
        .and_then(|r| r.get("controls_covered").and_then(Value::as_u64))
        .unwrap_or(0);
    let failed_controls = iso_row
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
    let cert_ready = pass_pct >= 88 && crit == 0;

    let themes: Vec<Value> = ISO_THEMES
        .iter()
        .map(|(id, title)| {
            let failed = theme_failed.get(*id).copied().unwrap_or(0);
            let mut controls = theme_controls.get(*id).cloned().unwrap_or_default();
            controls.sort();
            controls.dedup();
            json!({
                "theme": id,
                "title": title,
                "findings_linked": failed,
                "failed_controls": controls,
                "status": if failed == 0 { "pass" } else { "fail" },
            })
        })
        .collect();

    let narrative = if cert_ready {
        format!(
            "ISO 27001 Annex A IaC alignment at {pass_pct}% — technological controls (A.8) suitable for Stage 2 audit evidence."
        )
    } else {
        format!(
            "ISO 27001 posture {pass_pct}% with {failed_controls} failed controls — prioritize A.8 technological safeguards ({crit} critical findings)."
        )
    };

    json!({
        "framework": "ISO27001",
        "pass_pct": pass_pct,
        "controls_covered": total_controls,
        "controls_failed": failed_controls,
        "critical_findings": crit,
        "annex_a_themes": themes,
        "narrative": narrative,
        "certification_ready": cert_ready,
    })
}

fn iso_theme_of(tag: &str) -> Option<&'static str> {
    let t = tag.trim();
    if t.starts_with("ISO27001-") {
        let rest = t.strip_prefix("ISO27001-")?;
        if rest.starts_with("A.5") {
            return Some("A.5");
        }
        if rest.starts_with("A.6") {
            return Some("A.6");
        }
        if rest.starts_with("A.7") {
            return Some("A.7");
        }
        if rest.starts_with("A.8")
            || rest.starts_with("A.9")
            || rest.starts_with("A.10")
            || rest.starts_with("A.13")
        {
            return Some("A.8");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::backstage::GUEST_AUTH;

    #[test]
    fn maps_iso_themes() {
        let findings = vec![Finding::new(
            GUEST_AUTH,
            "app-config.yaml",
            "app-config.yaml",
        )];
        let compliance =
            vec![json!({"pack": "ISO27001", "controls_covered": 40, "controls_failed": 1})];
        let r = build(&findings, &compliance);
        assert_eq!(r["framework"], "ISO27001");
        assert!(r["annex_a_themes"].is_array());
    }
}
