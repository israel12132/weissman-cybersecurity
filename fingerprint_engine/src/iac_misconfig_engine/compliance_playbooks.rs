//! Compliance remediation playbooks — maps failed compliance controls to actionable runbooks
//! derived only from policies that actually triggered in the scan.

use super::model::Finding;
use super::policies;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[must_use]
pub fn build(findings: &[Finding], compliance_rows: &[Value]) -> Vec<Value> {
    let mut by_pack: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in compliance_rows {
        let pack = row.get("pack").and_then(Value::as_str).unwrap_or("").to_string();
        if let Some(failed) = row.get("failed_controls").and_then(Value::as_array) {
            for c in failed {
                if let Some(tag) = c.as_str() {
                    by_pack.entry(pack.clone()).or_default().insert(tag.to_string());
                }
            }
        }
    }

    let mut policy_by_control: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        for tag in f.policy.compliance {
            policy_by_control.entry((*tag).to_string()).or_default().push(f);
        }
    }

    let mut out = Vec::new();
    for (pack, controls) in &by_pack {
        for ctrl in controls {
            let related: Vec<&Finding> = policy_by_control.get(ctrl).cloned().unwrap_or_default();
            let steps: Vec<String> = if related.is_empty() {
                vec![format!("Review all IaC artifacts mapped to {ctrl} and remediate per CIS benchmark guidance.")]
            } else {
                related
                    .iter()
                    .take(5)
                    .map(|f| format!("[{}] {} — {}", f.policy.id, f.resource, f.policy.remediation))
                    .collect()
            };
            let severity = related
                .iter()
                .map(|f| f.policy.severity)
                .max()
                .map(|s| s.as_str())
                .unwrap_or("medium");
            out.push(json!({
                "pack": pack,
                "control": ctrl,
                "severity": severity,
                "findings_linked": related.len(),
                "policy_ids": related.iter().map(|f| f.policy.id).collect::<Vec<_>>(),
                "steps": steps,
                "pack_label": policies::pack_of(ctrl),
            }));
        }
    }
    out.sort_by(|a, b| {
        let sa = a["severity"].as_str().unwrap_or("");
        let sb = b["severity"].as_str().unwrap_or("");
        sb.cmp(sa)
    });
    out.truncate(40);
    out
}
