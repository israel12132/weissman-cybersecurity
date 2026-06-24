//! Policy waivers — operator-approved suppressions with audit trail. Waived findings are excluded
//! from gate blocking and risk scoring but remain visible in the posture summary.

use super::model::Finding;
use serde_json::{json, Value};
use std::collections::HashSet;

/// One approved waiver for a policy (optionally scoped to specific files).
#[derive(Debug, Clone)]
pub struct Waiver {
    pub policy_id: String,
    pub reason: String,
    pub expiry: Option<String>,
    pub files: Option<HashSet<String>>,
}

/// Parse `policy_waivers` from job_params — array of objects or CSV policy ids (reason = "operator waiver").
#[must_use]
pub fn parse(p: &Value) -> Vec<Waiver> {
    let raw = p
        .get("policy_waivers")
        .or_else(|| p.get("options").and_then(|o| o.get("policy_waivers")));
    let Some(raw) = raw else { return Vec::new() };

    match raw {
        Value::Array(arr) => arr
            .iter()
            .filter_map(|item| {
                if let Some(id) = item.as_str() {
                    return Some(Waiver {
                        policy_id: id.trim().to_string(),
                        reason: "operator waiver".to_string(),
                        expiry: None,
                        files: None,
                    });
                }
                let id = item.get("policy_id").or_else(|| item.get("id"))?.as_str()?.trim().to_string();
                if id.is_empty() {
                    return None;
                }
                let reason = item
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("approved exception")
                    .to_string();
                let expiry = item.get("expiry").and_then(Value::as_str).map(str::to_string);
                let files = item.get("files").and_then(|f| match f {
                    Value::Array(a) => {
                        let s: HashSet<String> = a.iter().filter_map(|v| v.as_str()).map(str::to_string).collect();
                        if s.is_empty() { None } else { Some(s) }
                    }
                    Value::String(s) => {
                        let set: HashSet<String> = s.split([',', '\n']).map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect();
                        if set.is_empty() { None } else { Some(set) }
                    }
                    _ => None,
                });
                Some(Waiver { policy_id: id, reason, expiry, files })
            })
            .collect(),
        Value::String(s) => s
            .split([',', '\n'])
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(|id| Waiver {
                policy_id: id.to_string(),
                reason: "operator waiver".to_string(),
                expiry: None,
                files: None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn matches(w: &Waiver, f: &Finding) -> bool {
    if f.policy.id != w.policy_id {
        return false;
    }
    match &w.files {
        Some(scope) => scope.iter().any(|s| f.file.contains(s.as_str())),
        None => true,
    }
}

/// Split findings into active (enforced) and waived (audited but suppressed).
#[must_use]
pub fn apply(findings: Vec<Finding>, waivers: &[Waiver]) -> (Vec<Finding>, Vec<Value>) {
    if waivers.is_empty() {
        return (findings, Vec::new());
    }
    let mut active = Vec::new();
    let mut waived_json = Vec::new();

    for f in findings {
        if let Some(w) = waivers.iter().find(|w| matches(w, &f)) {
            waived_json.push(json!({
                "policy_id": f.policy.id,
                "title": f.policy.title,
                "severity": f.policy.severity.as_str(),
                "file": f.file,
                "resource": f.resource,
                "reason": w.reason,
                "expiry": w.expiry,
                "observed": f.observed,
            }));
        } else {
            active.push(f);
        }
    }
    (active, waived_json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::policies::EXPOSED_ENV;
    use crate::iac_misconfig_engine::model::Finding;

    #[test]
    fn waives_matching_policy() {
        let f = Finding::new(EXPOSED_ENV, "host", ".env");
        let waivers = parse(&json!({"policy_waivers": [{"policy_id": "WZ-EXP-002", "reason": "legacy staging"}]}));
        let (active, waived) = apply(vec![f], &waivers);
        assert!(active.is_empty());
        assert_eq!(waived.len(), 1);
    }
}
