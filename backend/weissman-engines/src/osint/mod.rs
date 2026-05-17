//! OSINT: certificate transparency + host search (migrated from monolith `osint_engine`).

mod engine;

pub use engine::{run_osint, OsintCyberEngine, run_osint_result};
use serde_json::Value;
use std::collections::HashSet;

/// Subdomains extracted from OSINT JSON findings (`value` / `common_name`).
#[must_use]
pub fn subdomains_from_osint_findings(findings: &[Value]) -> Vec<String> {
    let mut out = HashSet::new();
    for f in findings {
        if let Some(obj) = f.as_object() {
            let v = obj
                .get("value")
                .and_then(|x| x.as_str())
                .or_else(|| obj.get("common_name").and_then(|x| x.as_str()));
            if let Some(s) = v {
                let s = s.trim().to_lowercase();
                if s.len() >= 2 && !s.contains('*') {
                    out.insert(s);
                }
            }
        }
    }
    out.into_iter().collect()
}
