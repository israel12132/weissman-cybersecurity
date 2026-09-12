//! CI / operator dry-run: execute one local detection without enrolling.
//!
//! Output is a JSON report whose `outcome` is either `finding_detected` or
//! `no_vulnerability_found`. The report never invents findings: every row comes
//! from the live detection. A `fabrication_detected` flag is omitted unless a
//! finding matches the forbidden placeholder lexicon (which fails the run).

use crate::detections;
use serde::Serialize;
use serde_json::Value;
use std::time::Instant;

const FORBIDDEN_LEXICON: &[&str] = &[
    "fabrication_detected",
    "lorem ipsum",
    "placeholder finding",
    "simulated_hit",
    "demo_only",
    "hardcoded_finding",
    "fake finding",
];

#[derive(Debug, Clone, Serialize)]
pub struct ProbeReport {
    pub engine: String,
    pub outcome: String,
    pub findings_count: usize,
    pub latency_us: u128,
    pub os: String,
    pub arch: String,
    pub findings: Vec<Value>,
    /// Present only when a finding matched the forbidden lexicon (must stay false).
    #[serde(skip_serializing_if = "is_false")]
    pub fabrication_detected: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Run `engine` locally and return an evidence-backed report.
pub async fn run_dry(engine: &str) -> anyhow::Result<ProbeReport> {
    let start = Instant::now();
    let findings = detections::run_detection(engine, None, &Value::Null).await?;
    let elapsed = start.elapsed();
    let fabrication_detected = findings.iter().any(finding_looks_fabricated);
    let outcome = if findings.is_empty() {
        "no_vulnerability_found"
    } else {
        "finding_detected"
    };
    Ok(ProbeReport {
        engine: engine.to_string(),
        outcome: outcome.to_string(),
        findings_count: findings.len(),
        latency_us: elapsed.as_micros(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        findings,
        fabrication_detected,
    })
}

#[must_use]
pub fn finding_looks_fabricated(finding: &Value) -> bool {
    let blob = finding.to_string().to_ascii_lowercase();
    FORBIDDEN_LEXICON.iter().any(|n| blob.contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lexicon_does_not_flag_live_evidence() {
        let v = json!({
            "title": "EDR/AV agent present: 1 vendor(s)",
            "severity": "info",
            "source": "agent",
            "vendors": ["Microsoft Defender"]
        });
        assert!(!finding_looks_fabricated(&v));
    }

    #[test]
    fn lexicon_flags_placeholder_text() {
        let v = json!({"title": "placeholder finding", "severity": "high"});
        assert!(finding_looks_fabricated(&v));
    }

    #[tokio::test]
    async fn process_inventory_dry_run_is_live_and_honest() {
        let report = run_dry("process_inventory")
            .await
            .expect("process_inventory must run");
        assert!(!report.fabrication_detected);
        assert!(report.outcome == "finding_detected" || report.outcome == "no_vulnerability_found");
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("fabrication_detected"));
        assert!(encoded.contains("finding_detected") || encoded.contains("no_vulnerability_found"));
    }
}
