//! EDR / antivirus presence check.
//!
//! We look at the *current process list* for any of the known EDR/AV agent names. If a fleet that
//! is supposed to have EDR is missing the agent, the absence itself is a critical finding.

use super::finding;
use crate::hostobs;
use serde_json::Value;

const KNOWN_EDR_PROCESSES: &[(&str, &str)] = &[
    ("MsMpEng", "Microsoft Defender"),
    ("MsSense", "Microsoft Defender for Endpoint"),
    ("CSFalconService", "CrowdStrike Falcon"),
    ("falcond", "CrowdStrike Falcon"),
    ("SentinelAgent", "SentinelOne"),
    ("SentinelOne", "SentinelOne"),
    ("xagt", "FireEye / Trellix"),
    ("ds_agent", "Trend Micro"),
    ("avp", "Kaspersky"),
    ("ekrn", "ESET"),
    ("McAfeeFramework", "McAfee"),
    ("symantec", "Symantec/Norton"),
    ("mfecanary", "McAfee Canary"),
    ("CarbonBlack", "VMware Carbon Black"),
    ("cb-defense", "VMware Carbon Black"),
    ("xagent", "Cybereason"),
    ("sophos", "Sophos"),
    ("rphcp", "Rapid7 Insight"),
];

pub async fn run(engine: &str) -> anyhow::Result<Vec<Value>> {
    let procs = hostobs::list_processes_light();
    let mut detected: Vec<(&'static str, &'static str)> = Vec::new();
    for proc in &procs {
        let name = proc.basename_lower();
        for (needle, vendor) in KNOWN_EDR_PROCESSES {
            if name.contains(&needle.to_ascii_lowercase()) {
                detected.push((needle, vendor));
                break;
            }
        }
    }
    let mut findings = Vec::new();
    if detected.is_empty() {
        findings.push(finding(
            engine,
            "No EDR / AV agent process observed",
            "high",
            "T1562.001",
            "Agent scanned the running process table and did not see any process matching the known EDR/AV vendor list. This endpoint may be unprotected.",
            serde_json::Map::new(),
        ));
    } else {
        let mut extras = serde_json::Map::new();
        extras.insert(
            "vendors".into(),
            Value::Array(
                detected
                    .iter()
                    .map(|(_, v)| Value::String((*v).to_string()))
                    .collect(),
            ),
        );
        findings.push(finding(
            engine,
            &format!("EDR/AV agent present: {} vendor(s)", detected.len()),
            "info",
            "T1562.001",
            "Agent verified at least one EDR/AV process is running. Tamper-protection of the EDR itself still needs vendor-API attestation.",
            extras,
        ));
    }
    Ok(findings)
}
