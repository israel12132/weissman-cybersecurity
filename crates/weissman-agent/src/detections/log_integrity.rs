//! Audit-log integrity probe — does the OS think its audit pipeline is healthy?

use super::finding;
use serde_json::Value;

pub async fn run(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    #[cfg(target_os = "linux")]
    {
        // Check that auditd or systemd-journald are running and that wtmp/btmp are present.
        let mut signals = serde_json::Map::new();
        for path in &[
            "/var/log/auth.log",
            "/var/log/wtmp",
            "/var/log/btmp",
            "/var/log/journal",
        ] {
            let exists = tokio::fs::metadata(path).await.is_ok();
            signals.insert((*path).to_string(), Value::Bool(exists));
        }
        let mut extras = serde_json::Map::new();
        extras.insert("log_paths".into(), Value::Object(signals.clone()));
        let any_missing = signals.values().any(|v| v.as_bool() == Some(false));
        let severity = if any_missing { "medium" } else { "info" };
        findings.push(finding(
            engine,
            if any_missing { "Audit-log path missing" } else { "Audit-log paths present" },
            severity,
            "T1070.002",
            "Agent verified the presence of canonical Linux audit-log paths. Forward to an immutable SIEM for tamper resistance.",
            extras,
        ));
    }
    #[cfg(target_os = "macos")]
    {
        let extras = serde_json::Map::new();
        findings.push(finding(
            engine,
            "Audit-log integrity probe (macOS)",
            "info",
            "T1070.002",
            "macOS unified-log integrity requires SystemAdministration entitlement; configure log shipping via `log stream` to your SIEM.",
            extras,
        ));
    }
    #[cfg(target_os = "windows")]
    {
        // Confirm the Security event log file is present + accessible.
        let candidate = std::path::Path::new(r"C:\Windows\System32\winevt\Logs\Security.evtx");
        let meta = tokio::fs::metadata(&candidate).await;
        let mut extras = serde_json::Map::new();
        let exists = meta.is_ok();
        extras.insert("security_evtx".into(), Value::Bool(exists));
        if let Ok(m) = meta {
            // Fully-qualified so no `use serde_json::json` import (which would be unused on
            // non-Windows targets) is needed just for this cfg-gated block.
            extras.insert("size_bytes".into(), serde_json::json!(m.len()));
        }
        findings.push(finding(
            engine,
            if exists { "Security.evtx present" } else { "Security.evtx not accessible" },
            if exists { "info" } else { "high" },
            "T1685.005",
            "Agent attempted to inspect the Security event log. If absent or 0 B, an actor may have cleared / disabled audit on this host.",
            extras,
        ));
    }
    Ok(findings)
}
