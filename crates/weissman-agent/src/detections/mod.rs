//! Detection registry. Every entry returns a vector of finding objects identical in shape to
//! engine findings produced by the remote scan engines.

mod arp_table;
mod baseline;
mod clipboard;
mod edr_presence;
mod log_integrity;
mod process_hollowing;
mod process_modules;
mod scheduled_tasks;
mod timestomp;
mod usb_devices;

use serde_json::Value;

pub type DetectionFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<Value>>> + Send>>;

/// All capability IDs advertised to the server at enrollment. The server uses this list to decide
/// which `agent_required_ok` engines may be dispatched to this agent.
pub fn all_capability_ids() -> Vec<&'static str> {
    vec![
        // process / memory
        "process_hollowing",
        "dll_hijacking_engine",
        "process_inventory",
        // persistence
        "persistence_mechanism",
        "bootkit_uefi",
        // network (local)
        "arp_spoofing_engine",
        "dns_tunneling_c2",
        "icmp_covert",
        // exfiltration
        "clipboard_hijack",
        "screen_capture_exfil",
        "insider_exfil",
        // evasion / hardening
        "av_bypass_engine",
        "log_tampering_engine",
        "anti_debug_evasion",
        "rootkit_simulation",
        "memory_forensics_evasion",
        // sensors
        "usb_enumeration",
        // UEBA — periodic baseline sample
        "ueba_baseline",
    ]
}

/// Dispatch a task to its detection.
pub fn run_detection(engine: &str, target: Option<&str>, params: &Value) -> DetectionFuture {
    let target = target.map(|s| s.to_string());
    let params = params.clone();
    let engine = engine.to_string();
    Box::pin(async move {
        match engine.as_str() {
            "process_hollowing" => process_hollowing::run(&engine).await,
            "dll_hijacking_engine" => process_modules::run_dll_hijacking(&engine).await,
            "process_inventory" => process_modules::run_inventory(&engine).await,
            "persistence_mechanism" => scheduled_tasks::run(&engine).await,
            "bootkit_uefi" => scheduled_tasks::run_uefi(&engine).await,
            "arp_spoofing_engine" => arp_table::run(&engine, target.as_deref(), &params).await,
            "dns_tunneling_c2" | "icmp_covert" => arp_table::run_dns_anomaly(&engine).await,
            "clipboard_hijack" | "screen_capture_exfil" | "insider_exfil" => {
                clipboard::run(&engine).await
            }
            "av_bypass_engine" => edr_presence::run(&engine).await,
            "log_tampering_engine" => log_integrity::run(&engine).await,
            "anti_debug_evasion" | "rootkit_simulation" | "memory_forensics_evasion" => {
                process_modules::run_unusual_runtime(&engine).await
            }
            "usb_enumeration" => usb_devices::run(&engine).await,
            "ueba_baseline" => baseline::run(&engine).await,
            other => Err(anyhow::anyhow!(
                "agent has no implementation for engine '{other}'"
            )),
        }
    })
}

/// Helper used by every detection to emit a finding with the standard envelope.
pub(crate) fn finding(
    engine: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    extras: serde_json::Map<String, Value>,
) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("type".into(), Value::String(engine.to_string()));
    obj.insert("title".into(), Value::String(title.to_string()));
    obj.insert("severity".into(), Value::String(severity.to_string()));
    obj.insert("mitre_attack".into(), Value::String(mitre.to_string()));
    obj.insert("description".into(), Value::String(description.to_string()));
    obj.insert("source".into(), Value::String("agent".into()));
    obj.insert(
        "remediation".into(),
        Value::String(default_remediation(engine, severity).to_string()),
    );
    for (k, v) in extras {
        obj.insert(k, v);
    }
    Value::Object(obj)
}

fn default_remediation(engine: &str, severity: &str) -> &'static str {
    let s = severity.to_ascii_lowercase();
    if engine.contains("hollow") {
        return "Isolate the host, capture a memory image (lime/winpmem), and run YARA + Volatility hollowfind plugin. Rotate any credentials available on the host.";
    }
    if engine.contains("dll_hijack") {
        return "Verify the loading module against its vendor signature, restore the canonical DLL from a known-good source, and revoke the abusive code path.";
    }
    if engine.contains("arp") {
        return "Pin the gateway MAC in OS arp cache, enable Dynamic ARP Inspection on access switches, and put the LAN behind 802.1x.";
    }
    if engine.contains("clipboard") {
        return "Audit Win32k clipboard hooks / CGEventTapCreate observers; enable Group Policy 'Restrict clipboard transfer' on sensitive endpoints.";
    }
    if engine.contains("usb") {
        return "Enforce USB allow-list policy (Intune/JAMF/MDM), block mass-storage class on workstations, monitor `udevadm monitor` events.";
    }
    if engine.contains("log") {
        return "Forward Windows event log / Linux journald to an immutable SIEM in real time; alert on EventID 1102 (audit log cleared).";
    }
    if engine.contains("av") || engine.contains("edr") {
        return "Run the official EDR health check (Defender 'Get-MpComputerStatus' / CrowdStrike 'rtr'), redeploy the agent if tampered, and require Tamper Protection.";
    }
    if engine.contains("uefi") {
        return "Verify SecureBoot + MeasuredBoot PCR values, apply firmware updates from the OEM, and enable BootGuard if available.";
    }
    if engine.contains("persistence") {
        return "Remove the unauthorised entry (schtasks/cron/launchd/systemd), block re-creation via Group Policy, and add a SOC alert for the same path.";
    }
    match s.as_str() {
        "critical" => "Treat as P0: contain the endpoint, capture forensics, rotate credentials.",
        "high" => "Fix within 7 days; deploy detection for the same indicator.",
        "medium" => "Plan a fix this sprint; document in the asset register.",
        "low" => "Track in backlog.",
        _ => "Investigate the observation in context.",
    }
}
