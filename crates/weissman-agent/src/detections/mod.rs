//! Detection registry. Every entry returns a vector of finding objects identical in shape to
//! engine findings produced by the remote scan engines.

mod arp_table;
mod baseline;
mod chronos;
mod clipboard;
mod edr_presence;
mod exfil_local;
mod hardware_local;
mod infostealer;
mod log_integrity;
mod malware_local;
pub mod onboarding_exec_gate;
mod mobile_local;
mod network_local;
pub(crate) mod ot_plc_decoy;
mod priv_esc_cred;
mod process_hollowing;
mod process_modules;
mod scheduled_tasks;
mod social_local;
mod syscall_hooks;
mod timestomp;
mod usb_devices;
mod util;

use serde_json::Value;

pub type DetectionFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<Value>>> + Send>>;

/// All capability IDs advertised to the server at enrollment.
pub fn all_capability_ids() -> Vec<&'static str> {
    vec![
        // process / memory
        "process_hollowing",
        "dll_hijacking_engine",
        "process_inventory",
        "anti_debug_evasion",
        "rootkit_surface_probe",
        "memory_forensics_evasion",
        // persistence / malware
        "persistence_mechanism",
        "bootkit_uefi",
        "polymorphic_engine",
        "ransomware_emulation",
        // network (local)
        "arp_spoofing_engine",
        "dns_tunneling_c2",
        "icmp_covert",
        "vlan_hopping_attack",
        "dhcp_attack_engine",
        "wifi_attack_engine",
        "bluetooth_attack_engine",
        "lte_5g_attack",
        "wpa3_attack_engine",
        "packet_injection_engine",
        "network_tap_advanced",
        "multicast_attack",
        "nat_traversal_attack",
        // exfiltration
        "acoustic_exfil",
        "em_exfil_engine",
        "optical_exfil",
        "keyboard_acoustic",
        "screen_capture_exfil",
        "clipboard_hijack",
        "insider_exfil",
        "storage_covert_channel",
        // evasion / hardening
        "av_bypass_engine",
        "log_tampering_engine",
        "timestomping",
        // mobile / social
        "sim_swap_engine",
        "bluetooth_mobile_attack",
        "nfc_relay_attack",
        "deepfake_voice_engine",
        "pretexting_engine",
        "insider_threat_engine",
        "physical_social_eng",
        // OT / hardware
        "lorawan_attack",
        "lora_attack",
        "voltage_glitch_attack",
        "tpm_firmware_attack",
        "cold_boot_attack",
        // commodity infostealer blast-radius
        "infostealer_emulation",
        // Privilege escalation & credential access (host auditor — not agent-required)
        "privilege_escalation_credential_access",
        // sensors
        "usb_enumeration",
        // UEBA — periodic baseline sample
        "ueba_baseline",
        // CHRONOS — 5ms process-delta ring buffer + SIGSTOP on shell spawn
        "chronos",
        // Host-resident ntdll stub integrity (Hell's Gate / Halo's Gate)
        "syscall_evasion",
    ]
}

/// Start the OT/PLC decoy listener (host-resident deception).
pub fn spawn_ot_plc_decoy() {
    ot_plc_decoy::spawn();
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
            "polymorphic_engine" => malware_local::run_polymorphic(&engine).await,
            "ransomware_emulation" => malware_local::run_ransomware(&engine).await,
            "arp_spoofing_engine" => arp_table::run(&engine, target.as_deref(), &params).await,
            "dns_tunneling_c2" => arp_table::run_dns_anomaly(&engine).await,
            "icmp_covert" => network_local::run_icmp_covert(&engine).await,
            "vlan_hopping_attack" => network_local::run_vlan(&engine).await,
            "dhcp_attack_engine" => network_local::run_dhcp(&engine).await,
            "wifi_attack_engine" => network_local::run_wifi(&engine).await,
            "wpa3_attack_engine" => network_local::run_wpa3(&engine).await,
            "bluetooth_attack_engine" | "bluetooth_mobile_attack" => {
                network_local::run_bluetooth(&engine).await
            }
            "lte_5g_attack" => network_local::run_lte_5g(&engine).await,
            "multicast_attack" => network_local::run_multicast(&engine).await,
            "nat_traversal_attack" => network_local::run_nat_traversal(&engine).await,
            "packet_injection_engine" => network_local::run_packet_injection(&engine).await,
            "network_tap_advanced" => network_local::run_network_tap(&engine).await,
            "acoustic_exfil" => exfil_local::run_acoustic(&engine).await,
            "em_exfil_engine" => exfil_local::run_em_exfil(&engine).await,
            "optical_exfil" => exfil_local::run_optical(&engine).await,
            "keyboard_acoustic" => exfil_local::run_keyboard_acoustic(&engine).await,
            "screen_capture_exfil" => exfil_local::run_screen_capture(&engine).await,
            "clipboard_hijack" => clipboard::run(&engine).await,
            "insider_exfil" => social_local::run_insider_threat(&engine).await,
            "storage_covert_channel" => exfil_local::run_storage_covert(&engine).await,
            "av_bypass_engine" => edr_presence::run(&engine).await,
            "log_tampering_engine" => {
                let mut findings = log_integrity::run(&engine).await?;
                findings.extend(timestomp::run(&engine).await?);
                Ok(findings)
            }
            "timestomping" => timestomp::run(&engine).await,
            "anti_debug_evasion"
            | "rootkit_surface_probe"
            | "rootkit_simulation"
            | "memory_forensics_evasion" => process_modules::run_unusual_runtime(&engine).await,
            "usb_enumeration" => usb_devices::run(&engine).await,
            "sim_swap_engine" => mobile_local::run_sim_swap(&engine).await,
            "nfc_relay_attack" => mobile_local::run_nfc(&engine).await,
            "deepfake_voice_engine" => social_local::run_deepfake_voice(&engine).await,
            "pretexting_engine" => social_local::run_pretexting(&engine).await,
            "insider_threat_engine" => social_local::run_insider_threat(&engine).await,
            "physical_social_eng" => social_local::run_physical_social(&engine).await,
            "lorawan_attack" | "lora_attack" => hardware_local::run_lorawan(&engine).await,
            "voltage_glitch_attack" => hardware_local::run_voltage_glitch(&engine).await,
            "tpm_firmware_attack" => hardware_local::run_tpm(&engine).await,
            "cold_boot_attack" => hardware_local::run_cold_boot(&engine).await,
            "infostealer_emulation" => infostealer::run(&engine, target.as_deref(), &params).await,
            "privilege_escalation_credential_access" => priv_esc_cred::run(&engine).await,
            "ueba_baseline" => baseline::run(&engine).await,
            "chronos" => chronos::run(&engine, &params).await,
            "syscall_evasion" => syscall_hooks::run(&engine).await,
            "deception_honeypot" => ot_plc_decoy::run(&engine).await,
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

#[cfg(test)]
mod tests {
    use super::all_capability_ids;

    /// Every engine in fingerprint_engine::AGENT_REQUIRED_ENGINES must have an agent implementation.
    const REQUIRED: &[&str] = &[
        "process_hollowing",
        "dll_hijacking_engine",
        "process_inventory",
        "av_bypass_engine",
        "log_tampering_engine",
        "timestomping",
        "anti_debug_evasion",
        "rootkit_surface_probe",
        "memory_forensics_evasion",
        "usb_enumeration",
        "dns_tunneling_c2",
        "icmp_covert",
        "bootkit_uefi",
        "persistence_mechanism",
        "polymorphic_engine",
        "ransomware_emulation",
        "acoustic_exfil",
        "em_exfil_engine",
        "optical_exfil",
        "keyboard_acoustic",
        "screen_capture_exfil",
        "clipboard_hijack",
        "insider_exfil",
        "storage_covert_channel",
        "arp_spoofing_engine",
        "vlan_hopping_attack",
        "dhcp_attack_engine",
        "wifi_attack_engine",
        "bluetooth_attack_engine",
        "lte_5g_attack",
        "wpa3_attack_engine",
        "packet_injection_engine",
        "network_tap_advanced",
        "multicast_attack",
        "nat_traversal_attack",
        "sim_swap_engine",
        "bluetooth_mobile_attack",
        "nfc_relay_attack",
        "deepfake_voice_engine",
        "pretexting_engine",
        "insider_threat_engine",
        "physical_social_eng",
        "lorawan_attack",
        "lora_attack",
        "voltage_glitch_attack",
        "tpm_firmware_attack",
        "cold_boot_attack",
        "infostealer_emulation",
        "chronos",
    ];

    #[test]
    fn agent_covers_all_required_engines() {
        let caps: std::collections::HashSet<_> = all_capability_ids().into_iter().collect();
        for id in REQUIRED {
            assert!(caps.contains(id), "missing agent capability: {id}");
        }
    }
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
    if engine.contains("infostealer") {
        return "Rotate all browser/session credentials, invalidate OAuth refresh tokens, enforce FIDO2, and hunt for staging directories matching reported paths.";
    }
    if engine.contains("wifi") || engine.contains("wpa3") || engine.contains("bluetooth") {
        return "Disable unused radios via MDM, require WPA3-Enterprise + PMF, and segment wireless clients from sensitive VLANs.";
    }
    match s.as_str() {
        "critical" => "Treat as P0: contain the endpoint, capture forensics, rotate credentials.",
        "high" => "Fix within 7 days; deploy detection for the same indicator.",
        "medium" => "Plan a fix this sprint; document in the asset register.",
        "low" => "Track in backlog.",
        _ => "Investigate the observation in context.",
    }
}
