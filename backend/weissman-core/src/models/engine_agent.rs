//! Endpoint-agent engine taxonomy — canonical list of host-resident engines.
//!
//! Single source of truth for CI audits (`verify_engine_wiring.mjs`, `engine_reality_audit.mjs`),
//! runtime capability badges, and worker dispatch classification.

/// Engines whose detection must run on an enrolled endpoint agent (not from a remote probe alone).
pub const AGENT_REQUIRED_ENGINES: &[&str] = &[
    // Stealth / EDR (host-only observation)
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
    // Malware / persistence
    "bootkit_uefi",
    "persistence_mechanism",
    "polymorphic_engine",
    "ransomware_emulation",
    // Data exfiltration
    "acoustic_exfil",
    "em_exfil_engine",
    "optical_exfil",
    "keyboard_acoustic",
    "screen_capture_exfil",
    "clipboard_hijack",
    "insider_exfil",
    "storage_covert_channel",
    // Network / wireless
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
    // Mobile
    "sim_swap_engine",
    "bluetooth_mobile_attack",
    "nfc_relay_attack",
    // Social engineering
    "deepfake_voice_engine",
    "pretexting_engine",
    "insider_threat_engine",
    "physical_social_eng",
    // OT / physical bus-level
    "lorawan_attack",
    "lora_attack",
    "voltage_glitch_attack",
    "tpm_firmware_attack",
    "cold_boot_attack",
    // Host-resident collector
    "infostealer_emulation",
    // NOTE: chronos is NOT agent-only — server hybrid runs via chronos_engine
];

/// True when `id` must dispatch to the endpoint agent fleet for host-resident collection.
#[must_use]
pub fn is_agent_required_engine(id: &str) -> bool {
    AGENT_REQUIRED_ENGINES.iter().any(|&k| k == id.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_required_list_is_non_empty_and_unique() {
        assert!(AGENT_REQUIRED_ENGINES.len() >= 40);
        let mut seen = std::collections::HashSet::new();
        for id in AGENT_REQUIRED_ENGINES {
            assert!(seen.insert(*id), "duplicate agent engine id: {id}");
        }
    }

    #[test]
    fn process_inventory_and_usb_are_agent_only() {
        assert!(is_agent_required_engine("process_inventory"));
        assert!(is_agent_required_engine("usb_enumeration"));
        assert!(!is_agent_required_engine("liquid_matrix"));
    }
}
