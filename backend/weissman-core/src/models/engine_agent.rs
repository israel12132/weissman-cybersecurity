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
    "sandbox_evasion",
    "rop_chain_engine",
    "heap_exploitation",
    "jit_spray",
    "com_hijacking",
    "parent_pid_spoof",
    "host_isolation",
    "host_privilege_escalation",
    "ebpf_sensor",
    "ioc_yara_hunt",
];

/// True when `id` must dispatch to the endpoint agent fleet for host-resident collection.
#[must_use]
pub fn is_agent_required_engine(id: &str) -> bool {
    AGENT_REQUIRED_ENGINES.iter().any(|&k| k == id.trim())
}

/// Dual-control / RoE-gated host engines — never auto-attached.
pub const SWARM_ATTACH_SKIP: &[&str] = &["host_isolation", "ransomware_emulation"];

/// Extra live host detections implemented on the agent but not in AGENT_REQUIRED_ENGINES.
pub const SWARM_ATTACH_EXTRAS: &[(&str, &str)] = &[
    ("chronos", "scan"),
    ("ot_plc_decoy", "findings"),
    ("stealthy_persistence_evasion", "findings"),
];

/// Classify a host engine for swarm-attach (attack / scan / findings).
#[must_use]
pub fn swarm_attach_category(id: &str) -> &'static str {
    match id.trim() {
        "process_hollowing"
        | "dll_hijacking_engine"
        | "anti_debug_evasion"
        | "rootkit_surface_probe"
        | "memory_forensics_evasion"
        | "dns_tunneling_c2"
        | "icmp_covert"
        | "arp_spoofing_engine"
        | "vlan_hopping_attack"
        | "dhcp_attack_engine"
        | "wifi_attack_engine"
        | "bluetooth_attack_engine"
        | "lte_5g_attack"
        | "wpa3_attack_engine"
        | "packet_injection_engine"
        | "network_tap_advanced"
        | "multicast_attack"
        | "nat_traversal_attack"
        | "parent_pid_spoof"
        | "rop_chain_engine"
        | "heap_exploitation"
        | "jit_spray"
        | "polymorphic_engine"
        | "lorawan_attack"
        | "lora_attack"
        | "voltage_glitch_attack"
        | "tpm_firmware_attack"
        | "cold_boot_attack" => "attack",
        "process_inventory"
        | "persistence_mechanism"
        | "bootkit_uefi"
        | "usb_enumeration"
        | "av_bypass_engine"
        | "log_tampering_engine"
        | "timestomping"
        | "ebpf_sensor"
        |         "ioc_yara_hunt"
        | "chronos"
        | "stealthy_persistence_evasion" => "scan",
        _ => "findings",
    }
}

/// Every agent-required engine except destructive skips, plus extras.
#[must_use]
pub fn swarm_attach_pack() -> Vec<(&'static str, &'static str)> {
    let mut out: Vec<(&'static str, &'static str)> = AGENT_REQUIRED_ENGINES
        .iter()
        .filter(|id| !SWARM_ATTACH_SKIP.contains(id))
        .map(|id| (*id, swarm_attach_category(id)))
        .collect();
    for extra in SWARM_ATTACH_EXTRAS {
        if !out.iter().any(|(e, _)| *e == extra.0) {
            out.push(*extra);
        }
    }
    out
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

    #[test]
    fn swarm_attach_pack_has_zero_gaps_against_agent_required() {
        let pack = swarm_attach_pack();
        let mut seen = std::collections::HashSet::new();
        for (engine, cat) in &pack {
            assert!(seen.insert(*engine), "duplicate pack engine {engine}");
            assert!(
                matches!(*cat, "attack" | "scan" | "findings"),
                "{engine} category {cat}"
            );
            assert!(!SWARM_ATTACH_SKIP.contains(engine));
        }
        for id in AGENT_REQUIRED_ENGINES {
            if SWARM_ATTACH_SKIP.contains(id) {
                assert!(!seen.contains(id), "skip {id} leaked into pack");
            } else {
                assert!(
                    seen.contains(id),
                    "gap: agent-required {id} missing from pack"
                );
            }
        }
        for (extra, _) in SWARM_ATTACH_EXTRAS {
            assert!(seen.contains(extra), "extra {extra} missing from pack");
        }
        assert_eq!(
            pack.len(),
            AGENT_REQUIRED_ENGINES.len() - SWARM_ATTACH_SKIP.len() + SWARM_ATTACH_EXTRAS.len()
        );
    }
}
