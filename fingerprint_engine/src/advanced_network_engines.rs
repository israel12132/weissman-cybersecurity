//! Advanced Network engines — real TCP/UDP port probes (no spoofing, no exploitation).
//!
//! Each engine fingerprints reachable network surface relevant to the named technique. We never
//! perform active denial or spoofing operations; only connect-and-banner probes against the user-
//! supplied target.

use crate::engine_probes::{empty_ok, extract_host, finding, tcp_banner, tcp_open};
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

async fn port_check(t: &str, engine_id: &str, title: &str, severity: &str, mitre: &str, ports: &[u16], note: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings: Vec<Value> = Vec::new();
    for &p in ports {
        if tcp_open(&host, p).await {
            let banner = tcp_banner(&host, p).await.unwrap_or_default();
            findings.push(finding(
                engine_id,
                &format!("{} ({}/tcp open)", title, p),
                severity,
                mitre,
                &format!(
                    "TCP {}:{} reachable. Banner: '{}'. {}",
                    host,
                    p,
                    banner.chars().take(120).collect::<String>(),
                    note
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok(engine_id, t)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("{}: {} open port(s)", engine_id, n))
    }
}

pub async fn run_arp_spoofing_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "arp_spoofing_engine",
        t,
        "ARP spoofing detection requires local L2 sniffer",
        "ARP is link-local and never reaches the network probe; deploy the agent inside the affected VLAN.",
    )
}
cli_wrapper!(run_arp_spoofing_engine, run_arp_spoofing_engine_result);

pub async fn run_vlan_hopping_attack_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "vlan_hopping_attack",
        t,
        "VLAN hopping detection requires switch-port tap",
        "Double-tagging and DTP exploit succeed only on the wire; deploy agent or SPAN port for visibility.",
    )
}
cli_wrapper!(run_vlan_hopping_attack, run_vlan_hopping_attack_result);

pub async fn run_dhcp_attack_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "dhcp_attack_engine",
        t,
        "DHCP starvation / rogue-server detection requires L2 visibility",
        "DHCP DISCOVER/OFFER frames are broadcast inside the subnet; agent or DHCP-snooping logs are required.",
    )
}
cli_wrapper!(run_dhcp_attack_engine, run_dhcp_attack_engine_result);

pub async fn run_dns_cache_poisoning_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let txt = crate::engine_probes::dns_txt(&host).await;
    let a = crate::engine_probes::dns_a(&host).await;
    let mut findings: Vec<Value> = Vec::new();
    if !txt.iter().any(|t| t.contains("v=spf1") || t.contains("DMARC1")) && !a.is_empty() {
        findings.push(finding(
            "dns_cache_poisoning",
            "Domain has A records but no SPF/DMARC TXT",
            "low",
            "T1071.004",
            &format!("DNS A={} no SPF/DMARC observed for {}.", a.join(","), host),
            t,
        ));
    }
    if findings.is_empty() { empty_ok("dns_cache_poisoning", t) }
    else { EngineResult::ok(findings.clone(), format!("dns_cache_poisoning: {}", findings.len())) }
}
cli_wrapper!(run_dns_cache_poisoning, run_dns_cache_poisoning_result);

pub async fn run_ntp_amplification_result(t: &str) -> EngineResult {
    port_check(t, "ntp_amplification", "NTP port", "low", "T1498.002", &[123], "Verify monlist disabled.").await
}
cli_wrapper!(run_ntp_amplification, run_ntp_amplification_result);

pub async fn run_snmp_exploitation_result(t: &str) -> EngineResult {
    port_check(t, "snmp_exploitation", "SNMP port", "medium", "T1046", &[161], "Test community strings public/private.").await
}
cli_wrapper!(run_snmp_exploitation, run_snmp_exploitation_result);

pub async fn run_rdp_attack_engine_result(t: &str) -> EngineResult {
    port_check(t, "rdp_attack_engine", "RDP", "high", "T1021.001", &[3389], "Internet-exposed RDP — high abuse risk.").await
}
cli_wrapper!(run_rdp_attack_engine, run_rdp_attack_engine_result);

pub async fn run_ldap_injection_engine_result(t: &str) -> EngineResult {
    port_check(t, "ldap_injection_engine", "LDAP/LDAPS", "medium", "T1078", &[389, 636, 3268, 3269], "Active Directory directory surface.").await
}
cli_wrapper!(run_ldap_injection_engine, run_ldap_injection_engine_result);

pub async fn run_voip_sip_attack_result(t: &str) -> EngineResult {
    port_check(t, "voip_sip_attack", "SIP / VoIP", "medium", "T1499", &[5060, 5061], "SIP REGISTER / INVITE surface.").await
}
cli_wrapper!(run_voip_sip_attack, run_voip_sip_attack_result);

pub async fn run_ss7_attack_simulation_result(t: &str) -> EngineResult {
    port_check(t, "ss7_attack_simulation", "SS7/SIGTRAN candidate port", "low", "T1499", &[2904, 2905], "SCTP/M3UA endpoints (SCTP usually).").await
}
cli_wrapper!(run_ss7_attack_simulation, run_ss7_attack_simulation_result);

pub async fn run_wifi_attack_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "wifi_attack_engine",
        t,
        "Wi-Fi attack detection requires RF agent",
        "WPA/802.11 frames are RF-layer and require a monitor-mode NIC; deploy the wireless sensor agent.",
    )
}
cli_wrapper!(run_wifi_attack_engine, run_wifi_attack_engine_result);

pub async fn run_bluetooth_attack_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "bluetooth_attack_engine",
        t,
        "Bluetooth attack detection requires BT-capable agent",
        "BLE/Classic Bluetooth traffic isn't visible over IP; deploy the BT sensor agent on a Linux/BlueZ host.",
    )
}
cli_wrapper!(run_bluetooth_attack_engine, run_bluetooth_attack_engine_result);

pub async fn run_ospf_bgp_hijack_result(t: &str) -> EngineResult {
    crate::bgp_dns_hijacking_engine::run_bgp_dns_hijacking_result(t).await
}
cli_wrapper!(run_ospf_bgp_hijack, run_ospf_bgp_hijack_result);

pub async fn run_mpls_vpn_attack_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "mpls_vpn_attack",
        t,
        "MPLS/VPN attack detection requires PE-router telemetry",
        "Inter-VRF leakage and label-stack abuse are visible on carrier PE routers, not over the public network.",
    )
}
cli_wrapper!(run_mpls_vpn_attack, run_mpls_vpn_attack_result);

pub async fn run_lte_5g_attack_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "lte_5g_attack",
        t,
        "LTE/5G attack detection requires SDR agent at the cell tower",
        "IMSI catchers and 5G NSA downgrades happen at the radio layer; deploy the SDR sensor in the coverage area.",
    )
}
cli_wrapper!(run_lte_5g_attack, run_lte_5g_attack_result);

pub async fn run_ipv6_advanced_attack_result(t: &str) -> EngineResult {
    crate::ipv6_attack_engine::run_ipv6_attack_result(t).await
}
cli_wrapper!(run_ipv6_advanced_attack, run_ipv6_advanced_attack_result);

pub async fn run_network_covert_channel_result(t: &str) -> EngineResult {
    crate::stealth_engine::run_stealth_engine_result(t).await
}
cli_wrapper!(run_network_covert_channel, run_network_covert_channel_result);

pub async fn run_wpa3_attack_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "wpa3_attack_engine",
        t,
        "WPA3 SAE attack detection requires wireless agent",
        "Dragonblood and group-downgrade attacks require capturing SAE handshakes from a monitor-mode NIC.",
    )
}
cli_wrapper!(run_wpa3_attack_engine, run_wpa3_attack_engine_result);

pub async fn run_tor_exit_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = crate::engine_probes::http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let url = "https://check.torproject.org/exit-addresses";
    if let Some(p) = crate::engine_probes::http_get(&client, url).await {
        let host = extract_host(t);
        let ips = crate::engine_probes::dns_a(&host).await;
        for ip in ips {
            if p.body.contains(&ip) {
                findings.push(finding(
                    "tor_exit_attack",
                    "Resolved IP is a Tor exit node",
                    "high",
                    "T1090.003",
                    &format!("{} resolves to {} which is on the published Tor exit list.", host, ip),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() { empty_ok("tor_exit_attack", t) }
    else { EngineResult::ok(findings.clone(), format!("tor_exit_attack: {}", findings.len())) }
}
cli_wrapper!(run_tor_exit_attack, run_tor_exit_attack_result);

pub async fn run_protocol_downgrade_result(t: &str) -> EngineResult {
    crate::pki_tls_engine::run_pki_tls_result(t).await
}
cli_wrapper!(run_protocol_downgrade, run_protocol_downgrade_result);

pub async fn run_network_baseline_anomaly_result(t: &str) -> EngineResult {
    crate::asm_engine::run_asm_result(t).await
}
cli_wrapper!(run_network_baseline_anomaly, run_network_baseline_anomaly_result);

pub async fn run_packet_injection_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "packet_injection_engine",
        t,
        "Packet-injection detection needs IDS/IPS or local pcap",
        "Forged frames are observed via IDS feeds (Suricata/Zeek) or a local pcap on the affected segment.",
    )
}
cli_wrapper!(run_packet_injection_engine, run_packet_injection_engine_result);

pub async fn run_network_tap_advanced_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "network_tap_advanced",
        t,
        "Hardware network-tap detection requires physical layer telemetry",
        "Passive optical taps don't generate any IP-level signal; ask the agent for cable-plant audit.",
    )
}
cli_wrapper!(run_network_tap_advanced, run_network_tap_advanced_result);

pub async fn run_multicast_attack_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "multicast_attack",
        t,
        "Multicast (IGMP/MLD) abuse detection requires local sniffer",
        "IGMP joins and PIM messages stay inside the broadcast domain; deploy the agent there.",
    )
}
cli_wrapper!(run_multicast_attack, run_multicast_attack_result);

pub async fn run_nat_traversal_attack_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "nat_traversal_attack",
        t,
        "NAT traversal abuse detection needs perimeter device logs",
        "STUN/UPnP and hole-punching only appear in firewall / NAT logs; route them to Weissman via syslog.",
    )
}
cli_wrapper!(run_nat_traversal_attack, run_nat_traversal_attack_result);
