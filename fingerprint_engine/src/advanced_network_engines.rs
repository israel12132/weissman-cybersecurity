//! Advanced Network engines — real TCP/UDP port probes (no spoofing, no exploitation).
//!
//! Each engine fingerprints reachable network surface relevant to the named technique. We never
//! perform active denial or spoofing operations; only connect-and-banner probes against the user-
//! supplied target.

use crate::engine_probes::{
    dns_a, dns_a_min_ttl, dns_caa, dns_mx, dns_txt, empty_ok, extract_host, finding,
    finding_with_probe_depth, host_header_rebinding_signal, http_client, http_get,
    http_get_with_headers, join_url, normalize_url, status_indicates_presence, tcp_banner,
    tcp_open, tcp_probe_response, tcp_scan, udp_probe_response,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

const NETWORK_PROBE_DEPTH: &str = "network_protocol_surface";

fn net_finding(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
) -> Value {
    finding_with_probe_depth(
        engine_id,
        title,
        severity,
        mitre,
        description,
        target,
        NETWORK_PROBE_DEPTH,
    )
}

/// Valid NTP mode-4 (server) response to a client-mode request.
#[must_use]
fn ntp_mode4_response(resp: &[u8]) -> bool {
    resp.len() >= 48 && (resp[0] & 0x07) == 4
}

/// NTP mode-7 (private/control) response — monlist/amplification surface.
#[must_use]
fn ntp_mode7_response(resp: &[u8]) -> bool {
    resp.len() >= 4 && (resp[0] & 0x07) == 7
}

/// SNMP GET response for sysDescr.0 with community `public`.
#[must_use]
fn snmp_public_sysdescr_response(resp: &[u8]) -> bool {
    if resp.first() != Some(&0x30) {
        return false;
    }
    let has_sysdescr_oid = resp
        .windows(6)
        .any(|w| w == [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01]);
    if !has_sysdescr_oid {
        return false;
    }
    // Require printable sysDescr payload, not just ASN.1 framing.
    resp.iter().any(|b| b.is_ascii_graphic() && *b != b' ')
        && String::from_utf8_lossy(resp)
            .chars()
            .any(|c| c.is_alphabetic())
}

/// LDAP bind response that indicates the server answered (success or invalid credentials).
#[must_use]
fn ldap_bind_response(resp: &[u8]) -> bool {
    if resp.first() != Some(&0x30) || resp.len() < 7 {
        return false;
    }
    // LDAPMessage → bindResponse (0x61) or resultCode present in typical bind reply.
    resp.contains(&0x61)
        || resp
            .windows(3)
            .any(|w| w == [0x0a, 0x01, 0x00] || w == [0x0a, 0x01, 0x31])
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
    let txt = dns_txt(&host).await;
    let a = dns_a(&host).await;
    let mx = dns_mx(&host).await;
    let caa = dns_caa(&host).await;
    let mut findings: Vec<Value> = Vec::new();

    let has_spf = txt.iter().any(|r| r.contains("v=spf1"));
    let has_dmarc = dns_txt(&format!("_dmarc.{}", host))
        .await
        .iter()
        .any(|r| r.contains("DMARC1"));
    if !mx.is_empty() && (!has_spf || !has_dmarc) {
        findings.push(net_finding(
            "dns_cache_poisoning",
            "MX present without full email auth (SPF/DMARC)",
            "medium",
            "T1071.004",
            &format!(
                "MX={:?} for {} but SPF={} DMARC={}. Missing mail-auth records increase spoofing risk after DNS cache poisoning.",
                mx, host, has_spf, has_dmarc
            ),
            t,
        ));
    }

    if let Some(ttl) = dns_a_min_ttl(&host).await {
        if ttl <= 30 && caa.is_empty() && !a.is_empty() {
            findings.push(net_finding(
                "dns_cache_poisoning",
                &format!("Ultra-short A TTL ({}s) without CAA", ttl),
                "medium",
                "T1071.004",
                &format!(
                    "A records for {} advertise TTL {}s and no CAA records were observed — rapid TTL rotation eases cache-poisoning and fraudulent issuance.",
                    host, ttl
                ),
                t,
            ));
        }
    }

    if findings.is_empty() {
        empty_ok("dns_cache_poisoning", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("dns_cache_poisoning: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_dns_cache_poisoning, run_dns_cache_poisoning_result);

pub async fn run_dns_rebinding_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();

    let baseline = http_get_with_headers(&client, &url, &[]).await;
    let foreign =
        http_get_with_headers(&client, &url, &[("Host", "rebind.attacker.example")]).await;
    if let (Some(base), Some(forg)) = (baseline, foreign) {
        if host_header_rebinding_signal(base.status, forg.status, forg.body.len()) {
            findings.push(finding(
                "dns_rebinding",
                "Host header accepted for foreign hostname",
                "medium",
                "T1190",
                &format!(
                    "Request to {} with Host: rebind.attacker.example returned HTTP {} (baseline {}). This split-horizon behavior aids DNS rebinding against browser same-origin policy.",
                    url, forg.status, base.status
                ),
                t,
            ));
        }
    }

    if let Some(ttl) = dns_a_min_ttl(&host).await {
        if ttl <= 60 {
            findings.push(finding(
                "dns_rebinding",
                &format!("Short DNS A TTL ({}s)", ttl),
                "low",
                "T1190",
                &format!(
                    "A records for {} advertise TTL {}s — ultra-short TTLs ease DNS rebinding pivot windows; prefer TTL ≥ 300s on internet-facing names.",
                    host, ttl
                ),
                t,
            ));
        }
    }

    if findings.is_empty() {
        empty_ok("dns_rebinding", t)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("dns_rebinding: {} signal(s)", n))
    }
}
cli_wrapper!(run_dns_rebinding, run_dns_rebinding_result);

pub async fn run_can_bus_surface_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings: Vec<Value> = Vec::new();
    for (port, label) in [
        (13400u16, "DoIP (ISO 13400)"),
        (35000u16, "OBD/WiFi gateway"),
        (29536u16, "Vector CAN bridge"),
    ] {
        if !tcp_open(&host, port).await {
            continue;
        }
        let mut detail = format!("TCP {}:{} accepts connections.", host, port);
        if port == 13400 {
            let probe: [u8; 17] = [
                0x02, 0xFD, 0x00, 0x05, 0x00, 0x00, 0x00, 0x07, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00,
            ];
            if let Some(resp) = tcp_probe_response(&host, port, &probe).await {
                if resp.len() >= 4 && resp[0] == 0x02 && resp[1] == 0xFD {
                    detail.push_str(" DoIP protocol header echoed.");
                }
            }
        }
        findings.push(finding(
            "can_bus_surface",
            &format!("{} ({}/tcp open)", label, port),
            if port == 13400 { "high" } else { "medium" },
            "T0855",
            &format!(
                "{} Internet-exposed vehicle diagnostic surface — isolate CAN/DoIP behind VPN; CAN-FD gateways share this attack plane.",
                detail
            ),
            t,
        ));
    }
    if findings.is_empty() {
        empty_ok("can_bus_surface", t)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("can_bus_surface: {} open port(s)", n))
    }
}
cli_wrapper!(run_can_bus_surface, run_can_bus_surface_result);

pub async fn run_ntp_amplification_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings: Vec<Value> = Vec::new();
    let mut ntp_req = [0u8; 48];
    ntp_req[0] = 0x1b;
    if let Some(resp) = udp_probe_response(&host, 123, &ntp_req).await {
        if ntp_mode4_response(&resp) {
            findings.push(net_finding(
                "ntp_amplification",
                "NTP server responded to client mode probe",
                "low",
                "T1498.002",
                &format!(
                    "UDP {}:123 returned a valid NTP mode-4 response ({} B). Verify monlist/monitor (mode 7) is disabled on this daemon.",
                    host, resp.len()
                ),
                t,
            ));
        }
        // Mode 7 monlist probe — amplification only when control queries are enabled.
        let mut monlist_req = [0u8; 48];
        monlist_req[0] = 0x17; // mode 7, version 2
        if let Some(m7) = udp_probe_response(&host, 123, &monlist_req).await {
            if ntp_mode7_response(&m7) && m7.len() > 48 {
                findings.push(net_finding(
                    "ntp_amplification",
                    "NTP mode-7 control query answered (monlist risk)",
                    "high",
                    "T1498.002",
                    &format!(
                        "UDP {}:123 returned mode-7 response ({} B) — NTP control queries may enable amplification; disable mode 7 or restrict to management nets.",
                        host, m7.len()
                    ),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("ntp_amplification", t)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("ntp_amplification: {} signal(s)", n))
    }
}
cli_wrapper!(run_ntp_amplification, run_ntp_amplification_result);

pub async fn run_snmp_exploitation_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings: Vec<Value> = Vec::new();
    const SNMP_GET: &[u8] = &[
        0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19,
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0c, 0x30,
        0x0a, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x00, 0x05, 0x00,
    ];
    if let Some(resp) = udp_probe_response(&host, 161, SNMP_GET).await {
        if snmp_public_sysdescr_response(&resp) {
            findings.push(net_finding(
                "snmp_exploitation",
                "SNMP agent answered public community GET",
                "high",
                "T1046",
                &format!(
                    "UDP {}:161 returned SNMP sysDescr.0 data for community 'public' ({} B). Change community strings and restrict SNMP to management nets.",
                    host, resp.len()
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("snmp_exploitation", t)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("snmp_exploitation: {} signal(s)", n))
    }
}
cli_wrapper!(run_snmp_exploitation, run_snmp_exploitation_result);

pub async fn run_rdp_attack_engine_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings: Vec<Value> = Vec::new();
    if tcp_open(&host, 3389).await {
        if let Some(banner) = tcp_banner(&host, 3389).await {
            if banner.starts_with("\x03\x00") {
                findings.push(net_finding(
                    "rdp_attack_engine",
                    "RDP TPKT banner observed on 3389/tcp",
                    "high",
                    "T1021.001",
                    &format!(
                        "TCP {}:3389 returned Microsoft RDP TPKT header (0x03 0x00). Internet-exposed RDP is a top brute-force / CVE target — require VPN + NLA.",
                        host
                    ),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("rdp_attack_engine", t)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("rdp_attack_engine: {} signal(s)", n))
    }
}
cli_wrapper!(run_rdp_attack_engine, run_rdp_attack_engine_result);

pub async fn run_ldap_injection_engine_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings: Vec<Value> = Vec::new();
    const LDAP_BIND: &[u8] = &[
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
    ];
    for (port, label) in [(389u16, "LDAP"), (3268, "Global Catalog LDAP")] {
        if let Some(resp) = tcp_probe_response(&host, port, LDAP_BIND).await {
            if ldap_bind_response(&resp) {
                findings.push(net_finding(
                    "ldap_injection_engine",
                    &format!("{} bind response on {}/tcp", label, port),
                    "medium",
                    "T1078",
                    &format!(
                        "TCP {}:{} answered LDAP bind probe ({} B). Anonymous or misconfigured directory binds enable user enumeration — disable anon bind and require TLS.",
                        host, port, resp.len()
                    ),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("ldap_injection_engine", t)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("ldap_injection_engine: {} signal(s)", n))
    }
}
cli_wrapper!(run_ldap_injection_engine, run_ldap_injection_engine_result);

pub async fn run_voip_sip_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings: Vec<Value> = Vec::new();
    let sip_options = format!(
        "OPTIONS sip:probe@{host} SIP/2.0\r\nVia: SIP/2.0/TCP {host}:5060\r\nMax-Forwards: 70\r\nTo: <sip:probe@{host}>\r\nFrom: <sip:probe@{host}>\r\nCall-ID: weissman-probe\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
    );
    for port in [5060u16, 5061] {
        if let Some(resp) = tcp_probe_response(&host, port, sip_options.as_bytes()).await {
            let text = String::from_utf8_lossy(&resp);
            if text.contains("SIP/2.0") && text.contains("Allow:") {
                findings.push(net_finding(
                    "voip_sip_attack",
                    &format!("SIP OPTIONS answered on {}/tcp", port),
                    "medium",
                    "T1499",
                    &format!(
                        "TCP {}:{} returned SIP/2.0 with Allow: header — REGISTER/INVITE surface exposed. Restrict SIP to trusted SBCs.",
                        host, port
                    ),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("voip_sip_attack", t)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("voip_sip_attack: {} signal(s)", n))
    }
}
cli_wrapper!(run_voip_sip_attack, run_voip_sip_attack_result);

pub async fn run_ss7_signaling_probe_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();

    let mx = dns_mx(&host).await;
    for rec in mx.iter().take(5) {
        let low = rec.to_ascii_lowercase();
        if low.contains("sms")
            || low.contains("smpp")
            || low.contains("messaging")
            || low.contains("telco")
            || low.contains("mobile")
        {
            findings.push(net_finding(
                "ss7_signaling_probe",
                &format!("Telco/SMS MX candidate: {rec}"),
                "info",
                "T1557",
                &format!(
                    "MX record {rec} for {host} suggests SMS/messaging infrastructure — correlate with SS7/SIGTRAN PCAP from carrier gateway for MAP/HLR abuse validation."
                ),
                t,
            ));
        }
    }

    let ss7_ports = tcp_scan(&host, &[2775, 2905, 8080, 8443, 9090], 6).await;
    for port in ss7_ports {
        let svc = match port {
            2775 => "SMPP (SMS gateway)",
            2905 => "SS7/SIGTRAN management (vendor-specific)",
            _ => "Telco HTTP management",
        };
        findings.push(net_finding(
            "ss7_signaling_probe",
            &format!("{svc} port {port}/tcp open on {host}"),
            if port == 2775 { "high" } else { "medium" },
            "T1557",
            &format!(
                "Live TCP connect to {host}:{port} succeeded — {svc} surface in scope. Full MAP/SS7 abuse requires PCAP from SS7 gateway or telco sensor agent."
            ),
            t,
        ));
    }

    let base = normalize_url(t);
    for path in ["/smpp", "/ss7", "/sigtran", "/sms", "/api/sms", "/api/ss7"] {
        let url = join_url(&base, path);
        if let Some(p) = http_get(&client, &url).await {
            if status_indicates_presence(p.status) {
                findings.push(net_finding(
                    "ss7_signaling_probe",
                    "Telco signaling HTTP management path reachable",
                    "medium",
                    "T1557",
                    &format!(
                        "{} ({}) — review for exposed SMSC/SS7 admin interfaces; pair with carrier PCAP for live MAP validation.",
                        p.final_url, p.status
                    ),
                    t,
                ));
                break;
            }
        }
    }

    if findings.is_empty() {
        let finding = finding(
            "ss7_signaling_probe",
            "No internet-exposed SS7/SMPP surface observed",
            "info",
            "T1557",
            &format!(
                "Live DNS/TCP/HTTP probes against {host} found no SMPP (2775), telco MX, or SS7 mgmt paths. Ingest M3UA/SCTP PCAP from the SS7 gateway or deploy the telco sensor agent for MAP-layer validation."
            ),
            t,
        );
        return EngineResult::ok(
            vec![finding],
            format!("ss7_signaling_probe: perimeter clear — PCAP/agent required for {host}"),
        );
    }
    EngineResult::ok(
        findings.clone(),
        format!("ss7_signaling_probe: {} live telco surface signal(s)", findings.len()),
    )
}
cli_wrapper!(run_ss7_signaling_probe, run_ss7_signaling_probe_result);

/// Legacy CLI name — delegates to live probe (no simulated findings).
pub async fn run_ss7_attack_simulation_result(t: &str) -> EngineResult {
    run_ss7_signaling_probe_result(t).await
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
cli_wrapper!(
    run_bluetooth_attack_engine,
    run_bluetooth_attack_engine_result
);

pub async fn run_ospf_bgp_hijack_result(t: &str) -> EngineResult {
    crate::bgp_dns_hijacking_engine::run_bgp_dns_hijacking_result(t).await
}
cli_wrapper!(run_ospf_bgp_hijack, run_ospf_bgp_hijack_result);

pub async fn run_mpls_vpn_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let ips = dns_a(&host).await;
    if ips.is_empty() {
        return empty_ok("mpls_vpn_attack", t);
    }
    let mut findings: Vec<Value> = Vec::new();
    for ip in ips.iter().take(2) {
        let query = format!("-v {}\n", ip);
        if let Some(resp) = tcp_probe_response("whois.cymru.com", 43, query.as_bytes()).await {
            let text = String::from_utf8_lossy(&resp);
            let line = text.lines().find(|l| l.contains('|') && l.contains(ip));
            if let Some(line) = line {
                let parts: Vec<&str> = line.split('|').map(str::trim).collect();
                if parts.len() >= 7 {
                    let asn = parts[0];
                    let prefix = parts[1];
                    let cc = parts[2];
                    let owner = parts[5];
                    findings.push(net_finding(
                        "mpls_vpn_attack",
                        &format!("Origin ASN {} ({}) for {}", asn, owner, ip),
                        "info",
                        "T1090",
                        &format!(
                            "Team Cymru origin lookup for {} → ASN {} prefix {} country {} owner {}. Validate MPLS/VPN segregation with the carrier; cross-VRF injection is a provider-side control.",
                            ip, asn, prefix, cc, owner
                        ),
                        t,
                    ));
                }
            }
        }
    }
    if findings.is_empty() {
        empty_ok("mpls_vpn_attack", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("mpls_vpn_attack: {}", findings.len()),
        )
    }
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
    // Look for HTTP-header surface that's commonly abused as a covert channel: long X- headers,
    // base64-looking values, Server-Timing entries with random tokens. We already cover entropy
    // in http_covert_exfil; here we report the surface so the SOC can compare.
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = crate::engine_probes::http_client().await;
    let url = crate::engine_probes::normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = crate::engine_probes::http_get(&client, &url).await {
        let suspicious: Vec<&(String, String)> = p
            .headers
            .iter()
            .filter(|(k, v)| {
                let lk = k.to_lowercase();
                (lk.starts_with("x-") || lk.starts_with("server-timing")) && v.len() > 80
            })
            .collect();
        if !suspicious.is_empty() {
            let mut f = finding(
                "network_covert_channel",
                &format!("{} suspicious long headers", suspicious.len()),
                "low",
                "T1071",
                &format!(
                    "Response from {} contains {} unusually long custom headers. Long X-* values are a common covert-channel surface; verify they aren't carrying encoded data.",
                    p.final_url, suspicious.len()
                ),
                t,
            );
            if let Some(obj) = f.as_object_mut() {
                obj.insert(
                    "headers".into(),
                    serde_json::json!(suspicious
                        .iter()
                        .map(|(k, _)| k.clone())
                        .collect::<Vec<_>>()),
                );
            }
            findings.push(f);
        }
    }
    if findings.is_empty() {
        empty_ok("network_covert_channel", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("network_covert_channel: {}", findings.len()),
        )
    }
}
cli_wrapper!(
    run_network_covert_channel,
    run_network_covert_channel_result
);

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
                    &format!(
                        "{} resolves to {} which is on the published Tor exit list.",
                        host, ip
                    ),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("tor_exit_attack", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("tor_exit_attack: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_tor_exit_attack, run_tor_exit_attack_result);

pub async fn run_protocol_downgrade_result(t: &str) -> EngineResult {
    crate::pki_tls_engine::run_pki_tls_result(t).await
}
cli_wrapper!(run_protocol_downgrade, run_protocol_downgrade_result);

pub async fn run_network_baseline_anomaly_result(t: &str) -> EngineResult {
    // Real probe: rerun ASM + flag ports that aren't in the canonical hardened set. The
    // delta vs a documented baseline is what's anomalous.
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let asm = crate::asm_engine::run_asm_result(t).await;
    // Canonical hardened ports per OWASP ASVS L1 — anything else is anomalous on an internet-
    // facing host.
    let canonical: std::collections::HashSet<u16> =
        [80, 443, 22, 25, 53, 110, 143, 465, 587, 993, 995]
            .iter()
            .copied()
            .collect();
    let anomalies: Vec<Value> = asm
        .findings
        .iter()
        .filter_map(|f| {
            f.get("port")
                .and_then(Value::as_u64)
                .map(|p| p as u16)
                .filter(|p| !canonical.contains(p))
                .map(|port| {
                    finding(
                        "network_baseline_anomaly",
                        &format!("Non-canonical port open: {}", port),
                        "low",
                        "T1046",
                        &format!(
                            "Port {} is open but not in the OWASP-recommended hardened set for internet-facing hosts. Document the use case or close the port.",
                            port
                        ),
                        t,
                    )
                })
        })
        .collect();
    if anomalies.is_empty() {
        empty_ok("network_baseline_anomaly", t)
    } else {
        let n = anomalies.len();
        EngineResult::ok(
            anomalies,
            format!("network_baseline_anomaly: {} anomaly", n),
        )
    }
}
cli_wrapper!(
    run_network_baseline_anomaly,
    run_network_baseline_anomaly_result
);

pub async fn run_packet_injection_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "packet_injection_engine",
        t,
        "Packet-injection detection needs IDS/IPS or local pcap",
        "Forged frames are observed via IDS feeds (Suricata/Zeek) or a local pcap on the affected segment.",
    )
}
cli_wrapper!(
    run_packet_injection_engine,
    run_packet_injection_engine_result
);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_probes::host_header_rebinding_signal;

    #[test]
    fn rebinding_host_signal_requires_foreign_success() {
        assert!(host_header_rebinding_signal(404, 200, 128));
        assert!(!host_header_rebinding_signal(200, 200, 128));
    }

    #[test]
    fn ntp_mode4_and_mode7_parsing() {
        let mut mode4 = [0u8; 48];
        mode4[0] = 0x24;
        assert!(ntp_mode4_response(&mode4));
        assert!(!ntp_mode4_response(&[0u8; 8]));

        let mut mode7 = [0u8; 64];
        mode7[0] = 0x17;
        assert!(ntp_mode7_response(&mode7));
    }

    #[test]
    fn snmp_requires_sysdescr_oid_and_printable_payload() {
        let bare_asn = [0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x00];
        assert!(!snmp_public_sysdescr_response(&bare_asn));
    }

    #[test]
    fn ldap_bind_response_requires_bind_reply_marker() {
        assert!(!ldap_bind_response(&[0x30, 0x03, 0x02, 0x01, 0x01]));
        assert!(ldap_bind_response(&[
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07
        ]));
    }
}
