//! Local network / wireless / protocol-surface collectors for agent-required network engines.
//!
//! Read-only host telemetry: enumerates Wi-Fi/BT/cellular interfaces, DHCP lease state, VLAN
//! tagging, multicast membership, NAT-traversal helpers, promiscuous/tap devices, and raw-socket
//! capability — the same observables an attacker would recon before launching local attacks.

use super::finding;
use super::util::{any_process_matches, dir_entry_names, path_exists, run_cmd, run_cmd_lossy};
use serde_json::{json, Map, Value};

pub async fn run_wifi(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let mut networks: Vec<Value> = Vec::new();
    let mut interfaces: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Some(out) = run_cmd("iw", &["dev"]).await {
            for line in out.lines() {
                if let Some(iface) = line.trim().strip_prefix("Interface ") {
                    interfaces.push(iface.to_string());
                }
            }
        }
        if let Some(out) = run_cmd_lossy(
            "nmcli",
            &["-t", "-f", "SSID,SECURITY,SIGNAL,BSSID", "dev", "wifi"],
        )
        .await
        {
            for line in out.lines().take(40) {
                let cols: Vec<&str> = line.split(':').collect();
                if cols.len() >= 3 {
                    networks.push(json!({
                        "ssid": cols[0],
                        "security": cols.get(1).unwrap_or(&""),
                        "signal": cols.get(2).unwrap_or(&""),
                        "bssid": cols.get(3).unwrap_or(&""),
                    }));
                }
            }
        }
        for iface in dir_entry_names("/sys/class/net").await {
            if path_exists(&format!("/sys/class/net/{iface}/wireless")).await {
                interfaces.push(iface);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(out) = run_cmd_lossy("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", &["-s"]).await {
            for line in out.lines().skip(1).take(30) {
                networks.push(json!({"scan_line": line.trim()}));
            }
        }
        if let Some(out) = run_cmd_lossy("networksetup", &["-listallhardwareports"]).await {
            for line in out.lines() {
                if line.contains("Device:") {
                    if let Some(dev) = line.split(':').nth(1) {
                        interfaces.push(dev.trim().to_string());
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_cmd_lossy("netsh", &["wlan", "show", "networks", "mode=bssid"]).await
        {
            for line in out.lines().take(50) {
                if line.contains("SSID")
                    || line.contains("Authentication")
                    || line.contains("Signal")
                {
                    networks.push(json!({"line": line.trim()}));
                }
            }
        }
        if let Some(out) = run_cmd_lossy("netsh", &["wlan", "show", "interfaces"]).await {
            for line in out.lines() {
                if line.trim_start().starts_with("Name") {
                    if let Some(n) = line.split(':').nth(1) {
                        interfaces.push(n.trim().to_string());
                    }
                }
            }
        }
    }

    let mut extras = Map::new();
    extras.insert("wireless_interfaces".into(), json!(interfaces));
    extras.insert("visible_networks".into(), json!(networks.len()));
    extras.insert(
        "network_sample".into(),
        json!(networks.iter().take(15).collect::<Vec<_>>()),
    );
    findings.push(finding(
        engine,
        &format!(
            "Wireless reconnaissance: {} interface(s), {} visible network(s)",
            interfaces.len(),
            networks.len()
        ),
        if networks.iter().any(|n| {
            n.get("security")
                .and_then(Value::as_str)
                .is_some_and(|s| s.contains("OPEN") || s.eq_ignore_ascii_case("none") || s.is_empty())
        }) {
            "high"
        } else if !networks.is_empty() {
            "medium"
        } else {
            "info"
        },
        "T1557.002",
        "Agent enumerated local wireless interfaces and nearby SSIDs. Open or weak-security networks in range expand evil-twin / rogue-AP attack surface.",
        extras,
    ));

    Ok(findings)
}

pub async fn run_wpa3(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = run_wifi(engine).await?;
    let mut wpa3_capable = false;
    let mut wpa2_only = false;

    #[cfg(target_os = "linux")]
    {
        if let Some(out) = run_cmd_lossy("iw", &["list"]).await {
            wpa3_capable = out.contains("SAE") || out.contains("OWE");
            wpa2_only = out.contains("WPA2") && !wpa3_capable;
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_cmd_lossy("netsh", &["wlan", "show", "networks", "mode=bssid"]).await
        {
            wpa3_capable = out.to_ascii_uppercase().contains("WPA3");
            wpa2_only = out.to_ascii_uppercase().contains("WPA2") && !wpa3_capable;
        }
    }

    if wpa3_capable {
        let mut extras = Map::new();
        extras.insert("wpa3_support".into(), json!(true));
        findings.push(finding(
            engine,
            "Host Wi-Fi stack advertises WPA3 (SAE/OWE) capability",
            "info",
            "T1557.002",
            "Wireless driver/firmware supports WPA3 — verify transition-mode downgrade protections and PMF (802.11w) enforcement.",
            extras,
        ));
    }
    if wpa2_only {
        findings.push(finding(
            engine,
            "Wi-Fi stack lacks WPA3 — downgrade / dragonblood-class surface",
            "medium",
            "T1557.002",
            "Observed WPA2-only wireless capability on this host. Attackers can force clients onto legacy cipher suites when transition mode is enabled.",
            Map::new(),
        ));
    }
    Ok(findings)
}

pub async fn run_bluetooth(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let mut devices: Vec<Value> = Vec::new();
    let mut adapter_up = false;

    if let Some(out) = run_cmd_lossy("bluetoothctl", &["devices"]).await {
        for line in out.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == "Device" {
                devices.push(json!({"mac": parts[1], "name": parts[2..].join(" ")}));
            }
        }
    }
    if let Some(out) = run_cmd_lossy("hciconfig", &[]).await {
        adapter_up = out.contains("UP RUNNING");
    }

    let mut extras = Map::new();
    extras.insert("adapter_up".into(), json!(adapter_up));
    extras.insert("paired_devices".into(), json!(devices.len()));
    extras.insert(
        "device_sample".into(),
        json!(devices.iter().take(10).collect::<Vec<_>>()),
    );
    findings.push(finding(
        engine,
        &format!(
            "Bluetooth surface: adapter {} — {} paired/bonded device(s)",
            if adapter_up { "UP" } else { "DOWN" },
            devices.len()
        ),
        if adapter_up && !devices.is_empty() {
            "medium"
        } else if adapter_up {
            "low"
        } else {
            "info"
        },
        "T1557.002",
        "Agent inventoried Bluetooth adapter state and bonded devices. Active adapters enable BlueBorne/KNOB/BLE relay pivoting from this endpoint.",
        extras,
    ));
    Ok(findings)
}

pub async fn run_dhcp(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let mut gateways: Vec<String> = Vec::new();
    let mut lease_server: Option<String> = None;

    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = tokio::fs::read_to_string("/proc/net/route").await {
            for line in text.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 3 && cols[1] == "00000000" {
                    if let Ok(gw) = u32::from_str_radix(cols[2], 16) {
                        gateways.push(format!(
                            "{}.{}.{}.{}",
                            gw & 0xff,
                            (gw >> 8) & 0xff,
                            (gw >> 16) & 0xff,
                            (gw >> 24) & 0xff
                        ));
                    }
                }
            }
        }
        for path in [
            "/var/lib/dhcp/dhclient.leases",
            "/var/lib/NetworkManager/internal-dhcp4.leases",
        ] {
            if let Ok(text) = tokio::fs::read_to_string(path).await {
                for line in text.lines() {
                    if line.contains("dhcp-server-identifier")
                        || line.contains("option dhcp-server-identifier")
                    {
                        lease_server = line
                            .split_whitespace()
                            .last()
                            .map(|s| s.trim_end_matches(';').to_string());
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_cmd_lossy("ipconfig", &["/all"]).await {
            for line in out.lines() {
                if line.contains("Default Gateway") {
                    if let Some(gw) = line.split(':').nth(1) {
                        let g = gw.trim();
                        if !g.is_empty() {
                            gateways.push(g.to_string());
                        }
                    }
                }
                if line.contains("DHCP Server") {
                    lease_server = line.split(':').nth(1).map(|s| s.trim().to_string());
                }
            }
        }
    }

    let unique_gw: std::collections::HashSet<_> = gateways.iter().cloned().collect();
    let mut extras = Map::new();
    extras.insert(
        "default_gateways".into(),
        json!(unique_gw.iter().collect::<Vec<_>>()),
    );
    extras.insert("dhcp_server".into(), json!(lease_server));
    findings.push(finding(
        engine,
        &format!("DHCP/gateway inventory: {} default gateway(s)", unique_gw.len()),
        if unique_gw.len() > 1 {
            "critical"
        } else {
            "info"
        },
        "T1557.003",
        "Agent captured default-gateway and DHCP-server identifiers. Multiple gateways or an unexpected DHCP server are strong rogue-DHCP / MitM indicators.",
        extras,
    ));
    Ok(findings)
}

pub async fn run_vlan(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let mut vlans: Vec<String> = Vec::new();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if let Some(out) = run_cmd_lossy("ip", &["-d", "link", "show", "type", "vlan"]).await {
            for line in out.lines() {
                if line.contains("vlan") || line.contains("@") {
                    vlans.push(line.trim().to_string());
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        for name in dir_entry_names("/proc/net/vlan").await {
            if name != "config" {
                vlans.push(name);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_cmd_lossy(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status | Format-List",
            ],
        )
        .await
        {
            for line in out.lines().take(30) {
                if line.to_ascii_lowercase().contains("vlan")
                    || line.to_ascii_lowercase().contains("trunk")
                {
                    vlans.push(line.trim().to_string());
                }
            }
        }
    }

    let mut extras = Map::new();
    extras.insert("vlan_interfaces".into(), json!(vlans));
    findings.push(finding(
        engine,
        &format!("802.1Q VLAN tagging: {} tagged interface(s)", vlans.len()),
        if vlans.is_empty() { "info" } else { "medium" },
        "T1599.001",
        "Agent enumerated VLAN-tagged interfaces. Double-tagging / switch-hop tradecraft requires trunk or native-VLAN misconfiguration — verify switch port modes.",
        extras,
    ));
    Ok(findings)
}

pub async fn run_lte_5g(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let mut modems: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        for name in dir_entry_names("/sys/class/net").await {
            if name.starts_with("wwan") || name.starts_with("rmnet") || name.contains("usb") {
                modems.push(name);
            }
        }
        if let Some(out) = run_cmd_lossy("mmcli", &["-L"]).await {
            for line in out.lines().skip(1) {
                modems.push(line.trim().to_string());
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_cmd_lossy("netsh", &["mbn", "show", "interfaces"]).await {
            modems.extend(
                out.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .take(20)
                    .map(str::to_string),
            );
        }
    }

    let mut extras = Map::new();
    extras.insert("cellular_interfaces".into(), json!(modems));
    findings.push(finding(
        engine,
        &format!("Cellular modem surface: {} interface(s)/modem(s)", modems.len()),
        if modems.is_empty() { "info" } else { "medium" },
        "T1557.002",
        "Agent detected cellular/WWAN interfaces. IMSI-catcher / fake-BTS attacks target these modems when firmware lacks mutual authentication.",
        extras,
    ));
    Ok(findings)
}

pub async fn run_multicast(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let mut groups: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = tokio::fs::read_to_string("/proc/net/igmp").await {
            groups.extend(
                text.lines()
                    .skip(1)
                    .filter_map(|l| l.split_whitespace().nth(1))
                    .map(str::to_string)
                    .take(30),
            );
        }
        if let Some(out) = run_cmd_lossy("ip", &["maddr", "show"]).await {
            for line in out.lines().filter(|l| l.contains("inet")) {
                groups.push(line.trim().to_string());
            }
        }
    }

    let mut extras = Map::new();
    extras.insert("multicast_groups".into(), json!(groups.len()));
    extras.insert(
        "sample".into(),
        json!(groups.iter().take(15).collect::<Vec<_>>()),
    );
    findings.push(finding(
        engine,
        &format!("Multicast membership: {} group(s)", groups.len()),
        if groups.len() > 5 { "medium" } else { "info" },
        "T1071.001",
        "Agent enumerated IGMP/multicast subscriptions. Excessive group membership can indicate mDNS/SSDP abuse or multicast tunneling.",
        extras,
    ));
    Ok(findings)
}

pub async fn run_nat_traversal(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let upnp_hits = any_process_matches(&["miniupnpd", "upnp", "nat-pmp", "stun", "turnserver"]);
    let mut listening: Vec<u16> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = tokio::fs::read_to_string("/proc/net/tcp").await {
            for line in text.lines().skip(1) {
                if let Some(port_hex) = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.split(':').nth(1))
                {
                    if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                        if matches!(port, 1900 | 5351 | 3478 | 5349) {
                            listening.push(port);
                        }
                    }
                }
            }
        }
    }

    let mut extras = Map::new();
    extras.insert("upnp_related_processes".into(), json!(upnp_hits));
    extras.insert("nat_helper_ports".into(), json!(listening));
    findings.push(finding(
        engine,
        "NAT traversal / UPnP surface inventory",
        if !upnp_hits.is_empty() || !listening.is_empty() { "medium" } else { "info" },
        "T1090.002",
        "Agent checked for UPnP/NAT-PMP/STUN helpers (ports 1900/5351/3478). These services enable punch-through that bypasses perimeter controls.",
        extras,
    ));
    Ok(findings)
}

pub async fn run_packet_injection(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let capture_tools = any_process_matches(&[
        "tcpdump",
        "wireshark",
        "dumpcap",
        "tshark",
        "npcap",
        "scapy",
    ]);
    let mut promisc: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        for iface in dir_entry_names("/sys/class/net").await {
            if let Ok(flags) =
                tokio::fs::read_to_string(format!("/sys/class/net/{iface}/flags")).await
            {
                if let Ok(f) = flags.trim().parse::<u32>() {
                    // IFF_PROMISC = 0x100
                    if f & 0x100 != 0 {
                        promisc.push(iface);
                    }
                }
            }
        }
    }

    let mut extras = Map::new();
    extras.insert("capture_tools_running".into(), json!(capture_tools));
    extras.insert("promiscuous_interfaces".into(), json!(promisc));
    findings.push(finding(
        engine,
        &format!(
            "Raw capture surface: {} promiscuous iface(s), {} capture tool(s)",
            promisc.len(),
            capture_tools.len()
        ),
        if !promisc.is_empty() || !capture_tools.is_empty() { "medium" } else { "info" },
        "T1557.002",
        "Agent inventoried promiscuous NICs and active packet-capture tooling — prerequisites for ARP/DNS injection and passive tap tradecraft.",
        extras,
    ));
    Ok(findings)
}

pub async fn run_network_tap(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let mut taps: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        for name in dir_entry_names("/sys/class/net").await {
            if name.starts_with("tap") || name.starts_with("tun") {
                taps.push(name);
            }
        }
    }
    let bridge_tools =
        any_process_matches(&["tcpdump", "dumpcap", "netsniff-ng", "dsniff", "ettercap"]);

    let mut extras = Map::new();
    extras.insert("tap_tun_interfaces".into(), json!(taps));
    extras.insert("sniffing_tools".into(), json!(bridge_tools));
    findings.push(finding(
        engine,
        &format!("Network tap / bridge surface: {} tun/tap, {} sniff tool(s)", taps.len(), bridge_tools.len()),
        if !taps.is_empty() || !bridge_tools.is_empty() { "high" } else { "info" },
        "T1557.002",
        "Agent detected virtual tap/tun interfaces and passive sniffing tools — indicators of inline interception or span-port emulation on this host.",
        extras,
    ));
    Ok(findings)
}

pub async fn run_icmp_covert(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let mut icmp_sockets = 0usize;
        if let Ok(text) = tokio::fs::read_to_string("/proc/net/icmp").await {
            icmp_sockets = text.lines().skip(1).count();
        }
        let ping_procs = any_process_matches(&["ping", "hping", "nping", "icmpsh"]);
        let mut extras = Map::new();
        extras.insert("icmp_stats_entries".into(), json!(icmp_sockets));
        extras.insert("icmp_tools".into(), json!(ping_procs));
        findings.push(finding(
            engine,
            &format!("ICMP channel inventory: {} /proc/net/icmp entries", icmp_sockets),
            if !ping_procs.is_empty() { "medium" } else { "info" },
            "T1095",
            "Agent sampled kernel ICMP statistics and ICMP-capable tooling. Covert ICMP tunnels often correlate with non-standard payload sizes and persistent raw sockets.",
            extras,
        ));
    }

    #[cfg(not(target_os = "linux"))]
    {
        findings.push(finding(
            engine,
            "ICMP covert-channel stats require Linux /proc/net/icmp",
            "info",
            "T1095",
            "Deploy agent on Linux gateway or enable extended ETW on Windows for ICMP payload-size baselines.",
            Map::new(),
        ));
    }
    Ok(findings)
}
