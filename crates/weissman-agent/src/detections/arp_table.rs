//! ARP table snapshot + DNS port anomaly detection (both local-network checks).

use super::finding;
use serde_json::{json, Value};

#[cfg(target_os = "linux")]
async fn read_arp_table() -> std::io::Result<Vec<(String, String, String)>> {
    let text = tokio::fs::read_to_string("/proc/net/arp").await?;
    let mut rows = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 6 {
            rows.push((
                cols[0].to_string(),
                cols[3].to_string(),
                cols[5].to_string(),
            ));
        }
    }
    Ok(rows)
}

#[cfg(not(target_os = "linux"))]
async fn read_arp_table() -> std::io::Result<Vec<(String, String, String)>> {
    // macOS / Windows: spawn the system `arp -a` command and parse its output. We avoid platform
    // crates for binary-size reasons.
    let output = tokio::process::Command::new("arp")
        .arg("-a")
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut rows = Vec::new();
    for line in stdout.lines() {
        // Format on macOS: "host (1.2.3.4) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
        let line = line.trim();
        if line.is_empty() || !line.contains(" at ") {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        let host = parts.get(0).copied().unwrap_or("");
        let ip = parts
            .get(1)
            .copied()
            .unwrap_or("")
            .trim_start_matches('(')
            .trim_end_matches(')')
            .to_string();
        let mac = line
            .split(" at ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("")
            .to_string();
        if !ip.is_empty() && !mac.is_empty() {
            rows.push((ip, host.to_string(), mac));
        }
    }
    Ok(rows)
}

pub async fn run(
    engine: &str,
    _target: Option<&str>,
    params: &Value,
) -> anyhow::Result<Vec<Value>> {
    let expected_mac = params
        .get("expected_gateway_mac")
        .and_then(Value::as_str)
        .map(|s| s.to_ascii_lowercase());

    let rows = match read_arp_table().await {
        Ok(r) => r,
        Err(e) => {
            return Ok(vec![finding(
                engine,
                "ARP table unreadable",
                "info",
                "T1557.002",
                &format!("ARP table could not be read on this host: {}", e),
                serde_json::Map::new(),
            )]);
        }
    };

    let mut findings = Vec::new();

    // Always emit an inventory finding (info) so SOC sees that the agent collected data.
    {
        let mut extras = serde_json::Map::new();
        extras.insert("entries".into(), json!(rows.len()));
        extras.insert(
            "sample".into(),
            Value::Array(
                rows.iter()
                    .take(20)
                    .map(|(ip, host, mac)| json!({"ip": ip, "hostname": host, "mac": mac}))
                    .collect(),
            ),
        );
        findings.push(finding(
            engine,
            &format!("ARP table snapshot: {} entries", rows.len()),
            "info",
            "T1557.002",
            "Agent enumerated the local ARP cache. Compare against the expected gateway MAC and known-good neighbours.",
            extras,
        ));
    }

    // If we know the expected gateway MAC, flag mismatches.
    if let Some(expected) = expected_mac {
        for (ip, _host, mac) in &rows {
            let mac_lc = mac.to_ascii_lowercase();
            // Heuristic: many gateways live at .1 / .254 — verify those first.
            if (ip.ends_with(".1") || ip.ends_with(".254")) && mac_lc != expected {
                let mut extras = serde_json::Map::new();
                extras.insert("ip".into(), Value::String(ip.clone()));
                extras.insert("observed_mac".into(), Value::String(mac_lc));
                extras.insert("expected_mac".into(), Value::String(expected.clone()));
                findings.push(finding(
                    engine,
                    "Gateway MAC differs from expected",
                    "critical",
                    "T1557.002",
                    &format!(
                        "Gateway candidate {} in ARP cache has MAC '{}'; tenant policy expects '{}'. Possible ARP spoofing / rogue gateway.",
                        ip, mac, expected
                    ),
                    extras,
                ));
            }
        }
    }

    Ok(findings)
}

pub async fn run_dns_anomaly(engine: &str) -> anyhow::Result<Vec<Value>> {
    // Look at /proc/net/{udp,tcp} on Linux for non-53 sockets owned by processes that look like
    // resolvers. Best-effort; on non-Linux we emit an info finding explaining the limitation.
    #[cfg(target_os = "linux")]
    {
        let udp = tokio::fs::read_to_string("/proc/net/udp")
            .await
            .unwrap_or_default();
        let tcp = tokio::fs::read_to_string("/proc/net/tcp")
            .await
            .unwrap_or_default();
        let mut suspicious = Vec::new();
        // Skip each file's OWN header row — `.skip(1)` on the *chained* iterator would only drop
        // /proc/net/udp's header and parse /proc/net/tcp's header line as data.
        for line in udp.lines().skip(1).chain(tcp.lines().skip(1)) {
            let col = line.split_whitespace().nth(2).unwrap_or("");
            // ip:port_hex; flag DNS-style traffic on non-standard ports.
            if let Some((_, port_hex)) = col.split_once(':') {
                if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                    // Exclude 5353 (mDNS/Bonjour) — it is a standard well-known DNS-family port and
                    // appears on essentially every LAN host, so flagging it is a pure false positive.
                    if port != 5353 && matches!(port, 5300..=5500 | 8053 | 10053 | 65353) {
                        suspicious.push(port);
                    }
                }
            }
        }
        if !suspicious.is_empty() {
            let mut extras = serde_json::Map::new();
            extras.insert("ports".into(), json!(suspicious));
            return Ok(vec![finding(
                engine,
                "DNS-like traffic on non-standard port",
                "medium",
                "T1071.004",
                &format!(
                    "Local socket inventory shows DNS-style traffic on {} non-standard port(s). Investigate for DNS tunnelling / covert-channel.",
                    suspicious.len()
                ),
                extras,
            )]);
        }
        return Ok(vec![]);
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(vec![finding(
            engine,
            "DNS port anomaly detection requires Linux /proc",
            "info",
            "T1071.004",
            "Agent runs on a non-Linux host; deploy on a Linux gateway to enumerate /proc/net/udp + /proc/net/tcp.",
            serde_json::Map::new(),
        )])
    }
}
