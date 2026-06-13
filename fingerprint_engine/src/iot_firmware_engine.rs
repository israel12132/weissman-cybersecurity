//! IoT / embedded-device firmware exposure mapper.
//!
//! Real fingerprinting of internet-facing embedded devices: identifies the embedded
//! web server / vendor from live `Server` headers, Basic-auth realms, and body markers,
//! maps each to its publicly-exploited CVE, scans the IoT-specific TCP ports
//! (Telnet / TR-069 / RTSP / ADB / DVR), and flags credential-prompting management
//! interfaces. Only emits a finding when a real response confirms the device —
//! no "body contains the word password" guessing.

use crate::engine_probes::{
    extract_host, header_value, http_client, normalize_url, probe_paths_concurrent,
    status_indicates_presence, tcp_banner, tcp_scan, HttpProbe, DEFAULT_PROBE_CONCURRENCY,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

/// An embedded-device signature: vendor/server tokens → exploited CVE.
struct DeviceSig {
    vendor: &'static str,
    tokens: &'static [&'static str],
    cve: &'static str,
    severity: &'static str,
}

const DEVICE_SIGS: &[DeviceSig] = &[
    DeviceSig { vendor: "Allegro RomPager", tokens: &["rompager", "allegro-software"], cve: "Misfortune Cookie CVE-2014-9222", severity: "high" },
    DeviceSig { vendor: "GoAhead embedded web server", tokens: &["goahead"], cve: "CVE-2017-8225 / CVE-2021-42342 RCE", severity: "high" },
    DeviceSig { vendor: "Boa web server (EOL)", tokens: &["server: boa", "boa/0."], cve: "Boa EOL chain (CVE-2017-9097)", severity: "high" },
    DeviceSig { vendor: "Hikvision device", tokens: &["hikvision", "app-webs", "dvrdvs"], cve: "CVE-2021-36260 unauthenticated RCE", severity: "critical" },
    DeviceSig { vendor: "Dahua device", tokens: &["dahua", "mvweb"], cve: "CVE-2021-33044 auth bypass", severity: "critical" },
    DeviceSig { vendor: "MikroTik RouterOS", tokens: &["routeros", "mikrotik"], cve: "CVE-2018-14847 Winbox path traversal", severity: "high" },
    DeviceSig { vendor: "D-Link HNAP", tokens: &["hnap", "d-link", "dlink"], cve: "HNAP command injection (CVE-2015-2051 family)", severity: "high" },
    DeviceSig { vendor: "Netgear router", tokens: &["netgear"], cve: "CVE-2016-6277 / CVE-2017-5521", severity: "high" },
    DeviceSig { vendor: "Zyxel device", tokens: &["zyxel"], cve: "CVE-2020-29583 hardcoded credentials", severity: "high" },
    DeviceSig { vendor: "DrayTek Vigor", tokens: &["draytek", "vigor"], cve: "CVE-2020-8515 unauthenticated RCE", severity: "high" },
    DeviceSig { vendor: "TP-Link device", tokens: &["tp-link", "tplink"], cve: "TP-Link router CVE family (CVE-2020-9374)", severity: "medium" },
    DeviceSig { vendor: "Ubiquiti airOS", tokens: &["airos", "ubnt", "ubiquiti"], cve: "airOS arbitrary file upload", severity: "medium" },
    DeviceSig { vendor: "AVTECH DVR", tokens: &["avtech"], cve: "AVTECH unauthenticated RCE", severity: "high" },
    DeviceSig { vendor: "mini_httpd (embedded)", tokens: &["mini_httpd"], cve: "EOL embedded HTTP server", severity: "low" },
    DeviceSig { vendor: "lighttpd (embedded)", tokens: &["lighttpd"], cve: "verify version against known CVEs", severity: "low" },
];

/// Embedded-device management paths (probed concurrently).
const DEVICE_PATHS: &[&str] = &[
    "/",
    "/login.cgi",
    "/cgi-bin/luci",
    "/cgi-bin/home.cgi",
    "/goform/",
    "/HNAP1/",
    "/api/system",
    "/api/device-info",
    "/api/firmware",
    "/upgrade.cgi",
    "/setup.cgi",
    "/doc/page/login.asp",
    "/system.html",
    "/status.html",
    "/login.asp",
    "/onvif/device_service",
];

/// IoT-specific TCP ports and the exposure each represents.
const IOT_PORTS: &[(u16, &str, &str)] = &[
    (23, "Telnet", "high"),
    (2323, "Telnet (alt / Mirai)", "high"),
    (7547, "TR-069 CWMP remote management", "high"),
    (554, "RTSP video stream", "medium"),
    (5555, "Android Debug Bridge (ADB)", "high"),
    (37777, "Dahua DVR proprietary", "high"),
    (9999, "Embedded admin", "medium"),
];

fn iot_finding(title: &str, severity: &str, mitre: &str, description: &str, target: &str) -> Value {
    json!({
        "type": "iot_firmware",
        "title": title,
        "severity": severity,
        "mitre_attack": mitre,
        "description": description,
        "target": target,
        "probe_depth": "embedded_device_surface",
    })
}

/// Build a lower-cased haystack from a probe's Server header, WWW-Authenticate, and body.
fn probe_haystack(p: &HttpProbe) -> String {
    let server = header_value(&p.headers, "server").unwrap_or_default();
    let www = header_value(&p.headers, "www-authenticate").unwrap_or_default();
    format!("server: {}\n{}\n{}", server, www, p.body).to_ascii_lowercase()
}

pub async fn run_iot_firmware_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let host = extract_host(target);
    let mut findings: Vec<Value> = Vec::new();
    let mut matched_vendors: Vec<&'static str> = Vec::new();

    // 1. Probe device management paths and fingerprint the embedded vendor.
    let probes = probe_paths_concurrent(&client, &url, DEVICE_PATHS, DEFAULT_PROBE_CONCURRENCY).await;
    for p in &probes {
        if !status_indicates_presence(p.status) {
            continue;
        }
        let haystack = probe_haystack(p);
        for sig in DEVICE_SIGS {
            if matched_vendors.contains(&sig.vendor) {
                continue;
            }
            if let Some(tok) = sig.tokens.iter().find(|t| haystack.contains(&t.to_ascii_lowercase())) {
                matched_vendors.push(sig.vendor);
                findings.push(iot_finding(
                    &format!("Embedded device identified: {}", sig.vendor),
                    sig.severity,
                    "T1190",
                    &format!(
                        "{} fingerprinted at {} (HTTP {}; matched '{}'). Publicly-exploited weakness: {}. Embedded/IoT devices are rarely patched — isolate from the internet and update firmware.",
                        sig.vendor, p.final_url, p.status, tok, sig.cve
                    ),
                    target,
                ));
            }
        }

        // 2. Credential-prompting management interface (Basic-auth realm).
        if let Some(www) = header_value(&p.headers, "www-authenticate") {
            let wl = www.to_ascii_lowercase();
            if wl.starts_with("basic") {
                findings.push(iot_finding(
                    &format!("Basic-auth management interface exposed: {}", p.final_url),
                    "high",
                    "T1078.001",
                    &format!(
                        "{} returns HTTP 401 with Basic authentication ({}). Internet-facing embedded admin panels are prime default-credential / brute-force targets — restrict access and change factory credentials.",
                        p.final_url, www
                    ),
                    target,
                ));
            }
        }
    }

    // 3. IoT-specific TCP ports (with banner evidence on Telnet).
    let ports: Vec<u16> = IOT_PORTS.iter().map(|&(p, ..)| p).collect();
    for port in tcp_scan(&host, &ports, 16).await {
        if let Some(&(_, name, sev)) = IOT_PORTS.iter().find(|&&(p, ..)| p == port) {
            let mut desc = format!(
                "{}/tcp ({}) is reachable on {} — a classic IoT botnet (Mirai-class) and remote-management exposure. Block at the perimeter.",
                port, name, host
            );
            if matches!(port, 23 | 2323) {
                if let Some(banner) = tcp_banner(&host, port).await {
                    let b = banner.trim();
                    if !b.is_empty() {
                        let snip: String = b.chars().take(80).collect();
                        desc.push_str(&format!(" Telnet banner: '{}'.", snip.replace('\n', " ")));
                    }
                }
            }
            findings.push(iot_finding(
                &format!("IoT service exposed: {} ({}/tcp)", name, port),
                sev,
                "T1133",
                &desc,
                target,
            ));
        }
    }

    if findings.is_empty() {
        return EngineResult::ok(
            vec![],
            format!("iot_firmware: no embedded-device surface observed on {}", host),
        );
    }
    let n = findings.len();
    EngineResult::ok(findings, format!("iot_firmware: {} embedded-device finding(s)", n))
}

pub async fn run_iot_firmware(target: &str) {
    print_result(run_iot_firmware_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn haystack_includes_server_and_body() {
        let p = HttpProbe {
            status: 200,
            headers: vec![("Server".to_string(), "GoAhead-Webs".to_string())],
            body: "<title>IP Camera</title>".to_string(),
            final_url: "https://cam.test/".to_string(),
        };
        let h = probe_haystack(&p);
        assert!(h.contains("goahead"));
        assert!(h.contains("ip camera"));
    }

    #[test]
    fn device_sigs_cover_major_vendors() {
        assert!(DEVICE_SIGS.iter().any(|s| s.vendor.contains("Hikvision")));
        assert!(DEVICE_SIGS.iter().any(|s| s.vendor.contains("MikroTik")));
        assert!(DEVICE_SIGS.iter().all(|s| !s.cve.is_empty()));
    }

    #[tokio::test]
    async fn empty_target_errors() {
        assert!(!run_iot_firmware_result("").await.success);
    }
}
