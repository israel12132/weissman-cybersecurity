//! IoT / embedded-device firmware exposure mapper (agentless).
//!
//! Live probes only: firmware artifact discovery (HEAD/GET + magic bytes), management
//! port banners, UPnP SSDP, SNMP public community, IoT web UI fingerprinting, RTSP
//! surfaces, factory-default credential hints visible in login HTML, vendor/version
//! extraction from observed headers/bodies, posture score, and toxic-combination paths.

use crate::engine_probes::{
    extract_host, header_value, http_client, join_url, normalize_url, probe_paths_concurrent,
    status_indicates_presence, tcp_banner, tcp_scan, udp_probe_response, HttpProbe,
    DEFAULT_PROBE_CONCURRENCY,
};
use crate::engine_result::{print_result, EngineResult};
use reqwest::Client;
use serde_json::{json, Value};

/// Vendor fingerprint tokens observed in Server headers / HTML bodies.
struct VendorSig {
    vendor: &'static str,
    tokens: &'static [&'static str],
    severity: &'static str,
}

const VENDOR_SIGS: &[VendorSig] = &[
    VendorSig {
        vendor: "MikroTik RouterOS",
        tokens: &["routeros", "mikrotik", "webfig"],
        severity: "high",
    },
    VendorSig {
        vendor: "TP-Link",
        tokens: &["tp-link", "tplink", "tl-w", "archer"],
        severity: "medium",
    },
    VendorSig {
        vendor: "Ubiquiti airOS",
        tokens: &["airos", "ubnt", "ubiquiti", "unifi"],
        severity: "medium",
    },
    VendorSig {
        vendor: "Hikvision",
        tokens: &["hikvision", "app-webs", "dvrdvs", "isapi"],
        severity: "critical",
    },
    VendorSig {
        vendor: "Dahua",
        tokens: &["dahua", "dvrip", "realmonitor"],
        severity: "critical",
    },
    VendorSig {
        vendor: "Allegro RomPager",
        tokens: &["rompager", "allegro-software"],
        severity: "high",
    },
    VendorSig {
        vendor: "GoAhead embedded web server",
        tokens: &["goahead"],
        severity: "high",
    },
    VendorSig {
        vendor: "Boa web server (EOL)",
        tokens: &["server: boa", "boa/0."],
        severity: "high",
    },
    VendorSig {
        vendor: "D-Link",
        tokens: &["hnap", "d-link", "dlink"],
        severity: "high",
    },
    VendorSig {
        vendor: "Netgear",
        tokens: &["netgear"],
        severity: "high",
    },
    VendorSig {
        vendor: "Zyxel",
        tokens: &["zyxel"],
        severity: "high",
    },
    VendorSig {
        vendor: "DrayTek Vigor",
        tokens: &["draytek", "vigor"],
        severity: "high",
    },
    VendorSig {
        vendor: "AVTECH DVR",
        tokens: &["avtech"],
        severity: "high",
    },
];

/// Embedded management / login paths (GET).
const DEVICE_PATHS: &[&str] = &[
    "/",
    "/login.cgi",
    "/cgi-bin/luci",
    "/cgi-bin/home.cgi",
    "/goform/",
    "/HNAP1/",
    "/api/system",
    "/api/device-info",
    "/setup.cgi",
    "/doc/page/login.asp",
    "/system.html",
    "/status.html",
    "/login.asp",
    "/webfig/",
    "/web/login",
];

/// Firmware artifact paths probed via HEAD then GET prefix.
const FIRMWARE_PATHS: &[&str] = &[
    "/firmware",
    "/update",
    "/upgrade",
    "/download",
    "/api/firmware",
    "/cgi-bin/",
    "/firmware.bin",
    "/firmware.img",
    "/firmware.trx",
    "/firmware.chk",
    "/update.bin",
    "/update.img",
    "/update.trx",
    "/update.chk",
    "/upgrade.bin",
    "/upgrade.img",
    "/download.bin",
    "/download.img",
    "/router.bin",
    "/backup.bin",
];

/// Camera / RTSP-related HTTP surfaces.
const RTSP_HTTP_PATHS: &[&str] = &[
    "/Streaming/Channels/101",
    "/onvif/device_service",
    "/cgi-bin/mjpg/video.cgi",
    "/cam/realmonitor?channel=1&subtype=0",
    "/axis-cgi/mjpg/video.cgi",
    "/videostream.cgi",
    "/api/rtsp",
    "/ISAPI/Streaming/channels/101",
];

/// Management ports: Telnet, SSH, FTP, TFTP, alternates.
const MGMT_PORTS: &[(u16, &str, &str)] = &[
    (23, "Telnet", "high"),
    (2323, "Telnet (alternate)", "high"),
    (22, "SSH", "medium"),
    (2222, "SSH (alternate)", "medium"),
    (21, "FTP", "high"),
    (69, "TFTP", "high"),
    (554, "RTSP", "medium"),
];

const SNMP_PUBLIC_GET: &[u8] = &[
    0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
    0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0c, 0x30, 0x0a, 0x06,
    0x06, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x00, 0x05, 0x00,
];

const SSDP_MSEARCH: &[u8] = b"\
M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 2\r\n\
ST: ssdp:all\r\n\
\r\n";

struct ExposureLedger {
    telnet: bool,
    ssh: bool,
    ftp: bool,
    tftp: bool,
    firmware_download: bool,
    no_tls: bool,
    snmp_public: bool,
    upnp: bool,
    default_cred_hint: bool,
    critical: u32,
    high: u32,
    medium: u32,
}

impl ExposureLedger {
    fn new(no_tls: bool) -> Self {
        Self {
            telnet: false,
            ssh: false,
            ftp: false,
            tftp: false,
            firmware_download: false,
            no_tls,
            snmp_public: false,
            upnp: false,
            default_cred_hint: false,
            critical: 0,
            high: 0,
            medium: 0,
        }
    }

    fn bump_sev(&mut self, sev: &str) {
        match sev {
            "critical" => self.critical += 1,
            "high" => self.high += 1,
            "medium" => self.medium += 1,
            _ => {}
        }
    }
}

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

fn probe_haystack(p: &HttpProbe) -> String {
    let server = header_value(&p.headers, "server").unwrap_or_default();
    let www = header_value(&p.headers, "www-authenticate").unwrap_or_default();
    format!("server: {}\n{}\n{}", server, www, p.body).to_ascii_lowercase()
}

#[must_use]
fn content_type_is_firmware(ct: &str) -> bool {
    let ct = ct.to_ascii_lowercase();
    ct.contains("application/octet-stream")
        || ct.contains("application/firmware")
        || ct.contains("application/x-trx")
        || ct.contains("application/x-img")
        || (ct.starts_with("application/") && ct.contains("octet"))
}

#[must_use]
fn firmware_magic_label(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x7fELF") {
        return Some("ELF");
    }
    if bytes.len() >= 4 && bytes[0..4] == [0x27, 0x05, 0x19, 0x56] {
        return Some("uImage");
    }
    if bytes.starts_with(b"HDR0") {
        return Some("TRX");
    }
    if bytes.starts_with(b"hsqs") || bytes.starts_with(b"sqsh") {
        return Some("Squashfs");
    }
    None
}

#[must_use]
fn is_firmware_artifact(ct: Option<&str>, bytes: &[u8]) -> Option<&'static str> {
    if let Some(ct) = ct {
        if content_type_is_firmware(ct) {
            return firmware_magic_label(bytes).or(Some("application/octet-stream"));
        }
    }
    firmware_magic_label(bytes)
}

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
    resp.iter().any(|b| b.is_ascii_graphic() && *b != b' ')
        && String::from_utf8_lossy(resp)
            .chars()
            .any(|c| c.is_alphabetic())
}

#[must_use]
fn ssdp_response_valid(resp: &[u8]) -> bool {
    let s = String::from_utf8_lossy(resp);
    let sl = s.to_ascii_lowercase();
    sl.contains("http/1.1")
        && (sl.contains("location:") || sl.contains("st:") || sl.contains("server:"))
}

#[must_use]
fn is_login_surface(path: &str, body: &str) -> bool {
    let pl = path.to_ascii_lowercase();
    let bl = body.to_ascii_lowercase();
    let path_login = pl.contains("login")
        || pl.contains("auth")
        || pl.ends_with("login.asp")
        || pl.ends_with("login.cgi");
    let form_login = bl.contains("type=\"password\"")
        || bl.contains("type='password'")
        || bl.contains("name=\"password\"")
        || bl.contains("loginform");
    path_login || form_login
}

#[must_use]
fn factory_default_cred_hint(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    b.contains("admin/admin")
        || b.contains("default password")
        || b.contains("factory default")
        || b.contains("default username")
        || b.contains("default login")
        || b.contains("default credentials")
}

#[must_use]
fn extract_version_token(haystack: &str) -> Option<String> {
    for marker in [
        "firmware version",
        "software version",
        "version:",
        "fw version",
        "routeros ",
        "v",
    ] {
        if let Some(idx) = haystack.to_ascii_lowercase().find(marker) {
            let tail = &haystack[idx + marker.len()..];
            let trimmed = tail.trim_start_matches([':', ' ', 'v', 'V']);
            let ver: String = trimmed
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-' || *c == '_')
                .collect();
            if ver.len() >= 3 && ver.chars().filter(|c| c.is_ascii_digit()).count() >= 2 {
                return Some(ver);
            }
        }
    }
    None
}

#[must_use]
fn extract_server_version(server: &str) -> Option<String> {
    let parts: Vec<&str> = server.split_whitespace().collect();
    for part in parts.iter().skip(1) {
        let ver: String = part
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
            .collect();
        if ver.len() >= 3 && ver.contains('.') {
            return Some(ver);
        }
    }
    None
}

async fn http_head_probe(
    client: &Client,
    url: &str,
) -> Option<(u16, Vec<(String, String)>, String)> {
    let resp = client.head(url).send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    Some((status, headers, final_url))
}

async fn http_get_bytes_prefix(
    client: &Client,
    url: &str,
    max: usize,
) -> Option<(u16, Vec<(String, String)>, Vec<u8>, String)> {
    let resp = client.get(url).send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let bytes = resp.bytes().await.ok()?;
    let n = bytes.len().min(max);
    Some((status, headers, bytes[..n].to_vec(), final_url))
}

fn tftp_rrq_packet() -> Vec<u8> {
    let mut pkt = vec![0x00, 0x01];
    pkt.extend_from_slice(b"firmware.bin");
    pkt.push(0);
    pkt.extend_from_slice(b"octet");
    pkt.push(0);
    pkt
}

#[must_use]
fn tftp_response_valid(resp: &[u8]) -> bool {
    resp.len() >= 2 && (resp[0] == 0x00 && (resp[1] == 0x03 || resp[1] == 0x05))
}

#[must_use]
fn service_banner_matches(port: u16, banner: &str) -> bool {
    let b = banner.trim();
    match port {
        22 | 2222 => b.starts_with("SSH-"),
        21 => b.starts_with("220"),
        23 | 2323 => !b.is_empty(),
        554 => b.starts_with("RTSP/"),
        _ => !b.is_empty(),
    }
}

fn posture_score(ledger: &ExposureLedger) -> u32 {
    let mut score: i32 = 100;
    if ledger.telnet {
        score -= 25;
    }
    if ledger.firmware_download {
        score -= 20;
    }
    if ledger.no_tls {
        score -= 15;
    }
    if ledger.snmp_public {
        score -= 15;
    }
    if ledger.ftp {
        score -= 12;
    }
    if ledger.tftp {
        score -= 12;
    }
    if ledger.upnp {
        score -= 8;
    }
    if ledger.default_cred_hint {
        score -= 10;
    }
    if ledger.ssh {
        score -= 5;
    }
    score -= (ledger.critical * 8).min(24) as i32;
    score -= (ledger.high * 4).min(20) as i32;
    score -= (ledger.medium * 2).min(10) as i32;
    score.clamp(0, 100) as u32
}

fn posture_grade(score: u32) -> &'static str {
    match score {
        95..=100 => "A+",
        90..=94 => "A",
        85..=89 => "A-",
        80..=84 => "B+",
        75..=79 => "B",
        70..=74 => "B-",
        65..=69 => "C+",
        60..=64 => "C",
        55..=59 => "C-",
        50..=54 => "D",
        _ => "F",
    }
}

fn synthesize_toxic_paths(ledger: &ExposureLedger, target: &str, host: &str) -> Option<Value> {
    let mut combos: Vec<String> = Vec::new();
    if ledger.telnet && ledger.firmware_download && ledger.no_tls {
        combos.push(
            "Telnet + cleartext firmware download over HTTP — unauthenticated remote shell and full image retrieval without TLS"
                .to_string(),
        );
    }
    if ledger.snmp_public && ledger.telnet {
        combos.push(
            "SNMP public community + Telnet — device inventory disclosure paired with interactive shell"
                .to_string(),
        );
    }
    if ledger.firmware_download && ledger.ftp {
        combos.push(
            "Firmware HTTP download + FTP — multiple unauthenticated file-transfer paths to the same image"
                .to_string(),
        );
    }
    if ledger.upnp && ledger.default_cred_hint {
        combos.push(
            "UPnP device descriptor + login page factory-default hint — discoverable management UI with documented default credentials"
                .to_string(),
        );
    }
    if combos.is_empty() {
        return None;
    }
    Some(iot_finding(
        &format!("IoT toxic combination: {} chained path(s) on {}", combos.len(), host),
        "critical",
        "T1190",
        &format!(
            "Observed exposures chain into high-impact paths on {}: {}. Isolate from the internet, disable legacy services, and enforce TLS on management.",
            host,
            combos.join(" | ")
        ),
        target,
    ))
}

async fn probe_firmware_artifacts(
    client: &Client,
    base: &str,
    target: &str,
    findings: &mut Vec<Value>,
    ledger: &mut ExposureLedger,
) {
    for path in FIRMWARE_PATHS {
        let url = join_url(base, path);
        let head = http_head_probe(client, &url).await;
        let head_ct = head
            .as_ref()
            .and_then(|(_, h, _)| header_value(h, "content-type"));
        let head_status = head.as_ref().map(|(s, _, _)| *s).unwrap_or(0);
        let head_ok = head.is_some();

        let should_get = head_ct.is_some_and(content_type_is_firmware)
            || matches!(head_status, 200 | 206 | 405)
            || !head_ok;
        let get = if should_get {
            http_get_bytes_prefix(client, &url, 512).await
        } else {
            None
        };

        let (status, headers, bytes, final_url) = if let Some((s, h, b, u)) = get {
            (s, h, b, u)
        } else if let Some((s, h, u)) = head {
            if !status_indicates_presence(s) {
                continue;
            }
            (s, h, Vec::new(), u)
        } else {
            continue;
        };

        if !status_indicates_presence(status) {
            continue;
        }

        let ct = header_value(&headers, "content-type");
        let label = is_firmware_artifact(ct, &bytes);
        if label.is_none() {
            continue;
        }

        ledger.firmware_download = true;
        let sev = "critical";
        ledger.bump_sev(sev);
        findings.push(iot_finding(
            &format!("Firmware artifact exposed: {}", final_url),
            sev,
            "T1190",
            &format!(
                "HTTP {} returned firmware-class content at {} (Content-Type: {}; magic/format: {}). Internet-facing firmware images enable reverse-engineering and supply-chain replay — remove public access.",
                status,
                final_url,
                ct.unwrap_or("(none)"),
                label.unwrap_or("binary")
            ),
            target,
        ));
    }
}

async fn probe_udp_services(
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    ledger: &mut ExposureLedger,
) {
    if let Some(resp) = udp_probe_response(host, 1900, SSDP_MSEARCH).await {
        if ssdp_response_valid(&resp) {
            ledger.upnp = true;
            let sev = "medium";
            ledger.bump_sev(sev);
            let snip: String = String::from_utf8_lossy(&resp).chars().take(200).collect();
            findings.push(iot_finding(
                &format!("UPnP SSDP responder on {}:1900/udp", host),
                sev,
                "T1046",
                &format!(
                    "M-SEARCH to UDP {}:1900 returned a UPnP device descriptor ({} B). SSDP exposes model/location URLs for IoT enumeration — restrict multicast/broadcast and disable UPnP on edge devices. Snippet: {}",
                    host,
                    resp.len(),
                    snip.replace('\r', " ").replace('\n', " ")
                ),
                target,
            ));
        }
    }

    if let Some(resp) = udp_probe_response(host, 161, SNMP_PUBLIC_GET).await {
        if snmp_public_sysdescr_response(&resp) {
            ledger.snmp_public = true;
            let sev = "high";
            ledger.bump_sev(sev);
            findings.push(iot_finding(
                &format!("SNMP public community readable on {}:161/udp", host),
                sev,
                "T1046",
                &format!(
                    "UDP {}:161 answered SNMP sysDescr.0 for community 'public' ({} B). Change community strings, prefer SNMPv3, and restrict to management networks.",
                    host,
                    resp.len()
                ),
                target,
            ));
        }
    }

    if let Some(resp) = udp_probe_response(host, 69, &tftp_rrq_packet()).await {
        if tftp_response_valid(&resp) {
            ledger.tftp = true;
            let sev = "high";
            ledger.bump_sev(sev);
            findings.push(iot_finding(
                &format!("TFTP service responded on {}:69/udp", host),
                sev,
                "T1133",
                &format!(
                    "UDP {}:69 returned a TFTP DATA/ERROR opcode in response to RRQ — firmware/config retrieval may be possible without authentication. Block TFTP at the perimeter.",
                    host
                ),
                target,
            ));
        }
    }
}

async fn probe_mgmt_ports(
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
    ledger: &mut ExposureLedger,
) {
    let ports: Vec<u16> = MGMT_PORTS.iter().map(|&(p, ..)| p).collect();
    for port in tcp_scan(host, &ports, 12).await {
        if port == 69 {
            continue;
        }
        let Some(&(_, name, sev)) = MGMT_PORTS.iter().find(|&&(p, ..)| p == port) else {
            continue;
        };
        match port {
            23 | 2323 => ledger.telnet = true,
            22 | 2222 => ledger.ssh = true,
            21 => ledger.ftp = true,
            _ => {}
        }
        ledger.bump_sev(sev);
        let mut desc = format!(
            "{}/tcp ({}) is reachable on {} — classic IoT/embedded management exposure. Block at the perimeter unless explicitly required.",
            port, name, host
        );
        if let Some(banner) = tcp_banner(host, port).await {
            let b = banner.trim();
            if service_banner_matches(port, b) {
                let snip: String = b.chars().take(120).collect();
                desc.push_str(&format!(" Banner: '{}'.", snip.replace('\n', " ")));
            }
        }
        findings.push(iot_finding(
            &format!("IoT management service exposed: {} ({}/tcp)", name, port),
            sev,
            "T1133",
            &desc,
            target,
        ));
    }
}

pub async fn run_iot_firmware_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let host = extract_host(target);
    let no_tls = url.starts_with("http://");
    let mut findings: Vec<Value> = Vec::new();
    let mut ledger = ExposureLedger::new(no_tls);
    let mut matched_vendors: Vec<&'static str> = Vec::new();

    probe_firmware_artifacts(&client, &url, target, &mut findings, &mut ledger).await;

    let probes =
        probe_paths_concurrent(&client, &url, DEVICE_PATHS, DEFAULT_PROBE_CONCURRENCY).await;
    for p in &probes {
        if !status_indicates_presence(p.status) {
            continue;
        }
        let haystack = probe_haystack(p);
        for sig in VENDOR_SIGS {
            if matched_vendors.contains(&sig.vendor) {
                continue;
            }
            if let Some(tok) = sig
                .tokens
                .iter()
                .find(|t| haystack.contains(&t.to_ascii_lowercase()))
            {
                matched_vendors.push(sig.vendor);
                let server = header_value(&p.headers, "server").unwrap_or_default();
                let version = extract_server_version(server)
                    .or_else(|| extract_version_token(&p.body))
                    .map(|v| format!(" (observed version: {})", v))
                    .unwrap_or_default();
                ledger.bump_sev(sig.severity);
                findings.push(iot_finding(
                    &format!("IoT web UI fingerprint: {}{}", sig.vendor, version),
                    sig.severity,
                    "T1592",
                    &format!(
                        "{} identified at {} (HTTP {}; matched '{}'){}. Patch firmware and restrict management to trusted networks.",
                        sig.vendor, p.final_url, p.status, tok, version
                    ),
                    target,
                ));
            }
        }

        if let Some(www) = header_value(&p.headers, "www-authenticate") {
            let wl = www.to_ascii_lowercase();
            if wl.starts_with("basic") {
                let sev = "high";
                ledger.bump_sev(sev);
                findings.push(iot_finding(
                    &format!("Basic-auth management interface: {}", p.final_url),
                    sev,
                    "T1078.001",
                    &format!(
                        "{} returns HTTP 401 with Basic authentication ({}). Internet-facing embedded admin panels are high-value targets — restrict access and rotate factory credentials.",
                        p.final_url, www
                    ),
                    target,
                ));
            }
        }

        let path = p.final_url.split('/').skip(3).collect::<Vec<_>>().join("/");
        let path_slash = format!("/{}", path);
        if is_login_surface(&path_slash, &p.body) && factory_default_cred_hint(&p.body) {
            ledger.default_cred_hint = true;
            let sev = "high";
            ledger.bump_sev(sev);
            findings.push(iot_finding(
                &format!("Factory default credential hint on login page: {}", p.final_url),
                sev,
                "T1078.001",
                &format!(
                    "Login HTML at {} contains explicit factory/default credential text (e.g. admin/admin). This is documentation of default credentials in the UI — change passwords immediately and remove default hints from production builds.",
                    p.final_url
                ),
                target,
            ));
        }
    }

    let rtsp_probes =
        probe_paths_concurrent(&client, &url, RTSP_HTTP_PATHS, DEFAULT_PROBE_CONCURRENCY).await;
    for p in &rtsp_probes {
        if !status_indicates_presence(p.status) {
            continue;
        }
        let haystack = probe_haystack(p);
        let camera_markers = [
            "rtsp",
            "streaming",
            "onvif",
            "hikvision",
            "dahua",
            "mjpg",
            "video.cgi",
        ];
        if camera_markers.iter().any(|m| haystack.contains(m)) {
            let sev = "medium";
            ledger.bump_sev(sev);
            findings.push(iot_finding(
                &format!("Camera / RTSP HTTP surface: {}", p.final_url),
                sev,
                "T1592",
                &format!(
                    "HTTP {} at {} exposes camera/streaming markers (RTSP/ONVIF/MJPEG). Video interfaces are frequent default-credential and CVE targets — segment IoT VLANs and disable WAN access.",
                    p.status, p.final_url
                ),
                target,
            ));
        }
    }

    probe_mgmt_ports(&host, target, &mut findings, &mut ledger).await;
    probe_udp_services(&host, target, &mut findings, &mut ledger).await;

    if let Some(toxic) = synthesize_toxic_paths(&ledger, target, &host) {
        findings.push(toxic);
    }

    if !findings.is_empty() {
        let score = posture_score(&ledger);
        let grade = posture_grade(score);
        findings.push(json!({
            "type": "iot_firmware",
            "category": "posture_score",
            "title": format!("IoT/firmware posture score: {}/100 (grade {})", score, grade),
            "severity": if score >= 70 { "info" } else if score >= 50 { "medium" } else { "high" },
            "mitre_attack": "T1595",
            "description": format!(
                "Aggregate posture from observed IoT exposures on {} — telnet={}, firmware_download={}, no_tls={}, snmp_public={}, upnp={}. Lower scores indicate immediate perimeter containment.",
                host, ledger.telnet, ledger.firmware_download, ledger.no_tls, ledger.snmp_public, ledger.upnp
            ),
            "target": target,
            "posture_score": score,
            "posture_grade": grade,
            "probe_depth": "embedded_device_surface",
        }));
    }

    if findings.is_empty() {
        return EngineResult::ok(
            vec![],
            format!(
                "iot_firmware: no embedded-device surface observed on {}",
                host
            ),
        );
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("iot_firmware: {} embedded-device finding(s)", n),
    )
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
    fn vendor_sigs_cover_requested_vendors() {
        assert!(VENDOR_SIGS.iter().any(|s| s.vendor.contains("Hikvision")));
        assert!(VENDOR_SIGS.iter().any(|s| s.vendor.contains("MikroTik")));
        assert!(VENDOR_SIGS.iter().any(|s| s.vendor.contains("TP-Link")));
        assert!(VENDOR_SIGS.iter().any(|s| s.vendor.contains("Ubiquiti")));
        assert!(VENDOR_SIGS.iter().any(|s| s.vendor.contains("Dahua")));
    }

    #[test]
    fn firmware_magic_detects_formats() {
        assert_eq!(firmware_magic_label(b"\x7fELF"), Some("ELF"));
        assert_eq!(
            firmware_magic_label(&[0x27, 0x05, 0x19, 0x56, 0x00]),
            Some("uImage")
        );
        assert_eq!(firmware_magic_label(b"HDR0\x00"), Some("TRX"));
        assert_eq!(firmware_magic_label(b"hsqs"), Some("Squashfs"));
        assert!(firmware_magic_label(b"not firmware").is_none());
    }

    #[test]
    fn content_type_firmware_octet_stream() {
        assert!(content_type_is_firmware("application/octet-stream"));
        assert!(!content_type_is_firmware("text/html"));
    }

    #[test]
    fn snmp_validates_sysdescr_oid_and_printable() {
        let mut resp = vec![0x30, 0x20, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x04, 0x0a];
        resp.extend_from_slice(b"RouterOS 7");
        assert!(snmp_public_sysdescr_response(&resp));
        assert!(!snmp_public_sysdescr_response(&[
            0x30, 0x03, 0x01, 0x01, 0x00
        ]));
    }

    #[test]
    fn ssdp_response_requires_upnp_markers() {
        let ok = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1:8080/desc.xml\r\nST: upnp:rootdevice\r\n\r\n";
        assert!(ssdp_response_valid(ok));
        assert!(!ssdp_response_valid(b"random udp noise"));
    }

    #[test]
    fn factory_default_hint_requires_admin_admin_or_phrase() {
        assert!(factory_default_cred_hint(
            "Default login is admin/admin for first setup"
        ));
        assert!(!factory_default_cred_hint(
            "<form><input type=password></form>"
        ));
    }

    #[test]
    fn login_surface_detects_password_form() {
        assert!(is_login_surface(
            "/",
            "<form><input type=\"password\" name=\"pwd\"></form>"
        ));
        assert!(is_login_surface("/login.asp", "<html></html>"));
        assert!(!is_login_surface("/status.html", "<html>ok</html>"));
    }

    #[test]
    fn extract_server_version_parses_routeros() {
        assert_eq!(
            extract_server_version("RouterOS 6.49.10"),
            Some("6.49.10".to_string())
        );
    }

    #[test]
    fn tftp_opcode_detection() {
        assert!(tftp_response_valid(&[0x00, 0x05, 0x00, 0x01]));
        assert!(tftp_response_valid(&[0x00, 0x03, 0x00, 0x01]));
        assert!(!tftp_response_valid(&[0xff, 0xff]));
    }

    #[test]
    fn posture_score_penalizes_toxic_signals() {
        let mut l = ExposureLedger::new(true);
        l.telnet = true;
        l.firmware_download = true;
        assert!(posture_score(&l) < 60);
    }

    #[test]
    fn toxic_combo_telnet_firmware_no_tls() {
        let mut l = ExposureLedger::new(true);
        l.telnet = true;
        l.firmware_download = true;
        let f = synthesize_toxic_paths(&l, "http://iot.test", "iot.test").unwrap();
        assert!(f
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("toxic"));
    }

    #[test]
    fn service_banner_ssh_prefix() {
        assert!(service_banner_matches(22, "SSH-2.0-OpenSSH_8.4"));
        assert!(service_banner_matches(554, "RTSP/1.0 200 OK"));
    }

    #[tokio::test]
    async fn empty_target_errors() {
        assert!(!run_iot_firmware_result("").await.success);
    }
}
