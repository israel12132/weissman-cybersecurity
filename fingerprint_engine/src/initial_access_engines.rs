//! Initial-access & endpoint engines — the mainstream techniques that the catalog never modelled
//! as first-class probes: malvertising / SEO-poisoning / ClickFix, commodity infostealers, network
//! printers/MFPs, and RADIUS/TACACS+/NAC.
//!
//! All network checks are **live**: real HTTP fetches, real PJL `@PJL INFO ID`, real SNMP
//! GetRequest for `sysDescr`, and a real RADIUS Access-Request liveness probe. Host-resident
//! collection (infostealer credential-store theft) is routed to the endpoint agent — never
//! simulated.

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    agent_required_ok, empty_ok, extract_host, header_value, http_client, http_get, join_url,
    normalize_url, tcp_open, tcp_probe_response, tcp_scan, udp_probe_response,
};
use crate::engine_result::EngineResult;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Small, dependency-free randomness for protocol identifiers ─────────────────

fn fill_pseudo_random(buf: &mut [u8]) {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        ^ (buf.as_ptr() as u64);
    let mut x = seed | 1;
    for b in buf.iter_mut() {
        // xorshift64
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xff) as u8;
    }
}

// ── SNMP v1 GetRequest builder (sysDescr 1.3.6.1.2.1.1.1.0) ────────────────────

fn ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    // Single-byte length form is sufficient for every packet we build (all < 128 bytes).
    let mut out = Vec::with_capacity(value.len() + 2);
    out.push(tag);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    out
}

/// Build an SNMP v1 GetRequest for sysDescr.0 with the given community string.
fn snmp_v1_get_sysdescr(community: &str) -> Vec<u8> {
    // OID 1.3.6.1.2.1.1.1.0
    let oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    let oid_tlv = ber_tlv(0x06, &oid);
    let null_tlv = vec![0x05, 0x00];
    let mut varbind_inner = oid_tlv;
    varbind_inner.extend_from_slice(&null_tlv);
    let varbind = ber_tlv(0x30, &varbind_inner);
    let varbind_list = ber_tlv(0x30, &varbind);

    let mut reqid = [0u8; 4];
    fill_pseudo_random(&mut reqid);
    let reqid_tlv = ber_tlv(0x02, &reqid);
    let err_status = vec![0x02, 0x01, 0x00];
    let err_index = vec![0x02, 0x01, 0x00];

    let mut pdu_body = reqid_tlv;
    pdu_body.extend_from_slice(&err_status);
    pdu_body.extend_from_slice(&err_index);
    pdu_body.extend_from_slice(&varbind_list);
    let pdu = ber_tlv(0xA0, &pdu_body); // GetRequest-PDU

    let version = vec![0x02, 0x01, 0x00]; // v1
    let community_tlv = ber_tlv(0x04, community.as_bytes());
    let mut msg_body = version;
    msg_body.extend_from_slice(&community_tlv);
    msg_body.extend_from_slice(&pdu);
    ber_tlv(0x30, &msg_body)
}

/// Extract the printable sysDescr OCTET STRING from an SNMP response (best-effort).
fn snmp_extract_octet_string(resp: &[u8]) -> Option<String> {
    // Find the last OCTET STRING (tag 0x04) of reasonable length — the varbind value.
    let mut i = 0usize;
    let mut best: Option<String> = None;
    while i + 2 < resp.len() {
        if resp[i] == 0x04 {
            let len = resp[i + 1] as usize;
            if len > 0 && i + 2 + len <= resp.len() {
                let slice = &resp[i + 2..i + 2 + len];
                if slice
                    .iter()
                    .all(|&b| b == 0x09 || b == 0x0a || b == 0x0d || (0x20..=0x7e).contains(&b))
                    && slice.len() > 2
                {
                    best = Some(String::from_utf8_lossy(slice).to_string());
                }
            }
        }
        i += 1;
    }
    best
}

// ── RADIUS Access-Request liveness probe ───────────────────────────────────────

fn radius_access_request(username: &str, nas_id: &str) -> Vec<u8> {
    let mut authenticator = [0u8; 16];
    fill_pseudo_random(&mut authenticator);
    let mut ident = [0u8; 1];
    fill_pseudo_random(&mut ident);

    let mut attrs: Vec<u8> = Vec::new();
    // User-Name (1)
    let uname = username.as_bytes();
    attrs.push(1);
    attrs.push((uname.len() + 2) as u8);
    attrs.extend_from_slice(uname);
    // NAS-Identifier (32)
    let nid = nas_id.as_bytes();
    attrs.push(32);
    attrs.push((nid.len() + 2) as u8);
    attrs.extend_from_slice(nid);
    // NAS-IP-Address (4)
    attrs.extend_from_slice(&[4, 6, 127, 0, 0, 1]);

    let total_len = 20 + attrs.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(1); // Code = Access-Request
    pkt.push(ident[0]);
    pkt.push((total_len >> 8) as u8);
    pkt.push((total_len & 0xff) as u8);
    pkt.extend_from_slice(&authenticator);
    pkt.extend_from_slice(&attrs);
    pkt
}

fn radius_code_name(code: u8) -> &'static str {
    match code {
        2 => "Access-Accept",
        3 => "Access-Reject",
        11 => "Access-Challenge",
        _ => "RADIUS response",
    }
}

// ── Engine: malvertising / SEO-poisoning / ClickFix ────────────────────────────

const CLICKFIX_TOKENS: &[&str] = &[
    "navigator.clipboard.writetext",
    "powershell -",
    "powershell.exe",
    "mshta",
    "iex(",
    "invoke-expression",
    "cmd /c",
    "cmd.exe /c",
    "win + r",
    "press win",
];

/// Real probe: detect ClickFix / fake-CAPTCHA paste lures, open-redirect (ad-cloaking) surface,
/// and unsafe third-party ad/script inclusion on the target.
pub async fn run_malvertising_seo_poison_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let client = http_client().await;
    let base = normalize_url(target);
    let target_host = extract_host(target);
    let mut findings = Vec::new();

    let mut paths = vec!["/".to_string()];
    paths.extend(cfg.string_list_or(
        "paths",
        &[
            "/download",
            "/downloads",
            "/get",
            "/verify",
            "/captcha",
            "/human",
        ],
    ));

    if cfg.bool_or("check_clickfix", true) {
        for p in &paths {
            let url = join_url(&base, p);
            if let Some(resp) = http_get(&client, &url).await {
                let body_l = resp.body.to_ascii_lowercase();
                let has_clipboard = body_l.contains("clipboard")
                    && (body_l.contains("powershell")
                        || body_l.contains("mshta")
                        || body_l.contains("iex(")
                        || body_l.contains("cmd /c"));
                let matched: Vec<&str> = CLICKFIX_TOKENS
                    .iter()
                    .copied()
                    .filter(|t| body_l.contains(t))
                    .collect();
                if has_clipboard || matched.len() >= 2 {
                    let ev = Evidence::new()
                        .with("url", url.clone())
                        .with("matched_tokens", json!(matched))
                        .check(
                            "clipboard_paste_lure",
                            has_clipboard,
                            "clipboard write + shell payload",
                        )
                        .check("status", true, json!(resp.status));
                    findings.push(finding_rich(
                        "malvertising_seo_poison",
                        "ClickFix / fake-CAPTCHA paste lure detected",
                        "critical",
                        "T1204.004",
                        "Page instructs the visitor to copy a command into the Run dialog / terminal (ClickFix). This is an active malware-delivery lure and indicates the site is compromised or hosting an attacker landing page.",
                        target,
                        0.9,
                        ev,
                    ));
                }
            }
        }
    }

    if cfg.bool_or("check_open_redirect", true) {
        let canary = cfg.string_or("redirect_canary", "https://example.com/");
        let canary_host = extract_host(&canary);
        let params = cfg.string_list_or(
            "redirect_params",
            &[
                "url", "redirect", "next", "return", "dest", "continue", "r", "u",
            ],
        );
        for param in params.iter().take(8) {
            let url = format!("{}/?{}={}", base.trim_end_matches('/'), param, canary);
            if let Some(resp) = http_get(&client, &url).await {
                let final_host = extract_host(&resp.final_url);
                if final_host.eq_ignore_ascii_case(&canary_host) && !canary_host.is_empty() {
                    let ev = Evidence::new()
                        .with("test_url", url.clone())
                        .with("redirected_to", resp.final_url.clone())
                        .with("parameter", param.clone())
                        .check(
                            "offsite_redirect",
                            true,
                            "followed to attacker-controlled host",
                        );
                    findings.push(finding_rich(
                        "malvertising_seo_poison",
                        &format!("Open redirect via '{}' parameter", param),
                        "high",
                        "T1204.001",
                        "Unvalidated redirect lets attackers cloak malicious-ad / SEO-poisoning links behind your trusted domain, defeating reputation filters.",
                        target,
                        0.75,
                        ev,
                    ));
                    break;
                }
            }
        }
    }

    if cfg.bool_or("check_third_party_scripts", true) {
        if let Some(resp) = http_get(&client, &base).await {
            let mut risky = Vec::new();
            for cap in resp.body.split("<script").skip(1) {
                let head: String = cap.chars().take(400).collect();
                let hl = head.to_ascii_lowercase();
                if let Some(src_idx) = hl.find("src=") {
                    let rest = &head[src_idx + 4..];
                    let srcval: String = rest
                        .trim_start_matches(['"', '\'', ' '])
                        .chars()
                        .take_while(|&c| c != '"' && c != '\'' && c != ' ' && c != '>')
                        .collect();
                    if srcval.starts_with("http") {
                        let sh = extract_host(&srcval);
                        if !sh.is_empty()
                            && !sh.eq_ignore_ascii_case(&target_host)
                            && !hl.contains("integrity=")
                        {
                            risky.push(srcval);
                        }
                    }
                }
            }
            risky.dedup();
            if !risky.is_empty() {
                let shown: Vec<String> = risky.iter().take(10).cloned().collect();
                let ev = Evidence::new()
                    .with("scripts_without_sri", json!(shown))
                    .with("count", risky.len())
                    .check(
                        "third_party_no_sri",
                        true,
                        "cross-origin <script> without integrity",
                    );
                findings.push(finding_rich(
                    "malvertising_seo_poison",
                    "Third-party scripts loaded without Subresource Integrity",
                    "medium",
                    "T1059.007",
                    "Cross-origin scripts with no integrity attribute can be swapped via a compromised ad/CDN (malvertising supply chain). Add SRI hashes + a strict CSP.",
                    target,
                    0.45,
                    ev,
                ));
            }
        }
    }

    if findings.is_empty() {
        return empty_ok("malvertising_seo_poison", target);
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!(
            "malvertising_seo_poison: {} initial-access exposure(s) on {}",
            n, target_host
        ),
    )
}

// ── Engine: infostealer emulation (agent-resident) ─────────────────────────────

/// Commodity infostealer (RedLine/Lumma/StealC-class) blast-radius emulation. This is inherently a
/// host action (reading browser credential stores, crypto wallets, app tokens), so it executes via
/// the endpoint agent. Routed here as the honest agent-required collector — no remote stand-in.
pub async fn run_infostealer_emulation_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let _cfg = ArsenalConfig::from_ctx(ctx);
    agent_required_ok(
        "infostealer_emulation",
        target,
        "Infostealer blast-radius emulation runs on the host via the Weissman agent",
        "Reading browser cookie/password stores, crypto-wallet files, Discord/Telegram tokens and VPN profiles is a host-resident action; the agent performs it read-only and reports exactly which secret stores were reachable.",
    )
}

// ── Engine: network printer / MFP ──────────────────────────────────────────────

const PRINTER_TCP_PORTS: &[u16] = &[9100, 515, 631, 80, 443, 8080, 280, 9000, 23];
const PRINTER_VENDOR_TOKENS: &[&str] = &[
    "hp",
    "jetdirect",
    "xerox",
    "canon",
    "brother",
    "lexmark",
    "ricoh",
    "kyocera",
    "epson",
    "konica",
    "sharp",
    "oki",
    "printer",
    "cups",
    "ipp",
];

/// Real probe: PJL `@PJL INFO ID`, IPP/CUPS, SNMP sysDescr, and LPD/web management surfaces.
pub async fn run_printer_mfp_attack_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let tcp_ports = cfg.ports_or("ports", PRINTER_TCP_PORTS);
    let open = tcp_scan(&host, &tcp_ports, cfg.concurrency()).await;
    let mut findings = Vec::new();

    // PJL on raw port 9100.
    if open.contains(&9100) && cfg.bool_or("check_pjl", true) {
        let payload = b"\x1b%-12345X@PJL INFO ID\r\n@PJL INFO STATUS\r\n\x1b%-12345X";
        let mut ev = Evidence::new()
            .with("host", host.clone())
            .with("port", 9100u16);
        if let Some(resp) = tcp_probe_response(&host, 9100, payload).await {
            let text = String::from_utf8_lossy(&resp);
            ev = ev.raw_excerpt(&resp).check(
                "pjl_info_id",
                true,
                text.lines().take(4).collect::<Vec<_>>().join(" | "),
            );
            findings.push(finding_rich(
                "printer_mfp_attack",
                "Unauthenticated PJL access on 9100/tcp",
                "high",
                "T1200",
                "Raw PJL/JetDirect is reachable without authentication. PJL can read/alter the device file system (PRET), exfiltrate spooled jobs and persist on the printer. Restrict 9100 to print servers only.",
                target,
                0.8,
                ev,
            ));
        } else {
            findings.push(finding_rich(
                "printer_mfp_attack",
                "Raw print port 9100/tcp open",
                "medium",
                "T1200",
                "JetDirect/raw port open; PJL response not captured. Confirm and lock down to authorized print servers.",
                target,
                0.45,
                ev.check("pjl_info_id", false, "no PJL response"),
            ));
        }
    }

    // IPP / CUPS / vendor web management.
    for &port in &open {
        if matches!(port, 631 | 80 | 443 | 8080 | 280) && cfg.bool_or("check_web", true) {
            let client = http_client().await;
            let scheme = if port == 443 { "https" } else { "http" };
            let url = format!("{}://{}:{}/", scheme, host, port);
            if let Some(resp) = http_get(&client, &url).await {
                let server = header_value(&resp.headers, "server")
                    .unwrap_or("")
                    .to_string();
                let blob = format!("{} {}", server, resp.body).to_ascii_lowercase();
                let matched: Vec<&str> = PRINTER_VENDOR_TOKENS
                    .iter()
                    .copied()
                    .filter(|t| blob.contains(*t))
                    .collect();
                if !matched.is_empty() {
                    let is_cups = blob.contains("cups") || blob.contains("ipp");
                    let ev = Evidence::new()
                        .with("url", url.clone())
                        .with("server", server)
                        .with("matched", json!(matched))
                        .check("vendor_signature", true, json!(matched));
                    findings.push(finding_rich(
                        "printer_mfp_attack",
                        &format!("Printer/MFP management surface on {}:{}", host, port),
                        if is_cups { "medium" } else { "medium" },
                        "T1200",
                        "Printer web/IPP management reachable. Verify admin authentication, disable IPP-everywhere if unused, and remove stored LDAP/SMB scan-to-folder credentials that a passback attack could harvest.",
                        target,
                        0.55,
                        ev,
                    ));
                }
            }
        }
    }

    if open.contains(&515) {
        findings.push(finding_rich(
            "printer_mfp_attack",
            "LPD (515/tcp) print service open",
            "low",
            "T1200",
            "Line Printer Daemon reachable; legacy LPD has weak access control and is a lateral-movement foothold. Disable if unused.",
            target,
            0.35,
            Evidence::new().with("host", host.clone()).with("port", 515u16),
        ));
    }

    // SNMP (UDP 161) — model + the classic stored-credential exposure.
    if cfg.bool_or("check_snmp", true) {
        let snmp_port = cfg.u64_or("snmp_port", 161) as u16;
        let communities = cfg.string_list_or("snmp_communities", &["public", "private"]);
        for community in communities.iter().take(6) {
            let pkt = snmp_v1_get_sysdescr(community);
            if let Some(resp) = udp_probe_response(&host, snmp_port, &pkt).await {
                let sysdescr = snmp_extract_octet_string(&resp).unwrap_or_default();
                let ev = Evidence::new()
                    .with("host", host.clone())
                    .with("udp_port", snmp_port)
                    .with("community", community.clone())
                    .with("sysDescr", sysdescr.clone())
                    .raw_excerpt(&resp)
                    .check("snmp_v1_get", true, "sysDescr.0 returned");
                findings.push(finding_rich(
                    "printer_mfp_attack",
                    &format!("SNMP readable with community '{}'", community),
                    "high",
                    "T1200",
                    "Device answers SNMP with a default/guessable community. Printer MIBs expose model, firmware and frequently the stored LDAP/SMB scan-to-folder credentials (a passback-attack source). Set a strong community / SNMPv3 and restrict access.",
                    target,
                    0.78,
                    ev,
                ));
                break;
            }
        }
    }

    if findings.is_empty() {
        return empty_ok("printer_mfp_attack", target);
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("printer_mfp_attack: {} printer exposure(s) on {}", n, host),
    )
}

// ── Engine: RADIUS / TACACS+ / NAC ─────────────────────────────────────────────

/// Real probe: RADIUS Access-Request liveness (Blast-RADIUS surface) + TACACS+ reachability.
pub async fn run_radius_nac_bypass_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let mut findings = Vec::new();

    let auth_ports = cfg.ports_or("radius_auth_ports", &[1812, 1645]);
    let username = cfg.string_or("probe_username", "weissman-probe");
    let nas_id = cfg.string_or("nas_identifier", "weissman");
    if cfg.bool_or("check_radius", true) {
        for &port in &auth_ports {
            let pkt = radius_access_request(&username, &nas_id);
            if let Some(resp) = udp_probe_response(&host, port, &pkt).await {
                let code = resp.first().copied().unwrap_or(0);
                let mut ev = Evidence::new()
                    .with("host", host.clone())
                    .with("udp_port", port)
                    .with("response_code", code)
                    .with("response_kind", radius_code_name(code))
                    .raw_excerpt(&resp)
                    .check(
                        "radius_access_request",
                        true,
                        "server replied to Access-Request",
                    );
                let (sev, score, title, desc) = if code == 2 {
                    (
                        "critical",
                        0.95,
                        "RADIUS Access-Accept without valid credentials",
                        "The RADIUS server accepted an Access-Request with no valid shared secret / credentials — a severe authentication-bypass condition. Investigate immediately.",
                    )
                } else {
                    (
                        "high",
                        0.7,
                        "RADIUS authentication server exposed",
                        "RADIUS over UDP is reachable. If Message-Authenticator is not enforced it is exploitable via Blast-RADIUS (CVE-2024-3596) to forge Access-Accept. Require Message-Authenticator, move to RADSEC (TLS), and restrict the NAS source set.",
                    )
                };
                ev = ev.check(
                    "blast_radius_surface",
                    code != 2,
                    "CVE-2024-3596 applies to UDP RADIUS without Message-Authenticator enforcement",
                );
                findings.push(finding_rich(
                    "radius_nac_bypass",
                    title,
                    sev,
                    "T1556",
                    desc,
                    target,
                    score,
                    ev,
                ));
                break;
            }
        }
    }

    if cfg.bool_or("check_tacacs", true) {
        let tacacs_port = cfg.u64_or("tacacs_port", 49) as u16;
        if tcp_open(&host, tacacs_port).await {
            findings.push(finding_rich(
                "radius_nac_bypass",
                &format!("TACACS+ reachable on {}:{}", host, tacacs_port),
                "medium",
                "T1556",
                "TACACS+ device-administration service is reachable. Restrict to management network only; legacy TACACS+ encrypts only the body with a shared MD5 secret and is brute-forceable offline if captured.",
                target,
                0.55,
                Evidence::new().with("host", host.clone()).with("port", tacacs_port).check("tcp_connect", true, "open"),
            ));
        }
    }

    if cfg.emit_agent_guidance() {
        let mut r = EngineResult::ok(findings, String::new());
        let mut guidance = agent_required_ok(
            "radius_nac_bypass",
            target,
            "802.1X / NAC bypass (MAB MAC-spoofing, EAP downgrade, hub-on-the-wire) requires an on-segment L2 collector",
            "Layer-2 NAC evasion is a physical/on-segment action and is validated by an authorized agent placed on the access network.",
        );
        r.findings.append(&mut guidance.findings);
        r.message = format!(
            "radius_nac_bypass: {} finding(s) on {}",
            r.findings.len(),
            host
        );
        return r;
    }

    if findings.is_empty() {
        return empty_ok("radius_nac_bypass", target);
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("radius_nac_bypass: {} finding(s) on {}", n, host),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_packet_is_well_formed() {
        let pkt = snmp_v1_get_sysdescr("public");
        assert_eq!(pkt[0], 0x30); // SEQUENCE
                                  // contains community "public"
        assert!(pkt.windows(6).any(|w| w == b"public"));
        // GetRequest PDU tag present
        assert!(pkt.contains(&0xA0));
    }

    #[test]
    fn radius_packet_header_is_valid() {
        let pkt = radius_access_request("user", "nas");
        assert_eq!(pkt[0], 1); // Access-Request
        let len = ((pkt[2] as usize) << 8) | pkt[3] as usize;
        assert_eq!(len, pkt.len());
        assert!(pkt.len() >= 20);
    }

    #[test]
    fn snmp_octet_string_extraction() {
        // SEQ wrapper not needed; just an octet string in the buffer.
        let mut buf = vec![0x04, 0x05];
        buf.extend_from_slice(b"HP123");
        assert_eq!(snmp_extract_octet_string(&buf).as_deref(), Some("HP123"));
    }
}
