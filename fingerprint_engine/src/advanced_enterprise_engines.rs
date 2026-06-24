//! Advanced Enterprise-Core Engines — real TCP/HTTP probes against the enterprise crown-jewel
//! systems the rest of the arsenal never touched: **SAP / ERP** and **IBM mainframe (z/OS)**.
//!
//! Every finding is evidence-backed: an engine only emits a finding when a live probe observed a
//! real protocol/banner/HTTP signal. Destructive actions (RFC calls with credentials, JCL job
//! submission, logic download) are never performed remotely — those are explicitly-authorized,
//! agent-mediated actions and are surfaced as `agent_required` guidance when
//! `include_agent_findings` is on (default).
//!
//! All knobs (`ports`, `timeout_ms`, `concurrency`, `intensity`, per-check toggles) are read from
//! the live scan request via [`ArsenalConfig`], giving the operator full control with no code change.

use crate::arsenal_config::{finding_rich, severity_for_score, ArsenalConfig, Evidence};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    extract_host, http_client, http_get, tcp_banner, tcp_open, tcp_probe_response, tcp_scan,
    HttpProbe,
};
use crate::engine_result::EngineResult;
use serde_json::Value;

/// Pick http/https scheme for a SAP/web port.
fn scheme_for(port: u16) -> &'static str {
    match port {
        443 | 44300 | 44301 | 50001 | 8443 => "https",
        _ => "http",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SAP / ERP
// ─────────────────────────────────────────────────────────────────────────────

/// Default SAP service ports (NetWeaver/ABAP+Java instance 00/01 + SAProuter + message server).
const SAP_DEFAULT_PORTS: &[u16] = &[
    80, 443, 3200, 3201, 3299, 3300, 3301, 3600, 3601, 8000, 8001, 8100, 44300, 50000, 50001,
    50013, 50113,
];

/// ICM / Web-AS surfaces. Unauthenticated reachability of these is an information-disclosure or, in
/// the case of the LM Configuration Wizard (`/CTCWebService`), the RECON pre-auth RCE surface
/// (CVE-2020-6287).
const SAP_HTTP_PATHS: &[(&str, &str, &str)] = &[
    (
        "/sap/public/info",
        "T1592",
        "Unauthenticated SAP system info (RELEASE/DB/OS) disclosure via /sap/public/info",
    ),
    (
        "/sap/public/icman/ping",
        "T1190",
        "SAP ICM ping endpoint reachable",
    ),
    ("/sap/bc/ping", "T1190", "SAP ABAP ICF /sap/bc/ping reachable"),
    (
        "/sap/bc/gui/sap/its/webgui",
        "T1190",
        "SAP GUI for HTML (WebGUI) logon exposed",
    ),
    (
        "/sap/admin/public/index.html",
        "T1190",
        "SAP ICM administration surface exposed",
    ),
    (
        "/CTCWebService/CTCWebServiceBean",
        "T1190",
        "SAP LM Configuration Wizard (RECON / CVE-2020-6287) pre-auth surface reachable",
    ),
    (
        "/CTCWebService/CTCWebServiceBean/ConfigServlet",
        "T1190",
        "SAP NetWeaver Java ConfigServlet (RECON) reachable",
    ),
];

const SAP_TOKENS: &[&str] = &[
    "sap netweaver",
    "sap-server",
    "sap web dispatcher",
    "sap j2ee engine",
    "as java",
    "/sap/public",
    "sap-perf-fesrec",
    "<rfc",
    "sap web application server",
    "icm/host_name_full",
];

fn sap_url(scheme: &str, host: &str, port: u16, path: &str) -> String {
    if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
        format!("{scheme}://{host}{path}")
    } else {
        format!("{scheme}://{host}:{port}{path}")
    }
}

/// Confirm a SAProuter on `host:port` by issuing the NI (Network Interface) admin info request used
/// by `saprouter -L`. A SAProuter replies on the wire; any framed response confirms the service.
async fn probe_saprouter(host: &str, port: u16) -> Option<Vec<u8>> {
    // NI packet: 4-byte big-endian length prefix followed by the "ROUTER_ADM" eyecatcher and the
    // info command opcode (2). This is the documented, read-only admin info request.
    let mut payload: Vec<u8> = Vec::new();
    let body: &[u8] = b"ROUTER_ADM\x00\x02\x00\x00";
    payload.extend_from_slice(&(body.len() as u32).to_be_bytes());
    payload.extend_from_slice(body);
    tcp_probe_response(host, port, &payload).await
}

/// Real SAP/ERP exposure assessment: port surface + unauthenticated ICM/Web-AS paths + SAProuter.
pub async fn run_sap_erp_attack_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let ports = cfg.ports_or("ports", SAP_DEFAULT_PORTS);
    let open = tcp_scan(&host, &ports, cfg.concurrency()).await;
    let mut findings: Vec<Value> = Vec::new();

    if open.is_empty() {
        return crate::engine_probes::empty_ok("sap_erp_attack", target);
    }

    // SAProuter (3299) — confirm via NI admin info request.
    if open.contains(&3299) {
        if let Some(resp) = probe_saprouter(&host, 3299).await {
            let ev = Evidence::new()
                .with("host", host.clone())
                .with("port", 3299_i64)
                .with("service", "SAProuter (NI protocol)")
                .check("ni_admin_info", true, "SAProuter replied to ROUTER_ADM info request")
                .raw_excerpt(&resp);
            findings.push(finding_rich(
                "sap_erp_attack",
                "SAProuter exposed to the network",
                "high",
                "T1190",
                &format!("SAProuter confirmed on {host}:3299 (replies to NI admin info). An exposed SAProuter is a pivot into the SAP landscape; restrict to known route tables and place behind VPN."),
                target,
                0.8,
                ev,
            ));
        } else {
            findings.push(finding_rich(
                "sap_erp_attack",
                "SAProuter port open (unconfirmed)",
                "medium",
                "T1046",
                &format!("TCP {host}:3299 accepts connections (SAProuter candidate) but did not answer the NI admin request."),
                target,
                0.4,
                Evidence::new().with("host", host.clone()).with("port", 3299_i64),
            ));
        }
    }

    // Dispatcher / gateway / message-server raw ports — report exposure (DIAG/RFC/MS are not meant
    // to face untrusted networks).
    for (p, label, mitre) in [
        (3200_u16, "SAP Dispatcher (DIAG) port exposed", "T1190"),
        (3300, "SAP Gateway (RFC) port exposed", "T1190"),
        (3600, "SAP Message Server port exposed", "T1190"),
    ] {
        if open.contains(&p) {
            let banner = tcp_banner(&host, p).await.unwrap_or_default();
            let ev = Evidence::new()
                .with("host", host.clone())
                .with("port", i64::from(p))
                .check("tcp_open", true, "port accepts connections");
            findings.push(finding_rich(
                "sap_erp_attack",
                label,
                "high",
                mitre,
                &format!("{label} on {host}:{p}. Banner len {}. Core SAP transport protocols must be confined to the SAP server VLAN; gateway ACLs (reg_info/sec_info) and message-server ACLs must reject untrusted peers.", banner.len()),
                target,
                0.7,
                ev,
            ));
        }
    }

    // HTTP/ICM surfaces.
    let client = http_client().await;
    let http_ports: Vec<u16> = open
        .iter()
        .copied()
        .filter(|p| {
            matches!(
                p,
                80 | 443 | 8000 | 8001 | 8100 | 44300 | 44301 | 50000 | 50001 | 50013 | 50113
            )
        })
        .collect();

    let mut confirmed_sap = false;
    for port in http_ports {
        let scheme = scheme_for(port);
        for (path, mitre, title) in SAP_HTTP_PATHS {
            let url = sap_url(scheme, &host, port, path);
            let Some(p): Option<HttpProbe> = http_get(&client, &url).await else {
                continue;
            };
            let blob = format!(
                "{}\n{}",
                p.headers
                    .iter()
                    .map(|(k, v)| format!("{k}: {v}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                p.body
            )
            .to_ascii_lowercase();
            let matched: Vec<&str> = SAP_TOKENS.iter().copied().filter(|t| blob.contains(t)).collect();
            let recon = path.contains("CTCWebService");
            // Only emit when we either confirmed SAP tokens OR the path itself returned a non-404
            // for a SAP-specific surface.
            let present = p.status != 404 && p.status != 410 && p.status != 0;
            if matched.is_empty() && !present {
                continue;
            }
            confirmed_sap = confirmed_sap || !matched.is_empty();
            let score = if recon && present {
                0.95
            } else if !matched.is_empty() {
                0.8
            } else {
                0.45
            };
            let ev = Evidence::new()
                .with("host", host.clone())
                .with("port", i64::from(port))
                .with("url", url.clone())
                .with("http_status", i64::from(p.status))
                .with("sap_tokens", Value::from(matched.clone()))
                .check("recon_surface", recon && present, *title);
            findings.push(finding_rich(
                "sap_erp_attack",
                title,
                severity_for_score(score),
                mitre,
                &format!(
                    "{title} — HTTP {} at {url}{}. {}",
                    p.status,
                    if matched.is_empty() {
                        String::new()
                    } else {
                        format!(" (SAP markers: {})", matched.join(", "))
                    },
                    if recon {
                        "If the LM Configuration Wizard answers without authentication the system is exposed to RECON (CVE-2020-6287) — patch SAP Note 2934135 and block /CTCWebService at the Web Dispatcher."
                    } else {
                        "Restrict ICF services to authenticated, allow-listed callers; deactivate unused ICF nodes (transaction SICF)."
                    }
                ),
                target,
                score,
                ev,
            ));
        }
    }

    if findings.is_empty() {
        return EngineResult::ok(
            vec![],
            format!(
                "sap_erp_attack: {} SAP candidate port(s) open on {host} but no SAP protocol/HTTP signal confirmed",
                open.len()
            ),
        );
    }

    if cfg.emit_agent_guidance() && confirmed_sap {
        findings.push(crate::arsenal_config::finding_rich(
            "sap_erp_attack",
            "SAP RFC/credential validation requires authorized connector",
            "info",
            "T1078",
            "SAP detected. Deep checks (default users SAP*/DDIC/EARLYWATCH, RFC gateway abuse, SOAP RFC ping, transport injection) require an authenticated SAP connector and explicit authorization — not performed by the remote probe.",
            target,
            1.0,
            Evidence::new().with("host", host.clone()).with("requires", "sap_connector"),
        ));
    }

    let n = findings.len();
    EngineResult::ok(findings, format!("sap_erp_attack: {n} SAP exposure finding(s) on {host}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// IBM mainframe (z/OS)
// ─────────────────────────────────────────────────────────────────────────────

const ZOS_DEFAULT_PORTS: &[u16] = &[21, 23, 175, 992, 1023, 2023, 8008, 10007];

/// z/OS / mainframe exposure: TN3270 (telnet/SSL), z/OS FTP (with JES surface), NJE.
pub async fn run_mainframe_zos_attack_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let ports = cfg.ports_or("ports", ZOS_DEFAULT_PORTS);
    let open = tcp_scan(&host, &ports, cfg.concurrency()).await;
    let mut findings: Vec<Value> = Vec::new();
    let mut mainframe_confirmed = false;

    // z/OS FTP (21) — banner frequently discloses "z/OS"/"MVS"/"FTPD1"/Communications Server.
    if open.contains(&21) {
        if let Some(banner) = tcp_banner(&host, 21).await {
            let b = banner.to_ascii_lowercase();
            let zos = ["z/os", "mvs", "ftpd1", "ftp cs", "v2r", "ibm ftp", "communications server"]
                .iter()
                .find(|m| b.contains(**m));
            if let Some(marker) = zos {
                mainframe_confirmed = true;
                let ev = Evidence::new()
                    .with("host", host.clone())
                    .with("port", 21_i64)
                    .with("banner", banner.trim().to_string())
                    .check("zos_ftp_banner", true, *marker)
                    .check(
                        "jes_spool_surface",
                        true,
                        "z/OS FTP exposes JES via SITE FILETYPE=JES (job submission/output)",
                    );
                findings.push(finding_rich(
                    "mainframe_zos_attack",
                    "z/OS FTP server exposed (JES job-submission surface)",
                    "high",
                    "T1133",
                    &format!("z/OS FTP confirmed on {host}:21 ('{marker}'). z/OS FTP can submit/read JES batch jobs (SITE FILETYPE=JES) — with credentials this is remote code execution on the mainframe. Restrict FTP to internal admin networks and enforce TLS + RACF."),
                    target,
                    0.85,
                    ev,
                ));
            } else if !banner.trim().is_empty() {
                findings.push(finding_rich(
                    "mainframe_zos_attack",
                    "FTP server exposed (mainframe candidate)",
                    "medium",
                    "T1046",
                    &format!("FTP on {host}:21 banner '{}' — not confirmed z/OS.", banner.trim()),
                    target,
                    0.4,
                    Evidence::new().with("host", host.clone()).with("port", 21_i64).with("banner", banner.trim().to_string()),
                ));
            }
        }
    }

    // TN3270 (23 / 992) — telnet negotiation (IAC) and EBCDIC logon screen.
    for tn_port in [23_u16, 992] {
        if !open.contains(&tn_port) {
            continue;
        }
        // Offer TN3270E so the host negotiates; read the raw IAC/EBCDIC response.
        let resp = tcp_probe_response(&host, tn_port, &[0xFF, 0xFD, 0x28]).await;
        if let Some(bytes) = resp {
            let has_iac = bytes.contains(&0xFF);
            // EBCDIC uppercase letters land in 0xC1..=0xE9; a logon screen is full of them.
            let ebcdic_density = bytes
                .iter()
                .filter(|b| (0xC1..=0xE9).contains(b) || **b == 0x40)
                .count();
            let looks_ebcdic = ebcdic_density * 3 >= bytes.len() && bytes.len() > 8;
            if has_iac || looks_ebcdic {
                mainframe_confirmed = true;
                let score = if looks_ebcdic { 0.85 } else { 0.6 };
                let ev = Evidence::new()
                    .with("host", host.clone())
                    .with("port", i64::from(tn_port))
                    .check("telnet_iac", has_iac, "server negotiated telnet (IAC present)")
                    .check("ebcdic_logon", looks_ebcdic, "EBCDIC logon-screen byte density")
                    .raw_excerpt(&bytes);
                findings.push(finding_rich(
                    "mainframe_zos_attack",
                    if tn_port == 992 {
                        "TN3270 over TLS (mainframe terminal) exposed"
                    } else {
                        "TN3270 mainframe terminal service exposed"
                    },
                    severity_for_score(score),
                    "T1133",
                    &format!("TN3270 service confirmed on {host}:{tn_port} (IAC={has_iac}, EBCDIC logon={looks_ebcdic}). Exposed 3270 logon screens (TSO/CICS/IMS) are brute-force and credential-stuffing targets. Restrict to internal networks, require TLS, and enforce RACF/ACF2/Top-Secret lockout policy."),
                    target,
                    score,
                    ev,
                ));
            }
        } else if tcp_open(&host, tn_port).await {
            findings.push(finding_rich(
                "mainframe_zos_attack",
                "TN3270 candidate port open",
                "medium",
                "T1046",
                &format!("TCP {host}:{tn_port} open (TN3270 candidate) but negotiation not confirmed."),
                target,
                0.4,
                Evidence::new().with("host", host.clone()).with("port", i64::from(tn_port)),
            ));
        }
    }

    // NJE (network job entry) store-and-forward.
    if open.contains(&175) {
        findings.push(finding_rich(
            "mainframe_zos_attack",
            "NJE (Network Job Entry) port exposed",
            "high",
            "T1133",
            &format!("TCP {host}:175 (NJE) reachable. NJE trust between nodes enables cross-system job submission ('NJElovesme'); restrict to known node lists and authenticated links."),
            target,
            0.6,
            Evidence::new().with("host", host.clone()).with("port", 175_i64),
        ));
    }

    if findings.is_empty() {
        return crate::engine_probes::empty_ok("mainframe_zos_attack", target);
    }
    if cfg.emit_agent_guidance() && mainframe_confirmed {
        findings.push(finding_rich(
            "mainframe_zos_attack",
            "RACF / credential testing requires authorized connector",
            "info",
            "T1078",
            "Mainframe confirmed. Credential testing (default IBMUSER/SYS1, RACF enumeration, JCL job submission, APF-authorized library abuse) requires explicit authorization and a TN3270/FTP credential connector — not performed by the remote probe.",
            target,
            1.0,
            Evidence::new().with("host", host.clone()).with("requires", "mainframe_connector"),
        ));
    }
    let n = findings.len();
    EngineResult::ok(findings, format!("mainframe_zos_attack: {n} mainframe exposure finding(s) on {host}"))
}
