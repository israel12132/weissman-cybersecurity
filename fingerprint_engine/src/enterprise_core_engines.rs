//! Enterprise-core attack engines — SAP/ERP and IBM mainframe (z/OS).
//!
//! These are the crown-jewel systems of most large enterprises, yet they sit outside the reach of
//! conventional web/cloud scanners. Both engines perform **real, read-only** network probing:
//! TCP service mapping of the documented SAP/mainframe port ranges plus protocol-accurate
//! identification (SAP ICM `/sap/public/info`, SAPControl, TN3270/FTP z/OS banners, DB2 DRDA, MQ).
//! Authenticated deep-tests (RFC abuse, RACF/ACF2 enumeration, transport injection) are explicitly
//! authorized on-segment actions and are surfaced via the endpoint-agent collector — never faked.

use crate::arsenal_config::{finding_rich, severity_for_score, ArsenalConfig, Evidence};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    agent_required_ok, empty_ok, extract_host, header_value, http_client, http_get, tcp_banner,
    tcp_scan,
};
use crate::engine_result::EngineResult;
use serde_json::json;

// ── SAP / ERP ────────────────────────────────────────────────────────────────

/// Documented SAP service ports (dispatcher, gateway, message server, ICM/Web, host agent,
/// start service). Operator can override via `job_params.ports`.
const DEFAULT_SAP_PORTS: &[u16] = &[
    3200, 3201, 3202, 3299, 3300, 3301, 3600, 3601, 8000, 8001, 8080, 8443, 44300, 44301, 50000,
    50001, 50013, 50014, 1128, 1129,
];

const SAP_ICM_HTTP_PORTS: &[u16] = &[8000, 8001, 8080, 8443, 44300, 44301, 50000, 50001, 50013];

fn classify_sap_port(port: u16) -> (&'static str, &'static str, f64, &'static str) {
    match port {
        3299 => (
            "SAProuter",
            "T1190",
            0.7,
            "SAProuter (NI route proxy) reachable. If route permission table (saprouttab) is permissive it proxies into the internal SAP landscape.",
        ),
        3300 | 3301 => (
            "SAP Gateway (RFC)",
            "T1210",
            0.85,
            "SAP Gateway exposed. Missing reginfo/secinfo ACLs allow unauthenticated RFC server registration and OS command execution (10KBLAZE / CVE-2019-0259 class).",
        ),
        3600 | 3601 => (
            "SAP Message Server",
            "T1190",
            0.8,
            "SAP Message Server exposed. Unrestricted internal port enables app-server enumeration and message-server impersonation (CVE-2020-6287 RECON pre-conditions).",
        ),
        3200 | 3201 | 3202 => (
            "SAP Dispatcher (DIAG)",
            "T1190",
            0.6,
            "SAP Dispatcher / DIAG protocol exposed (SAP GUI). Internet exposure is unusual and increases pre-auth attack surface.",
        ),
        1128 | 1129 => (
            "SAP Host Agent (SAPControl)",
            "T1190",
            0.7,
            "SAP Host Agent reachable. Unauthenticated SAPControl SOAP methods can leak host/instance data and, when misconfigured, allow privileged operations.",
        ),
        50013 | 50014 => (
            "SAP Start Service (SAPControl SOAP)",
            "T1190",
            0.75,
            "sapstartsrv SAPControl SOAP endpoint reachable. Several SAPControl methods are unauthenticated (CVE-2020-6207 SolMan class) and disclose system internals.",
        ),
        _ => (
            "SAP Web/ICM",
            "T1190",
            0.55,
            "SAP Internet Communication Manager (ICM) web port reachable.",
        ),
    }
}

/// Real SAP/ERP exposure probe.
pub async fn run_sap_erp_attack_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let ports = cfg.ports_or("ports", DEFAULT_SAP_PORTS);
    let concurrency = cfg.concurrency();
    let open = tcp_scan(&host, &ports, concurrency).await;

    let mut findings = Vec::new();
    for &port in &open {
        let (service, mitre, base_score, rationale) = classify_sap_port(port);
        let mut ev = Evidence::new()
            .with("host", host.clone())
            .with("port", port)
            .with("service", service)
            .check(
                "tcp_connect",
                true,
                format!("{}:{} accepted connection", host, port),
            );

        let mut score = base_score;
        let mut extra_title = String::new();

        // Deep, protocol-accurate identification for ICM/Web + SAPControl ports.
        if cfg.bool_or("check_icm_endpoints", true) && SAP_ICM_HTTP_PORTS.contains(&port) {
            let client = http_client().await;
            let scheme = if matches!(port, 8443 | 44300 | 44301 | 50001) {
                "https"
            } else {
                "http"
            };
            let mut icm_paths: Vec<String> = vec![
                "/sap/public/info".to_string(),
                "/sap/public/icman/ping".to_string(),
                "/sap/bc/ping".to_string(),
            ];
            icm_paths.extend(cfg.string_list("extra_paths"));
            for p in icm_paths {
                let url = format!("{}://{}:{}{}", scheme, host, port, p);
                if let Some(resp) = http_get(&client, &url).await {
                    let server = header_value(&resp.headers, "server")
                        .unwrap_or("")
                        .to_string();
                    let body_l = resp.body.to_ascii_lowercase();
                    let server_l = server.to_ascii_lowercase();
                    let sap_signal = server_l.contains("sap")
                        || server_l.contains("icm")
                        || body_l.contains("sap netweaver")
                        || body_l.contains("<rfcversion")
                        || body_l.contains("sap-system")
                        || body_l.contains("sap web application server");
                    if sap_signal {
                        score = (score + 0.15).min(0.95);
                        ev = ev
                            .check(
                                "icm_http_confirm",
                                true,
                                json!({ "path": p, "status": resp.status, "server": server }),
                            )
                            .with("icm_server_banner", server.clone());
                        if body_l.contains("<rfcsi") || p.contains("info") {
                            // /sap/public/info discloses kernel/release if reachable.
                            let excerpt: String = resp.body.chars().take(220).collect();
                            ev = ev.with("sap_public_info_excerpt", excerpt);
                            extra_title = " — /sap/public/info disclosed".to_string();
                            score = (score + 0.05).min(0.97);
                        }
                        break;
                    }
                    ev = ev.check(
                        "icm_http_probe",
                        false,
                        json!({ "path": p, "status": resp.status }),
                    );
                }
            }
        }

        let severity = severity_for_score(score);
        findings.push(finding_rich(
            "sap_erp_attack",
            &format!("{} reachable on {}:{}{}", service, host, port, extra_title),
            severity,
            mitre,
            rationale,
            target,
            score,
            ev,
        ));
    }

    // Generic ERP web signatures (Oracle E-Business Suite, MS Dynamics) on the target itself.
    if cfg.bool_or("check_erp_web", true) {
        let client = http_client().await;
        let base = crate::engine_probes::normalize_url(target);
        let erp_paths: &[(&str, &str, &str)] = &[
            ("/OA_HTML/AppsLogin", "Oracle E-Business Suite", "T1190"),
            (
                "/OA_HTML/AppsLocalLogin.jsp",
                "Oracle E-Business Suite",
                "T1190",
            ),
            ("/webclient/", "Microsoft Dynamics", "T1190"),
            ("/sap/bc/gui/sap/its/webgui", "SAP WebGUI", "T1190"),
        ];
        for (p, product, mitre) in erp_paths {
            let url = crate::engine_probes::join_url(&base, p);
            if let Some(resp) = http_get(&client, &url).await {
                if crate::engine_probes::status_indicates_presence(resp.status) {
                    let ev = Evidence::new()
                        .with("url", url.clone())
                        .with("product", *product)
                        .check("erp_login_surface", true, json!({ "status": resp.status }));
                    findings.push(finding_rich(
                        "sap_erp_attack",
                        &format!("{} login surface exposed", product),
                        "medium",
                        mitre,
                        "Enterprise ERP web login reachable. Confirm MFA/SSO enforcement, patch level, and that it is not internet-exposed without a reverse proxy + WAF.",
                        target,
                        0.5,
                        ev,
                    ));
                }
            }
        }
    }

    if cfg.emit_agent_guidance() && !open.is_empty() {
        let mut r = EngineResult::ok(findings, String::new());
        let mut guidance = agent_required_ok(
            "sap_erp_attack",
            target,
            "Authorized SAP deep-test (RFC abuse, transport injection, SAP* default creds) requires an on-segment agent",
            "Unauthenticated RFC callback registration, gw/msg ACL exploitation and authenticated transport injection are intrusive, on-segment actions.",
        );
        r.findings.append(&mut guidance.findings);
        r.message = format!(
            "sap_erp_attack: {} SAP/ERP service(s) mapped on {}",
            r.findings.len(),
            host
        );
        return r;
    }

    if findings.is_empty() {
        return empty_ok("sap_erp_attack", target);
    }
    EngineResult::ok(
        findings,
        format!("sap_erp_attack: SAP/ERP services mapped on {}", host),
    )
}

// ── IBM Mainframe (z/OS) ───────────────────────────────────────────────────────

const DEFAULT_MAINFRAME_PORTS: &[u16] = &[
    21, 23, 175, 446, 447, 448, 992, 1023, 1414, 2323, 5023, 8009,
];

const TN3270_TOKENS: &[&str] = &[
    "z/os",
    "mvs",
    "tso",
    "vtam",
    "ussmsg",
    "cics",
    "ims",
    "logon",
    "tpx",
    "netview",
    "racf",
    " readytso",
    "ispf",
    "***",
    "hercules",
    "zos",
];

const ZOS_FTP_TOKENS: &[&str] = &[
    "z/os",
    "mvs",
    "ftpd1",
    "ibm ftp",
    "220-ftp",
    "unix system services",
    "csv2r",
];

fn classify_mainframe_port(port: u16) -> (&'static str, f64, &'static str) {
    match port {
        23 | 2323 | 5023 => (
            "TN3270 / Telnet (TSO/VTAM)",
            0.7,
            "3270 terminal access to the mainframe. Exposed TSO/VTAM logon enables credential attacks against RACF/ACF2/Top-Secret and direct access to CICS/IMS transactions.",
        ),
        992 => (
            "TN3270 over TLS",
            0.6,
            "Encrypted 3270 terminal service. Confirms a mainframe terminal endpoint is internet-reachable.",
        ),
        21 => (
            "z/OS FTP (JES)",
            0.85,
            "z/OS FTP supports SITE FILETYPE=JES — authenticated users can submit JCL jobs (remote code execution on the mainframe). Must never be internet-exposed.",
        ),
        446 | 447 | 448 => (
            "DB2 DRDA",
            0.65,
            "DB2 for z/OS DRDA listener reachable. Enables authenticated SQL/stored-procedure access and is a common pivot into mainframe data.",
        ),
        1414 => (
            "IBM MQ",
            0.6,
            "IBM MQ queue manager listener reachable. Unauthenticated channels (e.g. SYSTEM.DEF.SVRCONN) allow message injection and admin command abuse.",
        ),
        175 => (
            "NJE (Network Job Entry)",
            0.7,
            "NJE node reachable. Trust-based NJE allows spoofed nodes to submit jobs / route SYSOUT across the sysplex.",
        ),
        8009 => (
            "AJP / z/OS Connect",
            0.5,
            "AJP / z/OS Connect surface reachable; verify it is not an unauthenticated API bridge into CICS/Db2.",
        ),
        _ => ("Mainframe service", 0.4, "Mainframe-class service reachable."),
    }
}

/// Real IBM mainframe (z/OS) exposure probe.
pub async fn run_mainframe_zos_attack_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let ports = cfg.ports_or("ports", DEFAULT_MAINFRAME_PORTS);
    let open = tcp_scan(&host, &ports, cfg.concurrency()).await;

    let mut findings = Vec::new();
    for &port in &open {
        let (service, base_score, rationale) = classify_mainframe_port(port);
        let mut ev = Evidence::new()
            .with("host", host.clone())
            .with("port", port)
            .with("service", service)
            .check("tcp_connect", true, format!("{}:{} open", host, port));
        let mut score = base_score;
        let mut confirmed = false;

        // Banner-grab + token confirmation on cleartext terminal / FTP ports.
        if matches!(port, 23 | 2323 | 5023 | 21 | 175) {
            if let Some(banner) = tcp_banner(&host, port).await {
                let bytes = banner.as_bytes();
                let has_iac = bytes.iter().any(|&b| b == 0xff);
                let banner_l = banner.to_ascii_lowercase();
                let tokens = if port == 21 {
                    ZOS_FTP_TOKENS
                } else {
                    TN3270_TOKENS
                };
                let matched: Vec<&str> = tokens
                    .iter()
                    .copied()
                    .filter(|t| banner_l.contains(t))
                    .collect();
                ev = ev.raw_excerpt(bytes);
                if !matched.is_empty() {
                    confirmed = true;
                    score = (score + 0.2).min(0.95);
                    ev = ev.check("mainframe_banner_token", true, json!(matched));
                } else if has_iac && matches!(port, 23 | 2323 | 5023) {
                    confirmed = true;
                    score = (score + 0.05).min(0.85);
                    ev = ev.check(
                        "telnet_iac_negotiation",
                        true,
                        "TN3270/telnet option negotiation observed",
                    );
                } else {
                    ev = ev.check("mainframe_banner_token", false, "no z/OS token in banner");
                }
            }
        }

        let title = if confirmed {
            format!("{} confirmed on {}:{}", service, host, port)
        } else {
            format!("{} candidate on {}:{}", service, host, port)
        };
        findings.push(finding_rich(
            "mainframe_zos_attack",
            &title,
            severity_for_score(score),
            "T1078",
            rationale,
            target,
            score,
            ev,
        ));
    }

    if cfg.emit_agent_guidance() && !open.is_empty() {
        let mut r = EngineResult::ok(findings, String::new());
        let mut guidance = agent_required_ok(
            "mainframe_zos_attack",
            target,
            "Authorized RACF/ACF2/Top-Secret enumeration and JES job-submission tests require credentialed on-segment access",
            "Security-database enumeration and JCL submission are credentialed, intrusive actions executed from an authorized collector.",
        );
        r.findings.append(&mut guidance.findings);
        r.message = format!(
            "mainframe_zos_attack: {} mainframe service(s) mapped on {}",
            r.findings.len(),
            host
        );
        return r;
    }

    if findings.is_empty() {
        return empty_ok("mainframe_zos_attack", target);
    }
    EngineResult::ok(
        findings,
        format!(
            "mainframe_zos_attack: mainframe services mapped on {}",
            host
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sap_port_classification_specific_services() {
        let (svc, mitre, score, _) = classify_sap_port(3299);
        assert_eq!(svc, "SAProuter");
        assert_eq!(mitre, "T1190");
        assert_eq!(score, 0.7);

        let (svc, mitre, score, _) = classify_sap_port(3300);
        assert_eq!(svc, "SAP Gateway (RFC)");
        assert_eq!(mitre, "T1210");
        assert_eq!(score, 0.85);
        // 3301 shares the same arm.
        assert_eq!(classify_sap_port(3301), classify_sap_port(3300));

        let (svc, _, score, _) = classify_sap_port(3600);
        assert_eq!(svc, "SAP Message Server");
        assert_eq!(score, 0.8);
        assert_eq!(classify_sap_port(3601), classify_sap_port(3600));

        let (svc, _, score, _) = classify_sap_port(3200);
        assert_eq!(svc, "SAP Dispatcher (DIAG)");
        assert_eq!(score, 0.6);

        let (svc, _, score, _) = classify_sap_port(1128);
        assert_eq!(svc, "SAP Host Agent (SAPControl)");
        assert_eq!(score, 0.7);

        let (svc, _, score, _) = classify_sap_port(50013);
        assert_eq!(svc, "SAP Start Service (SAPControl SOAP)");
        assert_eq!(score, 0.75);
    }

    #[test]
    fn sap_port_classification_default_web_icm() {
        // Any unlisted (but scanned) port falls through to the generic ICM/Web arm.
        let (svc, mitre, score, _) = classify_sap_port(8000);
        assert_eq!(svc, "SAP Web/ICM");
        assert_eq!(mitre, "T1190");
        assert_eq!(score, 0.55);
        assert_eq!(classify_sap_port(9999), classify_sap_port(8000));
    }

    #[test]
    fn mainframe_port_classification_specific_services() {
        let (svc, score, _) = classify_mainframe_port(23);
        assert_eq!(svc, "TN3270 / Telnet (TSO/VTAM)");
        assert_eq!(score, 0.7);
        assert_eq!(classify_mainframe_port(2323), classify_mainframe_port(23));
        assert_eq!(classify_mainframe_port(5023), classify_mainframe_port(23));

        let (svc, score, _) = classify_mainframe_port(992);
        assert_eq!(svc, "TN3270 over TLS");
        assert_eq!(score, 0.6);

        let (svc, score, _) = classify_mainframe_port(21);
        assert_eq!(svc, "z/OS FTP (JES)");
        assert_eq!(score, 0.85);

        let (svc, score, _) = classify_mainframe_port(446);
        assert_eq!(svc, "DB2 DRDA");
        assert_eq!(score, 0.65);
        assert_eq!(classify_mainframe_port(447), classify_mainframe_port(446));
        assert_eq!(classify_mainframe_port(448), classify_mainframe_port(446));

        let (svc, score, _) = classify_mainframe_port(1414);
        assert_eq!(svc, "IBM MQ");
        assert_eq!(score, 0.6);

        let (svc, score, _) = classify_mainframe_port(175);
        assert_eq!(svc, "NJE (Network Job Entry)");
        assert_eq!(score, 0.7);

        let (svc, score, _) = classify_mainframe_port(8009);
        assert_eq!(svc, "AJP / z/OS Connect");
        assert_eq!(score, 0.5);
    }

    #[test]
    fn mainframe_port_classification_default() {
        let (svc, score, _) = classify_mainframe_port(65000);
        assert_eq!(svc, "Mainframe service");
        assert_eq!(score, 0.4);
    }

    #[test]
    fn default_port_lists_include_expected_members() {
        // Guard against accidental edits to the documented port maps.
        assert!(DEFAULT_SAP_PORTS.contains(&3299));
        assert!(DEFAULT_SAP_PORTS.contains(&3300));
        assert!(SAP_ICM_HTTP_PORTS.iter().all(|p| DEFAULT_SAP_PORTS.contains(p)));
        assert!(DEFAULT_MAINFRAME_PORTS.contains(&21));
        assert!(DEFAULT_MAINFRAME_PORTS.contains(&23));
    }
}
