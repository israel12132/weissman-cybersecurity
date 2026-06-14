//! Active Directory / Kerberos external attack-surface mapper.
//!
//! A remote, unauthenticated probe cannot extract TGS tickets, but it *can* map the
//! externally-reachable AD plumbing an operator would pivot through, with live evidence:
//!   • TCP reachability of Kerberos (88), LDAP/LDAPS (389/636), Global Catalog (3268/3269),
//!     SMB (445), kpasswd (464), MS-RPC EPM (135), WinRM (5985/5986), RDP (3389).
//!   • A **real anonymous LDAP simple-bind** (BER-encoded BindRequest) — success means the
//!     directory can be enumerated without credentials (AS-REP roastable users, SPNs, etc.).
//!   • HTTP SPNEGO/NTLM negotiation surface (ADFS, OWA/EWS, WinRM, `WWW-Authenticate: Negotiate`).
//!
//! Findings carry the concrete MITRE technique and the specific AD attack the exposure enables.
//! No tickets are requested and no credentials are submitted.

use crate::engine_probes::{
    extract_host, header_value, http_client, normalize_url, probe_paths_concurrent,
    status_indicates_presence, tcp_probe_response, tcp_scan, DEFAULT_PROBE_CONCURRENCY,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

/// AD service ports and the attack each one unlocks for a credentialed operator.
const AD_PORTS: &[(u16, &str, &str, &str)] = &[
    (88, "Kerberos KDC", "high", "T1558.003"),
    (389, "LDAP", "high", "T1087.002"),
    (636, "LDAPS", "medium", "T1087.002"),
    (3268, "Global Catalog (LDAP)", "high", "T1087.002"),
    (3269, "Global Catalog (LDAPS)", "medium", "T1087.002"),
    (445, "SMB", "high", "T1021.002"),
    (464, "kpasswd", "medium", "T1558"),
    (135, "MS-RPC endpoint mapper", "medium", "T1021.003"),
    (5985, "WinRM (HTTP)", "high", "T1021.006"),
    (5986, "WinRM (HTTPS)", "medium", "T1021.006"),
    (3389, "RDP", "high", "T1021.001"),
];

/// SPNEGO / Kerberos-relevant HTTP endpoints.
const KERBEROS_HTTP_PATHS: &[&str] = &[
    "/adfs/ls/",
    "/adfs/oauth2/authorize",
    "/EWS/Exchange.asmx",
    "/autodiscover/autodiscover.xml",
    "/mapi/",
    "/owa/",
    "/rpc/",
    "/api/auth/negotiate",
    "/auth/kerberos",
    "/SPNEGO",
    "/wsman",
];

fn kerb_finding(
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
) -> Value {
    json!({
        "type": "kerberoasting",
        "title": title,
        "severity": severity,
        "mitre_attack": mitre,
        "description": description,
        "target": target,
        "probe_depth": "ad_external_surface",
    })
}

/// Anonymous LDAP v3 simple BindRequest (name="", auth=simple ""):
/// `SEQUENCE { messageID 1, [APPLICATION 0] BindRequest { version 3, name "", simple "" } }`.
const LDAP_ANON_BIND: &[u8] = &[
    0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
];

/// Parse the resultCode from an LDAP BindResponse. Looks for the BindResponse tag
/// (`0x61`, APPLICATION 1) followed by the `ENUMERATED` resultCode (`0x0a 0x01 <code>`).
/// Returns the code (0 == success → anonymous bind accepted).
fn ldap_bind_result_code(resp: &[u8]) -> Option<u8> {
    let mut i = 0usize;
    while i + 1 < resp.len() {
        if resp[i] == 0x61 {
            let mut j = i + 1;
            while j + 2 < resp.len() {
                if resp[j] == 0x0a && resp[j + 1] == 0x01 {
                    return Some(resp[j + 2]);
                }
                j += 1;
            }
        }
        i += 1;
    }
    None
}

pub async fn run_kerberoasting_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    // 1. AD service port reachability.
    let ports: Vec<u16> = AD_PORTS.iter().map(|&(p, ..)| p).collect();
    let open = tcp_scan(&host, &ports, 16).await;
    for &port in &open {
        if let Some(&(_, name, sev, mitre)) = AD_PORTS.iter().find(|&&(p, ..)| p == port) {
            findings.push(kerb_finding(
                &format!("AD service reachable: {} ({}/tcp)", name, port),
                sev,
                mitre,
                &format!(
                    "{}/tcp ({}) is reachable on {}. Internet-exposed Active Directory plumbing — restrict to internal/VPN networks.",
                    port, name, host
                ),
                target,
            ));
        }
    }

    let kdc_open = open.contains(&88);
    let ldap_open = open.contains(&389) || open.contains(&3268);

    // 2. Kerberoasting / AS-REP feasibility (KDC + directory both reachable).
    if kdc_open && ldap_open {
        findings.push(kerb_finding(
            "Kerberoasting / AS-REP roasting attack surface exposed",
            "high",
            "T1558.003",
            &format!(
                "Both the Kerberos KDC (88/tcp) and LDAP directory ({}) are reachable on {}. A domain credential (or AS-REP-roastable account with pre-auth disabled) would allow SPN enumeration and offline TGS/AS-REP cracking.",
                if open.contains(&3268) { "3268/tcp GC" } else { "389/tcp" },
                host
            ),
            target,
        ));
    }

    // 3. NTLM-relay surface (SMB + LDAP without signing enforcement cannot be confirmed
    //    remotely, but co-exposure is the precondition).
    if open.contains(&445) && ldap_open {
        findings.push(kerb_finding(
            "NTLM relay precondition: SMB + LDAP co-exposed",
            "medium",
            "T1557.001",
            &format!(
                "SMB (445) and LDAP are both reachable on {} — the classic NTLM-relay-to-LDAP path. Enforce SMB signing and LDAP channel binding/signing.",
                host
            ),
            target,
        ));
    }

    // 4. Real anonymous LDAP bind (directory enumeration without credentials).
    if open.contains(&389) {
        if let Some(resp) = tcp_probe_response(&host, 389, LDAP_ANON_BIND).await {
            match ldap_bind_result_code(&resp) {
                Some(0) => findings.push(kerb_finding(
                    "Anonymous LDAP bind ACCEPTED — directory enumeration possible",
                    "critical",
                    "T1087.002",
                    &format!(
                        "389/tcp on {} accepted an anonymous LDAP simple bind (resultCode 0). The directory can be enumerated without credentials — exposing users, SPNs (Kerberoastable services), and accounts with Kerberos pre-auth disabled (AS-REP roastable). Disable anonymous binds (dsHeuristics) and require LDAP signing.",
                        host
                    ),
                    target,
                )),
                Some(code) => findings.push(kerb_finding(
                    "LDAP service confirmed (anonymous bind rejected)",
                    "info",
                    "T1087.002",
                    &format!(
                        "389/tcp on {} is a live LDAP service (bind resultCode {}). Anonymous bind was rejected — good. Directory still reachable; restrict to internal networks.",
                        host, code
                    ),
                    target,
                )),
                None => {}
            }
        }
    }

    // 5. HTTP SPNEGO / NTLM negotiation surface.
    let client = http_client().await;
    let probes = probe_paths_concurrent(
        &client,
        &url,
        KERBEROS_HTTP_PATHS,
        DEFAULT_PROBE_CONCURRENCY,
    )
    .await;
    for p in &probes {
        let www = header_value(&p.headers, "www-authenticate")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if p.status == 401 && (www.contains("negotiate") || www.contains("ntlm")) {
            let scheme = if www.contains("negotiate") {
                "Negotiate/Kerberos (SPNEGO)"
            } else {
                "NTLM"
            };
            findings.push(kerb_finding(
                &format!("{} authentication exposed: {}", scheme, p.final_url),
                "high",
                "T1558.003",
                &format!(
                    "{} requires {} authentication (WWW-Authenticate). In an AD environment this endpoint is bound to a service-account SPN and is a Kerberoasting target; NTLM endpoints are relay/brute-force targets.",
                    p.final_url, scheme
                ),
                target,
            ));
        } else if status_indicates_presence(p.status) && is_adfs_exchange_url(&p.final_url) {
            findings.push(kerb_finding(
                &format!("AD federation/Exchange endpoint exposed: {}", p.final_url),
                "medium",
                "T1558.003",
                &format!(
                    "{} (HTTP {}) is an internet-facing ADFS/Exchange surface — enables SPN enumeration and is a common Kerberoasting pivot.",
                    p.final_url, p.status
                ),
                target,
            ));
        }
    }

    if findings.is_empty() {
        return EngineResult::ok(
            vec![],
            format!(
                "kerberoasting: no external AD/Kerberos surface observed on {}",
                host
            ),
        );
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("kerberoasting: {} AD-surface finding(s)", n),
    )
}

fn is_adfs_exchange_url(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    u.contains("/adfs") || u.contains("/ews") || u.contains("/owa") || u.contains("autodiscover")
}

pub async fn run_kerberoasting(target: &str) {
    print_result(run_kerberoasting_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_anonymous_bind_success() {
        // SEQUENCE{ id 2, BindResponse{ resultCode 0, "", "" } }
        let resp = [
            0x30, 0x0c, 0x02, 0x01, 0x02, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
        ];
        assert_eq!(ldap_bind_result_code(&resp), Some(0));
    }

    #[test]
    fn parses_bind_rejection() {
        // resultCode 49 (invalidCredentials)
        let resp = [
            0x30, 0x0c, 0x02, 0x01, 0x02, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00,
        ];
        assert_eq!(ldap_bind_result_code(&resp), Some(0x31));
    }

    #[test]
    fn no_bindresponse_returns_none() {
        assert_eq!(ldap_bind_result_code(&[0x30, 0x00]), None);
    }

    #[tokio::test]
    async fn empty_target_errors() {
        assert!(!run_kerberoasting_result("").await.success);
    }
}
