//! Supreme-tier AD/Kerberos probes — called from the main kerberoasting engine module.

use super::{
    ad_finding, attack_path_finding, extract_ldap_strings, extract_naming_context,
    extract_sam_accounts, extract_spns, filter_and, filter_equality, filter_extensible_match,
    filter_present, ldap_bind_result_code, ldap_exchange, ldap_search_request, AdSignals,
    KerberosConfig, LDAP_ANON_BIND, T_ASREP, T_DELEGATION, T_DOMAIN_DISC, T_KERBEROAST,
    T_NTLM_RELAY,
};
use crate::arsenal_config::{finding_rich, Evidence, Intensity};
use crate::cloud_hunter::{GraphEdge, GraphNode};
use crate::engine_probes::{http_client, probe_paths_concurrent, DEFAULT_PROBE_CONCURRENCY};
use hickory_resolver::config::{ResolverConfig, CLOUDFLARE, GOOGLE, QUAD9};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use serde_json::{json, Value};
use std::time::Duration;

const ENGINE_ID: &str = "kerberoasting";

const ADCS_HTTP_PATHS: &[&str] = &[
    "/certsrv/",
    "/CertEnroll/",
    "/CertEnroll/certfnsh.asp",
    "/ADCSLC/CertEnroll",
    "/CertificateAuthorityAuth/",
];

const STARTTLS_OID: &[u8] = &[
    0x30, 0x1c, 0x02, 0x01, 0x03, 0x77, 0x17, 0x80, 0x15, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31,
    0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x31, 0x34, 0x36, 0x36, 0x2e, 0x32, 0x30, 0x30, 0x33, 0x37,
];

fn build_resolver(choice: &str) -> Option<TokioResolver> {
    let cfg = match choice {
        "cloudflare" => Some(ResolverConfig::udp_and_tcp(&CLOUDFLARE)),
        "google" => Some(ResolverConfig::udp_and_tcp(&GOOGLE)),
        "quad9" => Some(ResolverConfig::udp_and_tcp(&QUAD9)),
        _ => None,
    };
    match cfg {
        Some(c) => TokioResolver::builder_with_config(c, TokioRuntimeProvider::default())
            .build()
            .ok(),
        None => TokioResolver::builder_tokio().and_then(|b| b.build()).ok(),
    }
}

// ─── SMB2 signing probe (real negotiate response parse) ───────────────────────────

fn nbss_wrap(smb: &[u8]) -> Vec<u8> {
    let len = smb.len();
    let mut out = vec![0u8; 4];
    out[1] = ((len >> 16) & 0xff) as u8;
    out[2] = ((len >> 8) & 0xff) as u8;
    out[3] = (len & 0xff) as u8;
    out.extend_from_slice(smb);
    out
}

fn smb2_negotiate_req() -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
    h[12..14].copy_from_slice(&0u16.to_le_bytes()); // NEGOTIATE
    let dialects: [u16; 4] = [0x0202, 0x0210, 0x0300, 0x0302];
    let mut body = Vec::new();
    body.extend_from_slice(&36u16.to_le_bytes());
    body.extend_from_slice(&4u16.to_le_bytes());
    body.extend_from_slice(&0x0001u16.to_le_bytes()); // signing enabled requestor
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&[0u8; 24]);
    let mut smb = h;
    smb.extend_from_slice(&body);
    for d in &dialects {
        smb.extend_from_slice(&d.to_le_bytes());
    }
    nbss_wrap(&smb)
}

/// Returns (signing_enabled, signing_required) from SMB2 NEGOTIATE response SecurityMode.
fn parse_smb2_security_mode(resp: &[u8]) -> Option<(bool, bool)> {
    if resp.len() < 4 + 64 + 4 {
        return None;
    }
    let smb = &resp[4..];
    if smb[0..4] != [0xFE, b'S', b'M', b'B'] {
        return None;
    }
    let body_off = 64;
    if smb.len() < body_off + 4 {
        return None;
    }
    let security_mode = u16::from_le_bytes(smb[body_off + 2..body_off + 4].try_into().ok()?);
    Some(((security_mode & 0x01) != 0, (security_mode & 0x02) != 0))
}

pub async fn scan_smb_signing(
    host: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if !cfg.check_smb_signing || !sig.open_ports.contains(&445) {
        return;
    }
    let payload = smb2_negotiate_req();
    if let Some(resp) = ldap_exchange(host, 445, &[&payload], cfg.timeout_ms).await {
        if let Some((enabled, required)) = parse_smb2_security_mode(&resp) {
            sig.smb_signing_required = Some(required);
            sig.scores.smb_hardening = if required {
                100.0
            } else if enabled {
                40.0
            } else {
                0.0
            };
            let sev = if required { "info" } else { "high" };
            findings.push(ad_finding(
                if required {
                    "SMB signing REQUIRED (relay-resistant)"
                } else if enabled {
                    "SMB signing enabled but NOT required — NTLM relay possible"
                } else {
                    "SMB signing NOT enabled — NTLM relay highly feasible"
                },
                sev,
                T_NTLM_RELAY,
                &format!(
                    "SMB2 NEGOTIATE on {host}:445 returned SecurityMode signing_enabled={enabled} signing_required={required}. \
                     Without required signing, coerced NTLM auth can be relayed to LDAP/SMB on this host."
                ),
                target,
                0.91,
                Evidence::new()
                    .with("host", host)
                    .with("signing_enabled", enabled)
                    .with("signing_required", required)
                    .raw_excerpt(&resp)
                    .check("smb2_negotiate", true, "live SMB2 response parsed"),
                "smb_signing",
                &["CIS Control 3.10", "MSKB 887429"],
                Some("Enable SMB signing required via GPO: Microsoft network server/client: Digitally sign communications (always)."),
            ));
        }
    }
}

// ─── LDAP StartTLS probe ─────────────────────────────────────────────────────────

pub async fn scan_ldap_starttls(
    host: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if !cfg.check_ldap_starttls || !sig.open_ports.contains(&389) {
        return;
    }
    if let Some(resp) = ldap_exchange(host, 389, &[STARTTLS_OID], cfg.timeout_ms).await {
        // resultCode 0 on ExtendedResponse = StartTLS accepted
        let accepted = ldap_bind_result_code(&resp) == Some(0)
            || resp.windows(3).any(|w| w == [0x0a, 0x01, 0x00]);
        sig.ldap_starttls_ok = accepted;
        if accepted {
            sig.scores.ldap_hardening = sig.scores.ldap_hardening.max(30.0);
            findings.push(ad_finding(
                "LDAP StartTLS supported on 389/tcp",
                "medium",
                T_DOMAIN_DISC,
                &format!(
                    "{host}:389 accepted LDAP ExtendedRequest StartTLS (OID 1.3.6.1.4.1.1466.20037). \
                     Cleartext LDAP is available — enforce LDAPS-only + channel binding."
                ),
                target,
                0.88,
                Evidence::new()
                    .with("host", host)
                    .with("starttls", true)
                    .raw_excerpt(&resp),
                "ldap_starttls",
                &["NIST SC-8"],
                Some("Require LDAP signing + channel binding; prefer LDAPS 636; block cleartext LDAP at firewall."),
            ));
        }
    }
}

// ─── AD CS web enrollment surface ────────────────────────────────────────────────

pub async fn scan_adcs_http(
    url: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if !cfg.check_adcs_http {
        return;
    }
    let client = http_client().await;
    let probes = probe_paths_concurrent(
        &client,
        url,
        ADCS_HTTP_PATHS,
        cfg.concurrency.min(DEFAULT_PROBE_CONCURRENCY),
    )
    .await;
    for p in &probes {
        if p.status == 200 || p.status == 401 || p.status == 403 {
            let body_l = p.body.to_ascii_lowercase();
            if body_l.contains("certsrv")
                || body_l.contains("certificate")
                || body_l.contains("cert enroll")
                || p.final_url.to_ascii_lowercase().contains("certsrv")
            {
                sig.adcs_exposed = true;
                sig.scores.adcs_exposure = 0.0;
                findings.push(ad_finding(
                    &format!("AD CS web enrollment exposed: {}", p.final_url),
                    "critical",
                    "T1649",
                    &format!(
                        "Active Directory Certificate Services web interface responded at {} (HTTP {}). \
                         Misconfigured templates (ESC1–ESC8) enable domain escalation via certificate abuse.",
                        p.final_url, p.status
                    ),
                    target,
                    0.93,
                    Evidence::new()
                        .with("url", &p.final_url)
                        .with("http_status", p.status)
                        .check("adcs_http", true, "CertSrv/Enrollment surface"),
                    "adcs_exposure",
                    &["MITRE T1649", "SpecterOps ESC"],
                    Some("Disable web enrollment unless required; audit certificate templates; enable CT log monitoring; restrict enrollment agents."),
                ));
                break;
            }
        }
    }
}

// ─── Kerberos username enumeration oracle (AS-REQ) ─────────────────────────────

fn as_req_for_principal(realm: &str, username: &str) -> Vec<u8> {
    // Principal: cname = [1] name-type 1, name-string = username
    let user = username.as_bytes();
    let mut cname = vec![0x30];
    let mut cname_inner = vec![0x02, 0x01, 0x01]; // name-type 1
    let mut ns = vec![0x30];
    ns.extend(vec![0x04, user.len() as u8]);
    ns.extend_from_slice(user);
    cname_inner.extend(ns);
    cname.push(cname_inner.len() as u8);
    cname.extend(cname_inner);

    let mut req_body = Vec::new();
    req_body.extend(vec![0x02, 0x01, 0x05, 0x02, 0x01, 0x0a]); // pvno 5, msg-type 10
    req_body.push(0xa3);
    let mut tagged = cname;
    tagged.extend(vec![0x1b, realm.len() as u8]);
    tagged.extend_from_slice(realm.as_bytes());
    tagged.extend(vec![0x30, 0x00]); // empty till expiry
    let seq = {
        let mut s = vec![0x30];
        s.push(tagged.len() as u8);
        s.extend(tagged);
        s
    };
    req_body.extend(&seq[1..]);

    let mut body = vec![0x30];
    body.push((req_body.len() + 6) as u8);
    body.extend(vec![0x02, 0x01, 0x05, 0x02, 0x01, 0x0a]);
    body.extend(vec![0x30, 0x00]); // padata
    body.extend(req_body);
    let mut tagged = vec![0x6a];
    tagged.extend(&body[1..]);
    tagged
}

fn krb_error_code(resp: &[u8]) -> Option<i32> {
    // Search for DER INTEGER after KRB-ERROR tag 0x7e — heuristic for error-code field
    for (i, &b) in resp.iter().enumerate() {
        if b == 0x7e && i + 6 < resp.len() && resp[i + 2] == 0x02 {
            let len = resp[i + 3] as usize;
            if len == 1 && i + 4 < resp.len() {
                return Some(i32::from(resp[i + 4]));
            }
        }
    }
    None
}

pub async fn scan_kerberos_user_enum(
    host: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if !cfg.check_user_enum_krb || !sig.open_ports.contains(&88) {
        return;
    }
    let realm = if cfg.domain.is_empty() {
        host.to_ascii_uppercase()
    } else {
        cfg.domain.to_ascii_uppercase()
    };
    let invalid = "__weissman_invalid_probe__";
    let invalid_req = as_req_for_principal(&realm, invalid);
    let invalid_resp = ldap_exchange(host, 88, &[&invalid_req], cfg.timeout_ms).await;
    let invalid_code = invalid_resp.as_ref().and_then(|r| krb_error_code(r));

    let mut confirmed = Vec::new();
    for user in &cfg.probe_usernames {
        let req = as_req_for_principal(&realm, user);
        if let Some(resp) = ldap_exchange(host, 88, &[&req], cfg.timeout_ms).await {
            let code = krb_error_code(&resp);
            // 25 = PREAUTH_REQUIRED (user exists), 6 = principal unknown
            if code == Some(25) || (code != invalid_code && code.is_some() && code != Some(6)) {
                confirmed.push(user.clone());
            }
        }
    }
    if !confirmed.is_empty() {
        sig.user_enum_oracle = true;
        sig.scores.kerberos_hardening = 10.0;
        findings.push(ad_finding(
            &format!("Kerberos user-enumeration oracle: {} principal(s) confirmed", confirmed.len()),
            "high",
            T_DOMAIN_DISC,
            &format!(
                "KDC on {host}:88 distinguishes valid principals via AS-REQ error codes. Confirmed: {}. \
                 Enables targeted password spray before Kerberoasting.",
                confirmed.join(", ")
            ),
            target,
            0.87,
            Evidence::new()
                .with("realm", &realm)
                .with("confirmed_users", json!(confirmed))
                .with("invalid_baseline_code", json!(invalid_code)),
            "krb_user_enum",
            &["MITRE T1087.002"],
            Some("Enable Kerberos pre-auth for all accounts; monitor Event 4771; use CAPTCHA/lockout on edge auth."),
        ));
    }
}

// ─── Delegation / RBCD / machine SPN LDAP searches ───────────────────────────────

pub async fn scan_delegation_and_machines(
    host: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if !cfg.check_ldap_enum {
        return;
    }
    let ldap_port = if sig.open_ports.contains(&389) {
        389u16
    } else if sig.open_ports.contains(&3268) {
        3268
    } else {
        return;
    };
    let nc = match &sig.naming_context {
        Some(n) => n.clone(),
        None => return,
    };

    if cfg.check_delegation && (sig.ldap_anon_ok || cfg.intensity == Intensity::Aggressive) {
        // Unconstrained delegation: TRUSTED_FOR_DELEGATION 0x80000
        let uac_filter = filter_and(&[
            &filter_equality("objectCategory", "person"),
            &filter_extensible_match("userAccountControl", "1.2.840.113556.1.4.803", "524288"),
        ]);
        let search = ldap_search_request(
            5,
            &nc,
            2,
            &uac_filter,
            &["sAMAccountName", "userAccountControl"],
        );
        let msgs: Vec<&[u8]> = if sig.ldap_anon_ok {
            vec![LDAP_ANON_BIND, &search]
        } else {
            vec![&search]
        };
        if let Some(resp) = ldap_exchange(host, ldap_port, &msgs, cfg.timeout_ms).await {
            let strings = extract_ldap_strings(&resp);
            sig.unconstrained_delegation = extract_sam_accounts(&strings);
            if !sig.unconstrained_delegation.is_empty() {
                sig.scores.delegation_risk = 0.0;
                findings.push(ad_finding(
                    &format!(
                        "{} unconstrained delegation account(s) observable",
                        sig.unconstrained_delegation.len()
                    ),
                    "critical",
                    T_DELEGATION,
                    &format!(
                        "Accounts with TRUSTED_FOR_DELEGATION (UAC 0x80000): {}. \
                         Any internet-exposed service using these accounts stores TGTs — full domain compromise path.",
                        sig.unconstrained_delegation.join(", ")
                    ),
                    target,
                    0.94,
                    Evidence::new().with("accounts", json!(sig.unconstrained_delegation)),
                    "unconstrained_delegation",
                    &["MITRE T1558.001"],
                    Some("Remove unconstrained delegation; use constrained/resource-based delegation with gMSA; tier-0 separation."),
                ));
            }
        }

        // RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity present
        let rbcd_filter = filter_present("msDS-AllowedToActOnBehalfOfOtherIdentity");
        let rbcd_search = ldap_search_request(
            6,
            &nc,
            2,
            &rbcd_filter,
            &["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        );
        let rbcd_msgs: Vec<&[u8]> = if sig.ldap_anon_ok {
            vec![LDAP_ANON_BIND, &rbcd_search]
        } else {
            vec![&rbcd_search]
        };
        if let Some(resp) = ldap_exchange(host, ldap_port, &rbcd_msgs, cfg.timeout_ms).await {
            let strings = extract_ldap_strings(&resp);
            sig.rbcd_accounts = extract_sam_accounts(&strings);
            if !sig.rbcd_accounts.is_empty() {
                sig.scores.delegation_risk = 5.0;
                findings.push(ad_finding(
                    &format!("{} RBCD-configured computer(s) discovered", sig.rbcd_accounts.len()),
                    "high",
                    T_DELEGATION,
                    &format!(
                        "msDS-AllowedToActOnBehalfOfOtherIdentity set on: {}. \
                         Writable LDAP + RBCD enables S4U2Self/S4U2Proxy impersonation of domain admins.",
                        sig.rbcd_accounts.join(", ")
                    ),
                    target,
                    0.89,
                    Evidence::new().with("computers", json!(sig.rbcd_accounts)),
                    "rbcd_exposure",
                    &["MITRE T1558"],
                    Some("Audit RBCD ACLs; restrict who can write msDS-AllowedToActOnBehalfOfOtherIdentity; monitor Event 5136."),
                ));
            }
        }
    }

    if cfg.check_machine_spns && (sig.ldap_anon_ok || cfg.intensity == Intensity::Aggressive) {
        let machine_filter = filter_and(&[
            &filter_equality("objectCategory", "computer"),
            &filter_present("servicePrincipalName"),
        ]);
        let m_search = ldap_search_request(
            7,
            &nc,
            2,
            &machine_filter,
            &["servicePrincipalName", "sAMAccountName"],
        );
        let m_msgs: Vec<&[u8]> = if sig.ldap_anon_ok {
            vec![LDAP_ANON_BIND, &m_search]
        } else {
            vec![&m_search]
        };
        if let Some(resp) = ldap_exchange(host, ldap_port, &m_msgs, cfg.timeout_ms).await {
            let strings = extract_ldap_strings(&resp);
            sig.machine_spns = extract_spns(&strings);
            if !sig.machine_spns.is_empty() {
                findings.push(ad_finding(
                    &format!("{} machine-account SPN(s) enumerable", sig.machine_spns.len()),
                    "medium",
                    T_KERBEROAST,
                    &format!(
                        "Computer accounts with servicePrincipalName: {} — alternative Kerberoast targets when machine accounts use weak passwords.",
                        sig.machine_spns.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                    ),
                    target,
                    0.8,
                    Evidence::new().with("machine_spn_sample", json!(sig.machine_spns.iter().take(8).collect::<Vec<_>>())),
                    "machine_spn",
                    &["MITRE T1558.003"],
                    None,
                ));
            }
        }
    }
}

// ─── _msdcs zone DNS cartography ─────────────────────────────────────────────────

pub async fn scan_msdcs_dns(
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if !cfg.check_msdcs_dns || cfg.domain.is_empty() {
        return;
    }
    let Some(resolver) = build_resolver(&cfg.resolver) else {
        return;
    };
    let zone = format!("_msdcs.{}", cfg.domain.trim_end_matches('.'));
    if let Ok(lookup) = resolver.lookup(&zone, RecordType::A).await {
        for record in lookup.answers() {
            if let RData::A(a) = &record.data {
                let ip = a.to_string();
                sig.msdcs_hosts.push(ip.clone());
                findings.push(ad_finding(
                    &format!("_msdcs zone A record: {zone} → {ip}"),
                    "medium",
                    T_DOMAIN_DISC,
                    &format!("Public DNS exposes AD _msdcs zone glue ({zone} → {ip}) — aids DC/localization for external attackers."),
                    target,
                    0.82,
                    Evidence::new().with("zone", &zone).with("ip", ip),
                    "msdcs_dns",
                    &[],
                    None,
                ));
            }
        }
    }
}

// ─── Toxic combination headline (Wiz-style) ──────────────────────────────────────

pub fn emit_toxic_headline(target: &str, sig: &AdSignals, findings: &mut Vec<Value>) {
    let mut combos: Vec<String> = Vec::new();
    if sig.ldap_anon_ok && !sig.kerberoast_spns.is_empty() {
        combos.push(
            "anonymous LDAP + harvestable SPNs ⇒ credential-free Kerberoast setup".to_string(),
        );
    }
    if sig.kdc_live && sig.ldap_reachable && sig.smb_signing_required == Some(false) {
        combos.push(
            "internet KDC + LDAP + SMB signing not required ⇒ spray → relay → roast chain"
                .to_string(),
        );
    }
    if sig.adcs_exposed && sig.ldap_reachable {
        combos.push(
            "AD CS web enrollment + LDAP ⇒ ESC1–ESC8 certificate domain escalation".to_string(),
        );
    }
    if !sig.unconstrained_delegation.is_empty() && !sig.spnego_urls.is_empty() {
        combos.push("unconstrained delegation + internet SPNEGO ⇒ TGT theft path".to_string());
    }
    if !sig.asrep_accounts.is_empty() {
        combos.push(format!(
            "{} AS-REP-roastable account(s) ⇒ offline crack without pre-auth",
            sig.asrep_accounts.len()
        ));
    }
    if combos.is_empty() {
        return;
    }
    let headline = combos.join(" ⊕ ");
    findings.insert(
        0,
        ad_finding(
            &format!("TOXIC COMBINATION: {headline}"),
            "critical",
            T_KERBEROAST,
            "Correlated AD exposures form a domain-compromise chain beyond the sum of individual findings — prioritize perimeter lockdown and tier-0 hardening immediately.",
            target,
            0.97,
            Evidence::new()
                .with("combinations", json!(combos))
                .with("toxic_count", combos.len()),
            "toxic_combination",
            &["Wiz AD Posture", "MITRE ATT&CK"],
            None,
        ),
    );
}

// ─── Prioritized remediation roadmap ─────────────────────────────────────────────

pub fn emit_remediation_roadmap(target: &str, sig: &AdSignals, findings: &mut Vec<Value>) {
    let mut steps: Vec<Value> = Vec::new();
    let mut priority = 1u8;
    let mut push = |action: &str, detail: &str, effort: &str| {
        steps.push(json!({
            "priority": priority,
            "action": action,
            "detail": detail,
            "effort": effort,
        }));
        priority += 1;
    };

    if sig.open_ports.contains(&88) || sig.kdc_live {
        push(
            "P0",
            "Block Kerberos 88/tcp from internet — VPN/ZTNA only",
            "hours",
        );
    }
    if sig.ldap_anon_ok {
        push(
            "P0",
            "Disable anonymous LDAP binds (dsHeuristics bit 2) + require LDAP signing",
            "hours",
        );
    }
    if sig.smb_signing_required == Some(false) {
        push(
            "P0",
            "Enforce SMB signing required on all DCs (GPO)",
            "hours",
        );
    }
    if !sig.kerberoast_spns.is_empty() {
        push(
            "P1",
            "Rotate service-account passwords to 25+ char random; deploy gMSA",
            "days",
        );
    }
    if !sig.asrep_accounts.is_empty() {
        push(
            "P1",
            "Enable Kerberos pre-auth on all user accounts; audit UAC 0x400000",
            "hours",
        );
    }
    if sig.adcs_exposed {
        push(
            "P0",
            "Disable AD CS web enrollment; audit certificate templates (ESC1–ESC8)",
            "days",
        );
    }
    if !sig.unconstrained_delegation.is_empty() {
        push(
            "P0",
            "Remove unconstrained delegation from tier-0/tier-1 accounts",
            "days",
        );
    }
    if !sig.rbcd_accounts.is_empty() {
        push(
            "P1",
            "Audit RBCD msDS-AllowedToActOnBehalfOfOtherIdentity ACLs",
            "days",
        );
    }
    push(
        "P2",
        "Deploy honeypot SPN + monitor Event 4769 RC4-HMAC TGS-REQ volume",
        "days",
    );
    push(
        "P2",
        "Enable LDAP channel binding + EPA on ADFS/OWA",
        "days",
    );

    if steps.is_empty() {
        return;
    }
    findings.push(ad_finding(
        "Prioritized AD/Kerberos remediation roadmap",
        "info",
        T_KERBEROAST,
        "Ordered remediation plan derived from observed exposures — execute P0 items within 24h for internet-exposed AD.",
        target,
        0.99,
        Evidence::new().with("roadmap", Value::Array(steps)),
        "remediation_roadmap",
        &["CIS IG1", "NIST CSF PR.AC"],
        None,
    ));
}

// ─── Honest agent-guidance (capabilities that need host agent) ─────────────────

pub fn emit_agent_guidance(target: &str, cfg: &KerberosConfig, findings: &mut Vec<Value>) {
    if !cfg.emit_agent_guidance {
        return;
    }
    let capabilities = [
        (
            "credentialed_tgs_kerberoast",
            "Authenticated TGS-REQ / RC4 ticket capture for offline crack",
        ),
        (
            "bloodhound_acl_graph",
            "Full BloodHound ACE/ACL attack-path graph",
        ),
        (
            "gpo_laps_audit",
            "GPO, LAPS, and adminCount tier-0 policy audit on-DC",
        ),
        ("dcsync_surface", "DRSUAPI / DCSync permission enumeration"),
        (
            "internal_krbtgt",
            "KRBTGT hash rotation age + Golden Ticket indicators",
        ),
    ];
    for (cap, desc) in capabilities {
        findings.push(finding_rich(
            ENGINE_ID,
            &format!("Agent-required: {desc}"),
            "info",
            T_KERBEROAST,
            &format!(
                "This capability ({cap}) requires the Weissman host agent or internal AD vantage — \
                 not observable via external agentless scan. Deploy agent for full coverage."
            ),
            target,
            1.0,
            Evidence::new()
                .with("capability", cap)
                .with("requires_agent", true),
        ));
    }
}

// ─── Category sub-score finalization ─────────────────────────────────────────────

pub fn finalize_category_scores(sig: &mut AdSignals, findings: &[Value]) {
    for f in findings {
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("");
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("info");
        let penalty = match sev {
            "critical" => 40.0,
            "high" => 22.0,
            "medium" => 10.0,
            "low" => 4.0,
            _ => 0.0,
        };
        match cat {
            "port_exposure" | "dns_srv" | "msdcs_dns" => {
                sig.scores.dns_exposure = (sig.scores.dns_exposure - penalty).max(0.0);
            }
            "ldap_anonymous" | "ldap_starttls" | "ldap_enum" | "ldap_hardening" => {
                sig.scores.ldap_hardening = (sig.scores.ldap_hardening - penalty).max(0.0);
            }
            "kdc_liveness" | "krb_user_enum" => {
                sig.scores.kerberos_hardening = (sig.scores.kerberos_hardening - penalty).max(0.0);
            }
            "http_spnego" | "federation_exposure" => {
                sig.scores.spnego_surface = (sig.scores.spnego_surface - penalty).max(0.0);
            }
            "smb_signing" => {}
            "unconstrained_delegation" | "rbcd_exposure" => {
                sig.scores.delegation_risk = (sig.scores.delegation_risk - penalty).max(0.0);
            }
            "adcs_exposure" => {
                sig.scores.adcs_exposure = (sig.scores.adcs_exposure - penalty).max(0.0);
            }
            _ => {}
        }
    }
    if sig.smb_signing_required == Some(true) {
        sig.scores.relay_preconditions = 85.0;
    } else if sig.smb_signing_required == Some(false) {
        sig.scores.relay_preconditions = 10.0;
    } else if sig.open_ports.contains(&445) && sig.ldap_reachable {
        sig.scores.relay_preconditions = 35.0;
    }
}

pub fn enrich_posture_evidence(ev: Evidence, sig: &AdSignals) -> Evidence {
    ev.with("category_scores", json!(sig.scores.to_json()))
        .with(
            "unconstrained_delegation_count",
            sig.unconstrained_delegation.len(),
        )
        .with("rbcd_count", sig.rbcd_accounts.len())
        .with("machine_spn_count", sig.machine_spns.len())
        .with("adcs_exposed", sig.adcs_exposed)
        .with("user_enum_oracle", sig.user_enum_oracle)
        .with("smb_signing_required", json!(sig.smb_signing_required))
        .with("tier0_spn_count", sig.tier0_spns.len())
        .with(
            "constrained_delegation_count",
            sig.constrained_delegation.len(),
        )
        .with(
            "hybrid_entra_realm",
            sig.hybrid_entra_realm.as_deref().unwrap_or(""),
        )
        .with(
            "domain_functionality",
            sig.domain_functionality.as_deref().unwrap_or(""),
        )
}

pub fn extend_graph(nodes: &mut Vec<GraphNode>, edges: &mut Vec<GraphEdge>, sig: &AdSignals) {
    let mut add = |id: &str, label: &str, kind: &str| {
        nodes.push(GraphNode {
            id: id.to_string(),
            label: label.to_string(),
            node_type: "cloud_target".to_string(),
            status: "exposed".to_string(),
            cname_target: None,
            raw_finding: None,
        });
        edges.push(GraphEdge {
            id: format!("e_root_{id}"),
            from_id: "root".to_string(),
            to_id: id.to_string(),
            edge_type: kind.to_string(),
        });
    };
    if sig.adcs_exposed {
        add("adcs", "AD CS web enrollment", "ADCS_ESC");
    }
    if !sig.unconstrained_delegation.is_empty() {
        add("deleg", "unconstrained delegation", "DELEGATION");
    }
    if !sig.rbcd_accounts.is_empty() {
        add("rbcd", "RBCD misconfiguration", "RBCD");
    }
    if sig.user_enum_oracle {
        add("enum", "Kerberos user-enum oracle", "USER_ENUM");
    }
    if sig.smb_signing_required == Some(false) {
        edges.push(GraphEdge {
            id: "ap_relay".to_string(),
            from_id: "smb".to_string(),
            to_id: "ldap".to_string(),
            edge_type: "NTLM_RELAY".to_string(),
        });
    }
}

pub fn extend_attack_paths(target: &str, sig: &AdSignals, findings: &mut Vec<Value>) {
    if sig.adcs_exposed && sig.ldap_reachable {
        findings.push(attack_path_finding(
            "AD CS web enrollment + LDAP → ESC8/ESC1 certificate domain escalation",
            "critical",
            "T1649",
            "Internet-exposed Certificate Enrollment web interface alongside LDAP enables template misconfiguration abuse for DA certificates.",
            target,
            0.91,
            &[
                "discover /certsrv or /CertEnroll (this scan)",
                "enumerate vulnerable certificate templates via LDAP",
                "request certificate as low-priv user (ESC1/ESC8)",
                "use certificate for Kerberos PKINIT or authentication",
                "domain admin compromise",
            ],
            Evidence::new().with("adcs_exposed", true).with("ldap_reachable", sig.ldap_reachable),
        ));
    }
    if !sig.unconstrained_delegation.is_empty() && !sig.spnego_urls.is_empty() {
        findings.push(attack_path_finding(
            "Unconstrained delegation + internet SPNEGO → TGT theft",
            "critical",
            T_DELEGATION,
            &format!(
                "Service accounts with unconstrained delegation ({}) authenticate via internet SPNEGO — attacker captures TGTs for domain-wide impersonation.",
                sig.unconstrained_delegation.join(", ")
            ),
            target,
            0.92,
            &[
                "coerce delegated service to authenticate to attacker",
                "capture TGT from delegated account",
                "pass-the-ticket to any service in forest",
                "DCSync / Golden Ticket path",
            ],
            Evidence::new()
                .with("delegation_accounts", json!(sig.unconstrained_delegation))
                .with("spnego_urls", json!(sig.spnego_urls)),
        ));
    }
    if sig.user_enum_oracle && sig.kdc_live {
        findings.push(attack_path_finding(
            "Kerberos user-enum → password spray → Kerberoasting pipeline",
            "high",
            T_KERBEROAST,
            "Validated principals via KDC oracle enable targeted spray before SPN/TGS offline cracking.",
            target,
            0.85,
            &[
                "enumerate valid usernames via AS-REQ differential (this scan)",
                "low-and-slow password spray against validated accounts",
                "obtain any domain credential",
                "Kerberoast high-value SPNs / pivot to tier-0",
            ],
            Evidence::new().with("user_enum_oracle", true),
        ));
    }
}

// ─── Hybrid Entra / on-prem correlation (Microsoft GetUserRealm) ─────────────────

pub async fn scan_hybrid_entra(
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
    url: &str,
) {
    if !cfg.check_hybrid_entra || cfg.domain.is_empty() {
        return;
    }
    let client = http_client().await;
    let probe_user = format!("weissman-probe@{}", cfg.domain);
    let realm_url = format!(
        "https://login.microsoftonline.com/getuserrealm.srf?user={}&json=1",
        urlencoding::encode(&probe_user)
    );
    if let Ok(resp) = client.get(&realm_url).send().await {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let bl = body.to_ascii_lowercase();
        if status == 200 && !body.is_empty() {
            let ns_type = if bl.contains("\"managed\"") {
                "Managed"
            } else if bl.contains("\"federated\"") {
                "Federated"
            } else {
                "Unknown"
            };
            sig.hybrid_entra_realm = Some(ns_type.to_string());
            let sev = if ns_type == "Federated" {
                "medium"
            } else {
                "info"
            };
            findings.push(ad_finding(
                &format!("Microsoft Entra hybrid realm: {ns_type} ({})", cfg.domain),
                sev,
                T_DOMAIN_DISC,
                &format!(
                    "GetUserRealm for {probe_user} returned NameSpaceType={ns_type}. \
                     Federated domains expose ADFS as the internet Kerberos/SPNEGO pivot — correlate with SPNEGO findings."
                ),
                target,
                0.9,
                Evidence::new()
                    .with("url", &realm_url)
                    .with("namespace_type", ns_type)
                    .with("http_status", status)
                    .with("response_excerpt", body.chars().take(512).collect::<String>()),
                "hybrid_entra",
                &["Microsoft Entra ID", "Hybrid Identity"],
                Some("Harden ADFS/WAP; monitor federated sign-in anomalies; enforce CA policies on synced accounts."),
            ));
        }
    }
    // Autodiscover — Exchange/AD hybrid signal
    let auto_url = format!(
        "{}/autodiscover/autodiscover.xml",
        url.trim_end_matches('/')
    );
    if let Ok(resp) = client.get(&auto_url).send().await {
        let status = resp.status().as_u16();
        if status == 200 || status == 401 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("Autodiscover") || body.contains("RedirectAddr") {
                findings.push(ad_finding(
                    "Exchange Autodiscover endpoint exposed (hybrid mail)",
                    "medium",
                    T_DOMAIN_DISC,
                    &format!(
                        "Autodiscover responded at {auto_url} (HTTP {status}) — reveals hybrid Exchange topology and aids user enumeration."
                    ),
                    target,
                    0.82,
                    Evidence::new().with("url", &auto_url).with("http_status", status),
                    "hybrid_exchange",
                    &[],
                    None,
                ));
            }
        }
    }
}

// ─── LDAP rootDSE metadata (domain/forest functional level) ──────────────────────

fn domain_functionality_label(level: u32) -> &'static str {
    match level {
        0 => "Windows 2000 mixed/native",
        1 => "Windows Server 2003 interim",
        2 => "Windows Server 2003",
        3 => "Windows Server 2008",
        4 => "Windows Server 2008 R2",
        5 => "Windows Server 2012",
        6 => "Windows Server 2012 R2",
        7 => "Windows Server 2016",
        10 => "Windows Server 2025",
        _ if level >= 7 => "Windows Server 2016+",
        _ => "legacy",
    }
}

pub async fn scan_ldap_rootdse_meta(
    host: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if !cfg.check_ldap_enum {
        return;
    }
    let ldap_port = if sig.open_ports.contains(&389) {
        389u16
    } else if sig.open_ports.contains(&3268) {
        3268
    } else {
        return;
    };
    let root_filter = filter_present("objectClass");
    let root_search = ldap_search_request(
        8,
        "",
        0,
        &root_filter,
        &[
            "defaultNamingContext",
            "domainFunctionality",
            "forestFunctionality",
            "dnsHostName",
            "dsServiceName",
        ],
    );
    let msgs: Vec<&[u8]> = if sig.ldap_anon_ok {
        vec![LDAP_ANON_BIND, &root_search]
    } else if cfg.intensity == Intensity::Aggressive {
        vec![&root_search]
    } else {
        return;
    };
    if let Some(resp) = ldap_exchange(host, ldap_port, &msgs, cfg.timeout_ms).await {
        let strings = extract_ldap_strings(&resp);
        if sig.naming_context.is_none() {
            sig.naming_context = extract_naming_context(&strings);
        }
        // Heuristic: find standalone digit tokens 0-10 as functionality level
        for s in &strings {
            if let Ok(n) = s.parse::<u32>() {
                if n <= 10 {
                    let label = domain_functionality_label(n);
                    sig.domain_functionality = Some(format!("{n} ({label})"));
                    findings.push(ad_finding(
                        &format!("AD domain functional level: {label}"),
                        if n < 7 { "medium" } else { "info" },
                        T_DOMAIN_DISC,
                        &format!(
                            "rootDSE domainFunctionality={n} ({label}) on {host}:{ldap_port}. \
                             Legacy functional levels may lack modern Kerberos hardening (AES-only, FAST)."
                        ),
                        target,
                        0.85,
                        Evidence::new()
                            .with("host", host)
                            .with("level", n)
                            .with("label", label),
                        "ldap_rootdse",
                        &["CIS Microsoft Windows Server"],
                        Some("Raise domain/forest functional level; enforce AES256 for Kerberos; disable RC4 where possible."),
                    ));
                    break;
                }
            }
        }
    }
}

// ─── Tier-0 Kerberoastable SPNs (adminCount=1) ───────────────────────────────────

pub async fn scan_tier0_kerberoast_spns(
    host: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if !cfg.check_tier0_spns || !cfg.check_ldap_enum {
        return;
    }
    let ldap_port = if sig.open_ports.contains(&389) {
        389u16
    } else if sig.open_ports.contains(&3268) {
        3268
    } else {
        return;
    };
    let nc = match &sig.naming_context {
        Some(n) => n.clone(),
        None => return,
    };
    if !(sig.ldap_anon_ok || cfg.intensity == Intensity::Aggressive) {
        return;
    }
    let filter = filter_and(&[
        &filter_equality("objectCategory", "person"),
        &filter_equality("adminCount", "1"),
        &filter_present("servicePrincipalName"),
    ]);
    let search = ldap_search_request(
        9,
        &nc,
        2,
        &filter,
        &["sAMAccountName", "servicePrincipalName", "adminCount"],
    );
    let msgs: Vec<&[u8]> = if sig.ldap_anon_ok {
        vec![LDAP_ANON_BIND, &search]
    } else {
        vec![&search]
    };
    if let Some(resp) = ldap_exchange(host, ldap_port, &msgs, cfg.timeout_ms).await {
        let strings = extract_ldap_strings(&resp);
        sig.tier0_spns = extract_spns(&strings);
        if !sig.tier0_spns.is_empty() {
            sig.scores.delegation_risk = 0.0;
            findings.push(ad_finding(
                &format!(
                    "TIER-0 Kerberoastable: {} privileged SPN(s) on adminCount=1 accounts",
                    sig.tier0_spns.len()
                ),
                "critical",
                T_KERBEROAST,
                &format!(
                    "adminCount=1 accounts with servicePrincipalName: {}. \
                     Offline crack of any of these SPNs is a direct tier-0 / domain-admin path.",
                    sig.tier0_spns.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                ),
                target,
                0.96,
                Evidence::new()
                    .with("spn_count", sig.tier0_spns.len())
                    .with("spn_sample", json!(sig.tier0_spns.iter().take(8).collect::<Vec<_>>())),
                "tier0_kerberoast",
                &["MITRE T1558.003", "Tier Model"],
                Some("Never set SPNs on tier-0 accounts; use group-managed service accounts; enforce 25+ char random passwords."),
            ));
        }
    }
}

// ─── Constrained delegation exposure ─────────────────────────────────────────────

pub async fn scan_constrained_delegation(
    host: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if !cfg.check_delegation || !cfg.check_ldap_enum {
        return;
    }
    let ldap_port = if sig.open_ports.contains(&389) {
        389u16
    } else if sig.open_ports.contains(&3268) {
        3268
    } else {
        return;
    };
    let nc = match &sig.naming_context {
        Some(n) => n.clone(),
        None => return,
    };
    if !(sig.ldap_anon_ok || cfg.intensity == Intensity::Aggressive) {
        return;
    }
    let filter = filter_present("msDS-AllowedToDelegateTo");
    let search = ldap_search_request(
        10,
        &nc,
        2,
        &filter,
        &["sAMAccountName", "msDS-AllowedToDelegateTo"],
    );
    let msgs: Vec<&[u8]> = if sig.ldap_anon_ok {
        vec![LDAP_ANON_BIND, &search]
    } else {
        vec![&search]
    };
    if let Some(resp) = ldap_exchange(host, ldap_port, &msgs, cfg.timeout_ms).await {
        let strings = extract_ldap_strings(&resp);
        sig.constrained_delegation = extract_sam_accounts(&strings);
        if !sig.constrained_delegation.is_empty() {
            sig.scores.delegation_risk = sig.scores.delegation_risk.min(15.0);
            findings.push(ad_finding(
                &format!(
                    "{} constrained delegation principal(s) enumerable",
                    sig.constrained_delegation.len()
                ),
                "high",
                T_DELEGATION,
                &format!(
                    "Accounts/computers with msDS-AllowedToDelegateTo: {}. \
                     Combined with protocol transition, enables S4U2Self/S4U2Proxy impersonation chains.",
                    sig.constrained_delegation.join(", ")
                ),
                target,
                0.88,
                Evidence::new().with("accounts", json!(sig.constrained_delegation)),
                "constrained_delegation",
                &["MITRE T1558"],
                Some("Audit constrained delegation; remove protocol transition where not required; monitor Event 4769 S4U."),
            ));
        }
    }
}

// ─── LDAPS TLS certificate probe (real openssl handshake) ────────────────────────

pub async fn scan_ldaps_tls(
    host: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if !cfg.check_ldaps_tls {
        return;
    }
    let port = if sig.open_ports.contains(&636) {
        636u16
    } else if sig.open_ports.contains(&3269) {
        3269
    } else {
        return;
    };
    let host_owned = host.to_string();
    let timeout_ms = cfg.timeout_ms;
    let result = tokio::task::spawn_blocking(move || {
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
        use std::net::TcpStream as StdTcpStream;
        let mut builder = SslConnector::builder(SslMethod::tls_client()).ok()?;
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();
        let addr = format!("{host_owned}:{port}");
        let stream = StdTcpStream::connect(&addr).ok()?;
        let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
        let ssl = connector.connect(host_owned.as_str(), stream).ok()?;
        let cert = ssl.ssl().peer_certificate()?;
        let not_after = cert.not_after().to_string();
        let issuer = format!("{:?}", cert.issuer_name());
        let subject = format!("{:?}", cert.subject_name());
        Some((not_after, issuer, subject))
    })
    .await
    .ok()
    .flatten();

    if let Some((not_after, issuer, subject)) = result {
        findings.push(ad_finding(
            &format!("LDAPS certificate observed on {host}:{port}"),
            "info",
            T_DOMAIN_DISC,
            &format!(
                "Live TLS handshake on LDAPS {host}:{port}. Subject: {subject}. Issuer: {issuer}. NotAfter: {not_after}. \
                 Verify enterprise CA chain and disable weak ciphers on LDAPS."
            ),
            target,
            0.92,
            Evidence::new()
                .with("host", host)
                .with("port", port)
                .with("subject", subject)
                .with("issuer", issuer)
                .with("not_after", not_after),
            "ldaps_tls",
            &["NIST SC-8", "NIST SC-13"],
            Some("Use enterprise CA for LDAPS; enforce TLS 1.2+; enable LDAP channel binding (EPA)."),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig() -> AdSignals {
        AdSignals::new("corp.example".to_string())
    }

    #[test]
    fn nbss_wrap_encodes_length_big_endian() {
        // Small payload: header carries the 3-byte length.
        assert_eq!(nbss_wrap(&[0xAA, 0xBB]), vec![0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
        assert_eq!(nbss_wrap(&[]), vec![0x00, 0x00, 0x00, 0x00]);
        // 300 bytes = 0x00012C -> out[1]=0, out[2]=1, out[3]=0x2C.
        let payload = vec![0u8; 300];
        let wrapped = nbss_wrap(&payload);
        assert_eq!(wrapped.len(), 304);
        assert_eq!(&wrapped[0..4], &[0x00, 0x00, 0x01, 0x2C]);
    }

    #[test]
    fn smb2_negotiate_req_shape() {
        let req = smb2_negotiate_req();
        // 4 (NBSS) + 64 (header) + 36 (body) + 8 (4 dialects) = 112.
        assert_eq!(req.len(), 112);
        // NBSS length header for a 108-byte SMB message.
        assert_eq!(&req[0..4], &[0x00, 0x00, 0x00, 108]);
        // SMB2 magic follows the NBSS header.
        assert_eq!(&req[4..8], &[0xFE, b'S', b'M', b'B']);
        // Dialect list trailer: 0x0202, 0x0210, 0x0300, 0x0302 (LE).
        assert_eq!(
            &req[104..112],
            &[0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03]
        );
    }

    #[test]
    fn parse_smb2_security_mode_flags() {
        let mut resp = vec![0u8; 72];
        resp[4..8].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        // SecurityMode lives at smb[66..68] == resp[70..72].
        resp[70] = 0x03;
        assert_eq!(parse_smb2_security_mode(&resp), Some((true, true)));
        resp[70] = 0x01;
        assert_eq!(parse_smb2_security_mode(&resp), Some((true, false)));
        resp[70] = 0x02;
        assert_eq!(parse_smb2_security_mode(&resp), Some((false, true)));
        resp[70] = 0x00;
        assert_eq!(parse_smb2_security_mode(&resp), Some((false, false)));
    }

    #[test]
    fn parse_smb2_security_mode_rejects_bad_input() {
        // Too short.
        assert_eq!(parse_smb2_security_mode(&[0u8; 71]), None);
        // Long enough but wrong SMB magic.
        let resp = vec![0u8; 72];
        assert_eq!(parse_smb2_security_mode(&resp), None);
    }

    #[test]
    fn as_req_for_principal_exact_encoding() {
        // Deterministic DER-ish AS-REQ for realm "R", user "ab".
        let expected: Vec<u8> = vec![
            0x6a, 0x1d, 0x02, 0x01, 0x05, 0x02, 0x01, 0x0a, 0x30, 0x00, 0x02, 0x01, 0x05, 0x02,
            0x01, 0x0a, 0xa3, 0x0f, 0x30, 0x08, 0x02, 0x01, 0x01, 0x30, 0x04, 0x02, 0x61, 0x62,
            0x1b, 0x01, 0x52, 0x30, 0x00,
        ];
        assert_eq!(as_req_for_principal("R", "ab"), expected);
    }

    #[test]
    fn as_req_for_principal_embeds_identifiers() {
        let req = as_req_for_principal("EXAMPLE.COM", "svc_sql");
        // Outer application tag.
        assert_eq!(req[0], 0x6a);
        // The username bytes appear verbatim.
        assert!(req.windows(7).any(|w| w == b"svc_sql"));
        // The realm bytes appear verbatim.
        assert!(req.windows(11).any(|w| w == b"EXAMPLE.COM"));
    }

    #[test]
    fn krb_error_code_extracts_and_defaults() {
        // 0x7e KRB-ERROR marker, INTEGER (0x02 len 1) -> value 25 (PREAUTH_REQUIRED).
        assert_eq!(krb_error_code(&[0x7e, 0x00, 0x02, 0x01, 25, 0, 0, 0]), Some(25));
        // Marker not at index 0.
        assert_eq!(
            krb_error_code(&[0x00, 0x7e, 0x00, 0x02, 0x01, 6, 0, 0, 0]),
            Some(6)
        );
        // No marker -> None.
        assert_eq!(krb_error_code(&[0x00, 0x01, 0x02, 0x03]), None);
        // Marker present but too near the end (bounds check fails) -> None.
        assert_eq!(krb_error_code(&[0x7e, 0x00, 0x02, 0x01, 25]), None);
    }

    #[test]
    fn domain_functionality_label_mapping() {
        assert_eq!(domain_functionality_label(0), "Windows 2000 mixed/native");
        assert_eq!(domain_functionality_label(2), "Windows Server 2003");
        assert_eq!(domain_functionality_label(3), "Windows Server 2008");
        assert_eq!(domain_functionality_label(7), "Windows Server 2016");
        assert_eq!(domain_functionality_label(10), "Windows Server 2025");
        // Values >= 7 that are not explicitly mapped fall to the generic bucket.
        assert_eq!(domain_functionality_label(8), "Windows Server 2016+");
        assert_eq!(domain_functionality_label(9), "Windows Server 2016+");
    }

    #[test]
    fn emit_toxic_headline_no_combos_is_noop() {
        let s = sig();
        let mut findings: Vec<Value> = Vec::new();
        emit_toxic_headline("t", &s, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn emit_toxic_headline_asrep_combo() {
        let mut s = sig();
        s.asrep_accounts = vec!["u1".to_string(), "u2".to_string()];
        let mut findings: Vec<Value> = Vec::new();
        emit_toxic_headline("t", &s, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].get("severity").and_then(Value::as_str), Some("critical"));
        assert!(findings[0]
            .get("title")
            .and_then(Value::as_str)
            .unwrap()
            .contains("TOXIC COMBINATION"));
        assert_eq!(
            findings[0].get("category").and_then(Value::as_str),
            Some("toxic_combination")
        );
    }

    #[test]
    fn emit_remediation_roadmap_always_emits() {
        // Two unconditional P2 steps guarantee a roadmap even with no exposures.
        let s = sig();
        let mut findings: Vec<Value> = Vec::new();
        emit_remediation_roadmap("t", &s, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].get("severity").and_then(Value::as_str), Some("info"));
        assert_eq!(
            findings[0].get("category").and_then(Value::as_str),
            Some("remediation_roadmap")
        );
    }

    #[test]
    fn finalize_category_scores_applies_penalty() {
        let mut s = sig();
        let findings = vec![json!({"category": "adcs_exposure", "severity": "critical"})];
        finalize_category_scores(&mut s, &findings);
        // 100 - 40 (critical penalty) = 60.
        assert_eq!(s.scores.adcs_exposure, 60.0);
    }

    #[test]
    fn finalize_category_scores_ldap_and_relay() {
        let mut s = sig();
        let findings = vec![json!({"category": "ldap_anonymous", "severity": "high"})];
        finalize_category_scores(&mut s, &findings);
        // high penalty 22 -> 78.
        assert_eq!(s.scores.ldap_hardening, 78.0);

        let mut s2 = sig();
        s2.smb_signing_required = Some(false);
        finalize_category_scores(&mut s2, &[]);
        assert_eq!(s2.scores.relay_preconditions, 10.0);

        let mut s3 = sig();
        s3.smb_signing_required = Some(true);
        finalize_category_scores(&mut s3, &[]);
        assert_eq!(s3.scores.relay_preconditions, 85.0);
    }

    #[test]
    fn extend_graph_adds_nodes_for_exposures() {
        let mut s = sig();
        let mut nodes: Vec<GraphNode> = Vec::new();
        let mut edges: Vec<GraphEdge> = Vec::new();
        // No exposures -> nothing added.
        extend_graph(&mut nodes, &mut edges, &s);
        assert!(nodes.is_empty());
        assert!(edges.is_empty());

        s.adcs_exposed = true;
        extend_graph(&mut nodes, &mut edges, &s);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "adcs");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].edge_type, "ADCS_ESC");
    }

    #[test]
    fn extend_graph_relay_edge_without_node() {
        let mut s = sig();
        s.smb_signing_required = Some(false);
        let mut nodes: Vec<GraphNode> = Vec::new();
        let mut edges: Vec<GraphEdge> = Vec::new();
        extend_graph(&mut nodes, &mut edges, &s);
        assert!(nodes.is_empty());
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].id, "ap_relay");
        assert_eq!(edges[0].edge_type, "NTLM_RELAY");
    }

    #[test]
    fn extend_attack_paths_adcs_ldap() {
        let mut s = sig();
        let mut findings: Vec<Value> = Vec::new();
        extend_attack_paths("t", &s, &mut findings);
        assert!(findings.is_empty());

        s.adcs_exposed = true;
        s.ldap_reachable = true;
        extend_attack_paths("t", &s, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].get("severity").and_then(Value::as_str), Some("critical"));
        assert!(findings[0].get("attack_path").is_some());
    }

    #[test]
    fn enrich_posture_evidence_reports_counts() {
        let s = sig();
        let v = enrich_posture_evidence(Evidence::new(), &s).into_value();
        assert_eq!(v["adcs_exposed"].as_bool(), Some(false));
        assert_eq!(v["rbcd_count"].as_u64(), Some(0));
        assert_eq!(v["unconstrained_delegation_count"].as_u64(), Some(0));
        assert!(v["smb_signing_required"].is_null());

        let mut s2 = sig();
        s2.adcs_exposed = true;
        s2.unconstrained_delegation = vec!["svc$".to_string()];
        s2.smb_signing_required = Some(true);
        let v2 = enrich_posture_evidence(Evidence::new(), &s2).into_value();
        assert_eq!(v2["adcs_exposed"].as_bool(), Some(true));
        assert_eq!(v2["unconstrained_delegation_count"].as_u64(), Some(1));
        assert_eq!(v2["smb_signing_required"].as_bool(), Some(true));
    }
}
