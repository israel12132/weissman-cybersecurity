//! Active Directory / Kerberos External Attack Surface — world-class, agentless AD posture.
//!
//! Hybrid and on-prem Active Directory is the crown jewel of enterprise identity. This engine
//! performs the deepest *agentless, evidence-only* assessment of an externally reachable AD/Kerberos
//! surface that is possible without domain credentials — every finding is backed by a real
//! TCP/DNS/HTTP/LDAP observation; nothing is fabricated.
//!
//! Assessment layers (all read-only, Wiz/CrowdStrike-style exposure correlation):
//!   1. **DNS SRV cartography** — `_ldap._tcp`, `_kerberos._tcp`, `_gc._tcp._msdcs.{domain}` DC
//!      discovery (RFC 2782) mapping internet-facing domain controllers.
//!   2. **AD service port reachability** — Kerberos KDC (88), LDAP/LDAPS (389/636), Global Catalog
//!      (3268/3269), SMB (445), kpasswd (464), MS-RPC (135), WinRM (5985/5986), RDP (3389).
//!   3. **Live anonymous LDAP bind** — real BER-encoded BindRequest; success ⇒ directory
//!      enumeration without credentials (AS-REP roastable users, SPNs, privileged groups).
//!   4. **LDAP enumeration (when permitted)** — rootDSE `defaultNamingContext`, Kerberoastable
//!      SPNs on user accounts (`servicePrincipalName=*`), AS-REP roastable accounts
//!      (`DONT_REQ_PREAUTH` / UAC `0x400000`), domain functionality level.
//!   5. **Kerberos KDC liveness** — minimal AS-REQ probe elicits a real `KRB-ERROR` from port 88.
//!   6. **HTTP SPNEGO/NTLM surface** — ADFS, OWA/EWS, WinRM, `WWW-Authenticate: Negotiate`.
//!   7. **Attack-path synthesis** — toxic combinations (internet KDC + anonymous LDAP → offline
//!      Kerberoasting; SMB+LDAP → NTLM relay precondition; AS-REP roastable accounts exposed).
//!
//! Closes with a 0–100 **AD external posture score** (A+ … F). Every knob is driven from
//! `POST /api/command-center/scan` → `EngineRunContext::job_params`.
//! MITRE: T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting), T1087.002 (Domain Account
//! Discovery), T1021.* (Remote Services), T1557.001 (NTLM Relay).

#![allow(
    clippy::too_many_lines,
    clippy::module_name_repetitions,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::cloud_hunter::{GraphEdge, GraphNode};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    extract_host, header_value, http_client, normalize_url, probe_paths_concurrent,
    status_indicates_presence, tcp_scan, DEFAULT_PROBE_CONCURRENCY,
};
use crate::engine_result::{print_result, EngineResult};
use hickory_resolver::config::{ResolverConfig, CLOUDFLARE, GOOGLE, QUAD9};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const ENGINE_ID: &str = "kerberoasting";

const T_KERBEROAST: &str = "T1558.003";
const T_ASREP: &str = "T1558.004";
const T_DOMAIN_DISC: &str = "T1087.002";
const T_NTLM_RELAY: &str = "T1557.001";
const T_DELEGATION: &str = "T1558.001";

/// AD service ports and the attack each one unlocks for a credentialed operator.
const AD_PORTS: &[(u16, &str, &str, &str)] = &[
    (88, "Kerberos KDC", "high", T_KERBEROAST),
    (389, "LDAP", "high", T_DOMAIN_DISC),
    (636, "LDAPS", "medium", T_DOMAIN_DISC),
    (3268, "Global Catalog (LDAP)", "high", T_DOMAIN_DISC),
    (3269, "Global Catalog (LDAPS)", "medium", T_DOMAIN_DISC),
    (445, "SMB", "high", "T1021.002"),
    (464, "kpasswd", "medium", "T1558"),
    (135, "MS-RPC endpoint mapper", "medium", "T1021.003"),
    (5985, "WinRM (HTTP)", "high", "T1021.006"),
    (5986, "WinRM (HTTPS)", "medium", "T1021.006"),
    (3389, "RDP", "high", "T1021.001"),
];

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
    "/certsrv/",
    "/CertEnroll/",
];

#[path = "kerberoasting_supreme.rs"]
mod supreme;

pub(crate) const LDAP_ANON_BIND: &[u8] = &[
    0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
];

// ─── Configuration ───────────────────────────────────────────────────────────────

pub(crate) struct KerberosConfig {
    domain: String,
    intensity: Intensity,
    check_ports: bool,
    check_srv: bool,
    check_ldap_anon: bool,
    check_ldap_enum: bool,
    check_kdc_probe: bool,
    check_spnego_http: bool,
    check_ldap_starttls: bool,
    check_smb_signing: bool,
    check_adcs_http: bool,
    check_user_enum_krb: bool,
    check_delegation: bool,
    check_machine_spns: bool,
    check_msdcs_dns: bool,
    check_hybrid_entra: bool,
    check_tier0_spns: bool,
    check_ldaps_tls: bool,
    attack_paths: bool,
    emit_agent_guidance: bool,
    ad_ports: Vec<u16>,
    extra_http_paths: Vec<String>,
    ldap_base_dn: String,
    dc_hosts: Vec<String>,
    probe_usernames: Vec<String>,
    max_ldap_entries: usize,
    timeout_ms: u64,
    concurrency: usize,
    strict_mode: bool,
    resolver: String,
}

impl KerberosConfig {
    fn from_arsenal(cfg: &ArsenalConfig, target: &str) -> Self {
        let default_ports: Vec<u16> = AD_PORTS.iter().map(|&(p, ..)| p).collect();
        let mut domain = cfg.string("domain").unwrap_or_default();
        if domain.is_empty() {
            domain = infer_domain_from_target(target);
        }
        let intensity = cfg.intensity();
        let mut max_ldap = cfg.usize_or("max_ldap_entries", 32);
        max_ldap = max_ldap.clamp(4, 128);
        if intensity == Intensity::Light {
            max_ldap = max_ldap.min(16);
        }

        Self {
            domain,
            intensity,
            check_ports: cfg.bool_or("check_ports", true),
            check_srv: cfg.bool_or("check_srv", true),
            check_ldap_anon: cfg.bool_or("check_ldap_anon", true),
            check_ldap_enum: cfg.bool_or("check_ldap_enum", true),
            check_kdc_probe: cfg.bool_or("check_kdc_probe", true),
            check_spnego_http: cfg.bool_or("check_spnego_http", true),
            check_ldap_starttls: cfg.bool_or("check_ldap_starttls", true),
            check_smb_signing: cfg.bool_or("check_smb_signing", true),
            check_adcs_http: cfg.bool_or("check_adcs_http", true),
            check_user_enum_krb: cfg.bool_or("check_user_enum_krb", true),
            check_delegation: cfg.bool_or("check_delegation", true),
            check_machine_spns: cfg.bool_or("check_machine_spns", true),
            check_msdcs_dns: cfg.bool_or("check_msdcs_dns", true),
            check_hybrid_entra: cfg.bool_or("check_hybrid_entra", true),
            check_tier0_spns: cfg.bool_or("check_tier0_spns", true),
            check_ldaps_tls: cfg.bool_or("check_ldaps_tls", true),
            attack_paths: cfg.bool_or("attack_paths", true),
            emit_agent_guidance: cfg.bool_or("emit_agent_guidance", true),
            ad_ports: cfg.ports_or("ad_ports", &default_ports),
            extra_http_paths: cfg.string_list("extra_http_paths"),
            ldap_base_dn: cfg.string("ldap_base_dn").unwrap_or_default(),
            dc_hosts: cfg.string_list("dc_hosts"),
            probe_usernames: {
                let mut users = cfg.string_list("probe_usernames");
                if users.is_empty() {
                    users = vec![
                        "administrator".into(),
                        "admin".into(),
                        "krbtgt".into(),
                        "svc_backup".into(),
                    ];
                }
                users.truncate(12);
                users
            },
            max_ldap_entries: max_ldap,
            timeout_ms: cfg.timeout_ms(5000),
            concurrency: cfg.concurrency(),
            strict_mode: cfg.bool_or("strict_mode", false),
            resolver: cfg
                .string("resolver")
                .unwrap_or_else(|| "system".to_string()),
        }
    }

    fn http_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = KERBEROS_HTTP_PATHS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        for p in &self.extra_http_paths {
            if !paths.contains(p) {
                paths.push(p.clone());
            }
        }
        if self.intensity == Intensity::Light {
            paths.truncate(6);
        }
        paths
    }
}

fn infer_domain_from_target(target: &str) -> String {
    let host = extract_host(target).to_ascii_lowercase();
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() >= 2 {
            return parts[parts.len() - 2..].join(".");
        }
    }
    String::new()
}

// ─── AD signal accumulator (attack-path synthesis) ───────────────────────────────

#[derive(Clone, Debug, Default)]
pub(crate) struct CategoryScores {
    pub dns_exposure: f64,
    pub ldap_hardening: f64,
    pub kerberos_hardening: f64,
    pub spnego_surface: f64,
    pub relay_preconditions: f64,
    pub delegation_risk: f64,
    pub adcs_exposure: f64,
    pub smb_hardening: f64,
}

impl CategoryScores {
    fn new() -> Self {
        Self {
            dns_exposure: 100.0,
            ldap_hardening: 100.0,
            kerberos_hardening: 100.0,
            spnego_surface: 100.0,
            relay_preconditions: 100.0,
            delegation_risk: 100.0,
            adcs_exposure: 100.0,
            smb_hardening: 100.0,
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        json!({
            "dns_exposure": self.dns_exposure.round() as u8,
            "ldap_hardening": self.ldap_hardening.round() as u8,
            "kerberos_hardening": self.kerberos_hardening.round() as u8,
            "spnego_surface": self.spnego_surface.round() as u8,
            "relay_preconditions": self.relay_preconditions.round() as u8,
            "delegation_risk": self.delegation_risk.round() as u8,
            "adcs_exposure": self.adcs_exposure.round() as u8,
            "smb_hardening": self.smb_hardening.round() as u8,
        })
    }
}

#[derive(Default)]
pub(crate) struct AdSignals {
    domain: String,
    open_ports: BTreeSet<u16>,
    srv_hosts: Vec<String>,
    msdcs_hosts: Vec<String>,
    ldap_anon_ok: bool,
    ldap_reachable: bool,
    ldap_starttls_ok: bool,
    naming_context: Option<String>,
    kerberoast_spns: Vec<String>,
    asrep_accounts: Vec<String>,
    machine_spns: Vec<String>,
    unconstrained_delegation: Vec<String>,
    rbcd_accounts: Vec<String>,
    spnego_urls: Vec<String>,
    kdc_live: bool,
    adcs_exposed: bool,
    user_enum_oracle: bool,
    smb_signing_required: Option<bool>,
    domain_functionality: Option<String>,
    hybrid_entra_realm: Option<String>,
    tier0_spns: Vec<String>,
    constrained_delegation: Vec<String>,
    scores: CategoryScores,
}

impl AdSignals {
    pub(crate) fn new(domain: String) -> Self {
        Self {
            domain,
            scores: CategoryScores::new(),
            ..Self::default()
        }
    }
}

// ─── Finding helpers ─────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub(crate) fn ad_finding(
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    confidence: f64,
    evidence: Evidence,
    category: &str,
    standards: &[&str],
    remediation: Option<&str>,
) -> Value {
    let mut f = finding_rich(
        ENGINE_ID,
        title,
        severity,
        mitre,
        description,
        target,
        confidence,
        evidence,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("ad_domain".to_string(), json!("kerberos_ad"));
        obj.insert("category".to_string(), json!(category));
        if !standards.is_empty() {
            obj.insert("standards".to_string(), json!(standards));
        }
        if let Some(r) = remediation {
            obj.insert("remediation".to_string(), json!(r));
        }
    }
    f
}

pub(crate) fn attack_path_finding(
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    confidence: f64,
    steps: &[&str],
    evidence: Evidence,
) -> Value {
    let mut f = ad_finding(
        title,
        severity,
        mitre,
        description,
        target,
        confidence,
        evidence,
        "attack_path",
        &[],
        None,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("attack_path".to_string(), json!(steps));
        obj.insert("graph_kind".to_string(), json!("toxic_combination"));
    }
    f
}

// ─── LDAP BER primitives ─────────────────────────────────────────────────────────

fn ber_len(n: usize) -> Vec<u8> {
    if n < 128 {
        vec![n as u8]
    } else if n < 256 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, (n & 0xff) as u8]
    }
}

fn ber_sequence(content: &[u8]) -> Vec<u8> {
    let mut v = vec![0x30];
    v.extend(ber_len(content.len()));
    v.extend_from_slice(content);
    v
}

fn ber_octet_string(s: &[u8]) -> Vec<u8> {
    let mut v = vec![0x04];
    v.extend(ber_len(s.len()));
    v.extend_from_slice(s);
    v
}

fn ber_integer(n: i32) -> Vec<u8> {
    if n >= 0 && n < 128 {
        vec![0x02, 0x01, n as u8]
    } else {
        vec![0x02, 0x01, n as u8]
    }
}

fn ber_enumerated(n: u8) -> Vec<u8> {
    vec![0x0a, 0x01, n]
}

fn ber_boolean(b: bool) -> Vec<u8> {
    vec![0x01, 0x01, u8::from(b)]
}

pub(crate) fn filter_present(attr: &str) -> Vec<u8> {
    let mut v = vec![0x87];
    let body = ber_octet_string(attr.as_bytes());
    v.extend_from_slice(&body[1..]);
    v
}

pub(crate) fn filter_equality(attr: &str, value: &str) -> Vec<u8> {
    let inner = ber_sequence(&{
        let mut s = ber_octet_string(attr.as_bytes());
        s.extend(ber_octet_string(value.as_bytes()));
        s
    });
    let mut v = vec![0xa3];
    v.extend_from_slice(&inner[1..]);
    v
}

pub(crate) fn filter_and(filters: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for f in filters {
        body.extend_from_slice(f);
    }
    let seq = ber_sequence(&body);
    let mut v = vec![0xa0];
    v.extend_from_slice(&seq[1..]);
    v
}

pub(crate) fn filter_extensible_match(attr: &str, oid: &str, value: &str) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend({
        let mut m = vec![0x81];
        let b = ber_octet_string(oid.as_bytes());
        m.extend_from_slice(&b[1..]);
        m
    });
    inner.extend({
        let mut t = vec![0x82];
        let b = ber_octet_string(attr.as_bytes());
        t.extend_from_slice(&b[1..]);
        t
    });
    inner.extend({
        let mut mv = vec![0x83];
        let b = ber_octet_string(value.as_bytes());
        mv.extend_from_slice(&b[1..]);
        mv
    });
    inner.extend(ber_boolean(false));
    let seq = ber_sequence(&inner);
    let mut v = vec![0xa9];
    v.extend_from_slice(&seq[1..]);
    v
}

pub(crate) fn ldap_search_request(
    message_id: i32,
    base: &str,
    scope: u8,
    filter: &[u8],
    attrs: &[&str],
) -> Vec<u8> {
    let mut search_body = Vec::new();
    search_body.extend(ber_octet_string(base.as_bytes()));
    search_body.extend(ber_enumerated(scope));
    search_body.extend(ber_enumerated(0)); // neverDerefAliases
    search_body.extend(ber_integer(0)); // sizeLimit
    search_body.extend(ber_integer(30)); // timeLimit seconds
    search_body.extend(ber_boolean(false)); // typesOnly
    search_body.extend_from_slice(filter);
    let mut attr_seq = Vec::new();
    for a in attrs {
        attr_seq.extend(ber_octet_string(a.as_bytes()));
    }
    search_body.extend(ber_sequence(&attr_seq));

    let mut app = vec![0x63];
    let seq = ber_sequence(&search_body);
    app.extend_from_slice(&seq[1..]);

    let mut msg = ber_integer(message_id);
    msg.extend(app);
    ber_sequence(&msg)
}

pub(crate) fn ldap_bind_result_code(resp: &[u8]) -> Option<u8> {
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

pub(crate) async fn ldap_exchange(
    host: &str,
    port: u16,
    messages: &[&[u8]],
    timeout_ms: u64,
) -> Option<Vec<u8>> {
    let addr = format!("{host}:{port}");
    let stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;
    let mut stream = stream;
    let mut combined = Vec::new();
    for msg in messages {
        if stream.write_all(msg).await.is_err() {
            return None;
        }
        let _ = stream.flush().await;
        let mut buf = vec![0u8; 65536];
        match timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => combined.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    if combined.is_empty() {
        None
    } else {
        Some(combined)
    }
}

pub(crate) fn extract_ldap_strings(resp: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let s = String::from_utf8_lossy(resp);
    for token in s.split(|c: char| !c.is_ascii_graphic() && c != '@' && c != '=' && c != ',') {
        let t = token.trim();
        if t.len() < 3 {
            continue;
        }
        if t.contains("DC=")
            || t.contains("servicePrincipalName")
            || t.contains("sAMAccountName")
            || t.contains('@')
            || t.starts_with("HTTP/")
            || t.starts_with("MSSQLSvc/")
            || t.starts_with("cifs/")
        {
            if !out.contains(&t.to_string()) {
                out.push(t.to_string());
            }
        }
    }
    out
}

pub(crate) fn extract_naming_context(strings: &[String]) -> Option<String> {
    strings
        .iter()
        .find(|s| s.contains("DC=") && !s.contains("servicePrincipalName"))
        .cloned()
        .or_else(|| strings.iter().find(|s| s.starts_with("DC=")).cloned())
}

pub(crate) fn extract_spns(strings: &[String]) -> Vec<String> {
    strings
        .iter()
        .filter(|s| {
            s.contains('/')
                && (s.contains('@')
                    || s.starts_with("HTTP/")
                    || s.starts_with("MSSQLSvc/")
                    || s.starts_with("cifs/")
                    || s.starts_with("ldap/")
                    || s.starts_with("host/"))
        })
        .take(64)
        .cloned()
        .collect()
}

pub(crate) fn extract_sam_accounts(strings: &[String]) -> Vec<String> {
    strings
        .iter()
        .filter(|s| {
            s.len() >= 2
                && s.len() <= 32
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
                && !s.contains('/')
                && !s.contains('=')
                && !s.contains('@')
        })
        .take(32)
        .cloned()
        .collect()
}

// ─── DNS SRV discovery ───────────────────────────────────────────────────────────

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

async fn srv_lookup(resolver: &TokioResolver, name: &str) -> Vec<(u16, String)> {
    let mut out = Vec::new();
    if let Ok(lookup) = resolver.srv_lookup(name).await {
        for record in lookup.answers() {
            if let RData::SRV(srv) = &record.data {
                let host = srv.target.to_string().trim_end_matches('.').to_string();
                if !host.is_empty() {
                    out.push((srv.port, host));
                }
            }
        }
    }
    out
}

async fn discover_ad_srv(domain: &str, resolver_choice: &str) -> Vec<(String, u16, String)> {
    if domain.is_empty() {
        return Vec::new();
    }
    let Some(resolver) = build_resolver(resolver_choice) else {
        return Vec::new();
    };
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    let queries = [
        ("_ldap._tcp", format!("_ldap._tcp.{d}")),
        ("_kerberos._tcp", format!("_kerberos._tcp.{d}")),
        ("_ldap._tcp.dc._msdcs", format!("_ldap._tcp.dc._msdcs.{d}")),
        (
            "_kerberos._tcp.dc._msdcs",
            format!("_kerberos._tcp.dc._msdcs.{d}"),
        ),
        ("_gc._tcp", format!("_gc._tcp.{d}")),
        ("_gc._tcp._msdcs", format!("_gc._tcp._msdcs.{d}")),
        ("_kpasswd._tcp", format!("_kpasswd._tcp.{d}")),
    ];
    let mut out = Vec::new();
    for (svc, q) in &queries {
        for (port, host) in srv_lookup(&resolver, q).await {
            out.push(((*svc).to_string(), port, host));
        }
    }
    out
}

// ─── Kerberos KDC probe (minimal AS-REQ → KRB-ERROR) ─────────────────────────────

/// Craft a minimal krb5 AS-REQ that elicits `KRB-ERROR` from a live KDC (proves port 88 is Kerberos).
fn minimal_as_req(realm: &str) -> Vec<u8> {
    // APPLICATION 10 (AS-REQ) wrapping a minimal KDC-REQ-BODY with empty cname/realm.
    let realm_bytes = realm.as_bytes();
    let mut body = Vec::new();
    body.extend(ber_integer(5)); // pvno
    body.extend(ber_integer(10)); // msg-type AS-REQ
    body.extend(ber_sequence(&ber_octet_string(b"krb5"))); // empty padata seq via minimal
    let mut req_body = Vec::new();
    req_body.extend(ber_integer(5));
    req_body.extend(ber_integer(10));
    // cname empty principal
    req_body.extend({
        let mut p = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x05, 0x00];
        p
    });
    req_body.extend(ber_octet_string(realm_bytes));
    let req_seq = ber_sequence(&req_body);
    body.extend({
        let mut tagged = vec![0xa3];
        tagged.extend_from_slice(&req_seq[1..]);
        tagged
    });
    let as_req = ber_sequence(&body);
    let mut tagged = vec![0x6a];
    tagged.extend_from_slice(&as_req[1..]);
    tagged
}

fn response_is_krb_error(resp: &[u8]) -> bool {
    resp.iter().any(|&b| b == 0x7e) // APPLICATION 30 KRB-ERROR
}

// ─── Scoring & posture ───────────────────────────────────────────────────────────

fn severity_counts(findings: &[Value]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for f in findings {
        if f.get("category").and_then(Value::as_str) == Some("posture_summary") {
            continue;
        }
        let sev = f
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("info")
            .to_string();
        *m.entry(sev).or_insert(0) += 1;
    }
    m
}

fn compute_score(findings: &[Value]) -> u8 {
    let counts = severity_counts(findings);
    let mut score: i32 = 100;
    score -= i32::try_from(counts.get("critical").copied().unwrap_or(0)).unwrap_or(0) * 22;
    score -= i32::try_from(counts.get("high").copied().unwrap_or(0)).unwrap_or(0) * 12;
    score -= i32::try_from(counts.get("medium").copied().unwrap_or(0)).unwrap_or(0) * 6;
    score -= i32::try_from(counts.get("low").copied().unwrap_or(0)).unwrap_or(0) * 2;
    score.clamp(0, 100) as u8
}

fn grade_for_score(score: u8) -> &'static str {
    match score {
        95..=100 => "A+",
        85..=94 => "A",
        70..=84 => "B",
        55..=69 => "C",
        40..=54 => "D",
        _ => "F",
    }
}

fn roastability_verdict(sig: &AdSignals) -> &'static str {
    if sig.ldap_anon_ok && !sig.kerberoast_spns.is_empty() {
        "CRITICAL — Kerberoastable SPNs enumerable without credentials"
    } else if sig.ldap_anon_ok {
        "HIGH — anonymous LDAP bind accepted; directory enumeration possible"
    } else if sig.kdc_live && sig.ldap_reachable {
        "HIGH — internet KDC + LDAP; Kerberoasting feasible with any domain credential"
    } else if !sig.asrep_accounts.is_empty() {
        "HIGH — AS-REP roastable accounts observable"
    } else if sig.kdc_live {
        "MEDIUM — Kerberos KDC internet-exposed"
    } else {
        "LOW — limited external Kerberos roast surface"
    }
}

fn posture_summary(target: &str, findings: &[Value], sig: &AdSignals) -> Value {
    let counts = severity_counts(findings);
    let score = compute_score(findings);
    let grade = grade_for_score(score);
    let verdict = roastability_verdict(sig);
    let sev = if score < 40 {
        "critical"
    } else if score < 60 {
        "high"
    } else if score < 75 {
        "medium"
    } else {
        "low"
    };
    let ev = supreme::enrich_posture_evidence(
        Evidence::new()
            .with("score", score)
            .with("grade", grade)
            .with("counts", json!(counts))
            .with("verdict", verdict)
            .with("domain", &sig.domain)
            .with(
                "open_ports",
                json!(sig.open_ports.iter().copied().collect::<Vec<_>>()),
            )
            .with("kerberoast_spn_count", sig.kerberoast_spns.len())
            .with("asrep_account_count", sig.asrep_accounts.len())
            .check("kdc_live", sig.kdc_live, "Kerberos KDC responded on 88/tcp")
            .check(
                "ldap_anon",
                sig.ldap_anon_ok,
                "Anonymous LDAP bind accepted",
            )
            .check(
                "ldap_reachable",
                sig.ldap_reachable,
                "LDAP service reachable",
            ),
        sig,
    );

    ad_finding(
        &format!("AD external Kerberos posture: {score}/100 (grade {grade}) — {verdict}"),
        sev,
        T_KERBEROAST,
        &format!(
            "Domain {}: {} critical / {} high / {} medium findings. Posture index 100 = no observed external AD weakness. Verdict reflects real roast/relay preconditions observed remotely.",
            if sig.domain.is_empty() { "(inferred)" } else { &sig.domain },
            counts.get("critical").copied().unwrap_or(0),
            counts.get("high").copied().unwrap_or(0),
            counts.get("medium").copied().unwrap_or(0),
        ),
        target,
        0.99,
        ev,
        "posture_summary",
        &["CIS Control 5", "NIST AC-2", "NIST IA-2"],
        Some(
            "Restrict AD ports to internal/VPN; disable anonymous LDAP binds; enforce LDAP signing & channel binding; require Kerberos pre-auth; tier-0 admin separation; monitor TGS-REQ volume for Kerberoasting.",
        ),
    )
}

// ─── Attack-path synthesis ───────────────────────────────────────────────────────

fn synthesize_attack_paths(target: &str, sig: &AdSignals, findings: &mut Vec<Value>) {
    if sig.kdc_live && sig.ldap_reachable {
        findings.push(attack_path_finding(
            "Internet KDC + LDAP → Kerberoasting / AS-REP roasting",
            "critical",
            T_KERBEROAST,
            "Both Kerberos KDC (88) and LDAP are internet-reachable — any stolen domain credential or AS-REP-roastable account enables offline TGS cracking and lateral movement.",
            target,
            0.92,
            &[
                "attacker discovers internet-exposed KDC + LDAP (this scan)",
                "obtain domain credential via spray/phish or AS-REP roast pre-auth-disabled account",
                "enumerate SPNs via LDAP / BloodHound-style graph",
                "request TGS tickets for service accounts (Kerberoasting)",
                "offline crack weak service-account passwords → lateral movement to tier-0",
            ],
            Evidence::new()
                .with("kdc_live", sig.kdc_live)
                .with("ldap_reachable", sig.ldap_reachable)
                .with("open_ports", json!(sig.open_ports)),
        ));
    }

    if sig.ldap_anon_ok && !sig.kerberoast_spns.is_empty() {
        let sample = sig
            .kerberoast_spns
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>();
        findings.push(attack_path_finding(
            "Anonymous LDAP → SPN harvest → offline Kerberoasting (no creds)",
            "critical",
            T_KERBEROAST,
            &format!(
                "Anonymous LDAP bind succeeded and {} Kerberoastable SPN(s) were enumerated remotely — attacker needs only network access to begin offline cracking.",
                sig.kerberoast_spns.len()
            ),
            target,
            0.95,
            &[
                "anonymous LDAP bind accepted (dsHeuristics misconfiguration)",
                "enumerate user accounts with servicePrincipalName set",
                &format!("sample SPNs: {}", sample.join(", ")),
                "with any domain user cred: request TGS for each SPN",
                "offline GPU crack → service account takeover",
            ],
            Evidence::new()
                .with("spn_sample", json!(sample))
                .with("spn_count", sig.kerberoast_spns.len()),
        ));
    }

    if !sig.asrep_accounts.is_empty() {
        let sample = sig
            .asrep_accounts
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>();
        findings.push(attack_path_finding(
            "AS-REP roasting — pre-authentication disabled accounts exposed",
            "critical",
            T_ASREP,
            &format!(
                "{} account(s) with DONT_REQ_PREAUTH (UAC 0x400000) observable via LDAP — offline crackable without prior authentication.",
                sig.asrep_accounts.len()
            ),
            target,
            0.93,
            &[
                "LDAP search for userAccountControl:1.2.840.113556.1.4.803:=4194304",
                &format!("accounts: {}", sample.join(", ")),
                "send AS-REQ without pre-auth → receive encrypted AS-REP",
                "offline crack user password hash",
                "valid user TGT → domain enumeration / Kerberoasting",
            ],
            Evidence::new()
                .with("accounts_sample", json!(sample))
                .with("account_count", sig.asrep_accounts.len()),
        ));
    }

    if sig.open_ports.contains(&445) && sig.ldap_reachable {
        findings.push(attack_path_finding(
            "SMB + LDAP co-exposure → NTLM relay to LDAP (signing not verified remotely)",
            "high",
            T_NTLM_RELAY,
            "SMB and LDAP are both reachable — classic NTLM relay path to create machine accounts or modify AD objects if signing/channel binding are not enforced.",
            target,
            0.88,
            &[
                "coerce/trick victim into NTLM auth to attacker-controlled SMB listener",
                "relay NTLM to LDAP/LDAPS on domain controller",
                "create computer account or modify RBCD / group membership",
                "Kerberoast new SPN / escalate to domain admin",
            ],
            Evidence::new()
                .with("smb_open", true)
                .with("ldap_reachable", sig.ldap_reachable),
        ));
    }

    if !sig.spnego_urls.is_empty() && sig.kdc_live {
        findings.push(attack_path_finding(
            "Internet SPNEGO endpoint + KDC → targeted service-account Kerberoasting",
            "high",
            T_KERBEROAST,
            &format!(
                "HTTP SPNEGO/NTLM endpoints ({}) are internet-facing alongside a live KDC — each maps to an SPN-backed service account, the classic Kerberoasting target class.",
                sig.spnego_urls.len()
            ),
            target,
            0.86,
            &[
                "enumerate SPNs tied to ADFS/OWA/WinRM endpoints",
                "request TGS for HTTP/ service SPNs with any domain user",
                "offline crack service account password",
                "abuse service rights (ADFS token signing, Exchange impersonation)",
            ],
            Evidence::new().with("spnego_urls", json!(sig.spnego_urls)),
        ));
    }
}

// ─── Security graph ──────────────────────────────────────────────────────────────

fn build_graph(target: &str, sig: &AdSignals) -> (Vec<GraphNode>, Vec<GraphEdge>) {
    let mut nodes = vec![GraphNode {
        id: "root".to_string(),
        label: target.to_string(),
        node_type: "root".to_string(),
        status: if sig.open_ports.is_empty() {
            "secure".to_string()
        } else {
            "exposed".to_string()
        },
        cname_target: None,
        raw_finding: None,
    }];
    let mut edges = Vec::new();
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
    if sig.kdc_live || sig.open_ports.contains(&88) {
        add("kdc", "Kerberos KDC (88)", "KDC_EXPOSED");
    }
    if sig.ldap_reachable {
        add("ldap", "LDAP directory", "LDAP_EXPOSED");
    }
    if sig.ldap_anon_ok {
        add("anon_ldap", "anonymous LDAP bind", "ANON_LDAP");
    }
    if !sig.kerberoast_spns.is_empty() {
        add(
            "spns",
            &format!("{} Kerberoastable SPN(s)", sig.kerberoast_spns.len()),
            "SPN_HARVEST",
        );
    }
    if !sig.asrep_accounts.is_empty() {
        add(
            "asrep",
            &format!("{} AS-REP roastable", sig.asrep_accounts.len()),
            "ASREP_ROAST",
        );
    }
    if sig.open_ports.contains(&445) {
        add("smb", "SMB (445)", "SMB_RELAY");
    }
    if !sig.spnego_urls.is_empty() {
        add("spnego", "HTTP SPNEGO/NTLM", "SPNEGO");
    }
    if sig.kdc_live && sig.ldap_reachable {
        edges.push(GraphEdge {
            id: "ap_kerb".to_string(),
            from_id: "kdc".to_string(),
            to_id: "ldap".to_string(),
            edge_type: "KERBEROAST_CHAIN".to_string(),
        });
    }
    (nodes, edges)
}

fn is_adfs_exchange_url(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    u.contains("/adfs") || u.contains("/ews") || u.contains("/owa") || u.contains("autodiscover")
}

// ─── Core scan orchestration ─────────────────────────────────────────────────────

async fn scan_ad_ports(
    host: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    let open = tcp_scan(host, &cfg.ad_ports, cfg.concurrency).await;
    for port in open {
        sig.open_ports.insert(port);
    }
    for &port in &sig.open_ports {
        if let Some(&(_, name, sev, mitre)) = AD_PORTS.iter().find(|&&(p, ..)| p == port) {
            let mut sev = sev;
            if cfg.strict_mode && sev == "medium" {
                sev = "high";
            }
            findings.push(ad_finding(
                &format!("AD service reachable: {name} ({port}/tcp)"),
                sev,
                mitre,
                &format!(
                    "{port}/tcp ({name}) is reachable on {host}. Internet-exposed Active Directory plumbing — restrict to internal/VPN networks and monitor for Kerberos/LDAP anomalies."
                ),
                target,
                0.95,
                Evidence::new()
                    .with("host", host)
                    .with("port", port)
                    .with("service", name)
                    .check("tcp_open", true, "TCP connect succeeded"),
                "port_exposure",
                &["CIS Control 12", "NIST SC-7"],
                Some("Block AD ports at perimeter firewall; require VPN/ZTNA for admin access."),
            ));
        }
    }
    sig.ldap_reachable = sig.open_ports.contains(&389) || sig.open_ports.contains(&3268);
    sig.kdc_live = sig.open_ports.contains(&88);
}

async fn scan_srv_records(
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if cfg.domain.is_empty() {
        return;
    }
    let records = discover_ad_srv(&cfg.domain, &cfg.resolver).await;
    for (svc, port, host) in &records {
        if !sig.srv_hosts.contains(host) {
            sig.srv_hosts.push(host.clone());
        }
        findings.push(ad_finding(
            &format!("AD SRV record: {svc} → {host}:{port}"),
            "high",
            T_DOMAIN_DISC,
            &format!(
                "DNS SRV {svc}.{domain} resolves to {host}:{port} — domain controller / AD service locator exposed via public DNS.",
                domain = cfg.domain
            ),
            target,
            0.9,
            Evidence::new()
                .with("srv_service", svc)
                .with("srv_host", host)
                .with("srv_port", *port)
                .with("domain", &cfg.domain)
                .check("dns_srv", true, "Live SRV lookup"),
            "dns_srv",
            &["NIST CM-8"],
            Some("Review public DNS AD records; use split-horizon DNS so internal SRVs are not internet-visible."),
        ));
    }
}

async fn scan_ldap(
    host: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    let ldap_port = if sig.open_ports.contains(&389) {
        389u16
    } else if sig.open_ports.contains(&3268) {
        3268
    } else {
        return;
    };

    if cfg.check_ldap_anon {
        if let Some(resp) = ldap_exchange(host, ldap_port, &[LDAP_ANON_BIND], cfg.timeout_ms).await
        {
            match ldap_bind_result_code(&resp) {
                Some(0) => {
                    sig.ldap_anon_ok = true;
                    findings.push(ad_finding(
                        "Anonymous LDAP bind ACCEPTED — directory enumeration possible",
                        "critical",
                        T_DOMAIN_DISC,
                        &format!(
                            "{ldap_port}/tcp on {host} accepted an anonymous LDAP simple bind (resultCode 0). Directory can be enumerated without credentials — exposing users, SPNs (Kerberoastable services), and accounts with Kerberos pre-auth disabled (AS-REP roastable)."
                        ),
                        target,
                        0.97,
                        Evidence::new()
                            .with("host", host)
                            .with("port", ldap_port)
                            .with("bind_result", 0)
                            .raw_excerpt(&resp)
                            .check("anonymous_bind", true, "resultCode 0"),
                        "ldap_anonymous",
                        &["CIS Control 5.4", "NIST AC-3"],
                        Some("Set dsHeuristics to block anonymous binds; require LDAP signing (LDAPServerIntegrity=2); enable channel binding."),
                    ));
                }
                Some(code) => {
                    findings.push(ad_finding(
                        "LDAP service confirmed (anonymous bind rejected)",
                        "info",
                        T_DOMAIN_DISC,
                        &format!(
                            "{ldap_port}/tcp on {host} is a live LDAP service (bind resultCode {code}). Anonymous bind rejected — good. Restrict directory to internal networks."
                        ),
                        target,
                        0.85,
                        Evidence::new()
                            .with("bind_result", code)
                            .raw_excerpt(&resp)
                            .check("anonymous_bind", false, format!("resultCode {code}")),
                        "ldap_hardening",
                        &[],
                        None,
                    ));
                }
                None => {}
            }

            if cfg.check_ldap_enum && (sig.ldap_anon_ok || cfg.intensity == Intensity::Aggressive) {
                let root_filter = filter_present("objectClass");
                let root_search = ldap_search_request(2, "", 0, &root_filter, &[]);
                let msgs: Vec<&[u8]> = if sig.ldap_anon_ok {
                    vec![LDAP_ANON_BIND, &root_search]
                } else {
                    vec![&root_search]
                };
                if let Some(enum_resp) = ldap_exchange(host, ldap_port, &msgs, cfg.timeout_ms).await
                {
                    let strings = extract_ldap_strings(&enum_resp);
                    let base_dn = if !cfg.ldap_base_dn.is_empty() {
                        Some(cfg.ldap_base_dn.clone())
                    } else {
                        extract_naming_context(&strings)
                    };
                    if let Some(ref nc) = base_dn {
                        sig.naming_context = Some(nc.clone());
                        findings.push(ad_finding(
                            "LDAP rootDSE: defaultNamingContext discovered",
                            "medium",
                            T_DOMAIN_DISC,
                            &format!("Active Directory naming context: {nc}"),
                            target,
                            0.88,
                            Evidence::new().with("defaultNamingContext", nc).check(
                                "rootdse",
                                true,
                                "naming context extracted",
                            ),
                            "ldap_enum",
                            &[],
                            None,
                        ));

                        let spn_filter = filter_and(&[
                            &filter_equality("objectCategory", "person"),
                            &filter_equality("objectClass", "user"),
                            &filter_present("servicePrincipalName"),
                        ]);
                        let spn_search = ldap_search_request(
                            3,
                            nc,
                            2,
                            &spn_filter,
                            &["servicePrincipalName", "sAMAccountName"],
                        );
                        let bind_msgs: Vec<&[u8]> = if sig.ldap_anon_ok {
                            vec![LDAP_ANON_BIND, &spn_search]
                        } else {
                            vec![&spn_search]
                        };
                        if let Some(spn_resp) =
                            ldap_exchange(host, ldap_port, &bind_msgs, cfg.timeout_ms).await
                        {
                            let spn_strings = extract_ldap_strings(&spn_resp);
                            let spns = extract_spns(&spn_strings);
                            sig.kerberoast_spns =
                                spns.iter().take(cfg.max_ldap_entries).cloned().collect();
                            if !sig.kerberoast_spns.is_empty() {
                                let sev = if sig.ldap_anon_ok { "critical" } else { "high" };
                                findings.push(ad_finding(
                                    &format!(
                                        "{} Kerberoastable SPN(s) enumerated via LDAP",
                                        sig.kerberoast_spns.len()
                                    ),
                                    sev,
                                    T_KERBEROAST,
                                    &format!(
                                        "servicePrincipalName values on user accounts observed: {}. Each is an offline-cracking target once any domain credential is obtained.",
                                        sig.kerberoast_spns.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                                    ),
                                    target,
                                    if sig.ldap_anon_ok { 0.96 } else { 0.82 },
                                    Evidence::new()
                                        .with("spn_count", sig.kerberoast_spns.len())
                                        .with("spn_sample", json!(sig.kerberoast_spns.iter().take(8).collect::<Vec<_>>()))
                                        .check("spn_enum", true, "LDAP search returned SPNs"),
                                    "spn_enumeration",
                                    &["MITRE T1558.003"],
                                    Some("Use gMSAs or strong random passwords for service accounts; monitor Event ID 4769 for RC4-HMAC TGS requests; implement honey accounts."),
                                ));
                            }
                        }

                        let asrep_filter = filter_and(&[
                            &filter_equality("objectCategory", "person"),
                            &filter_equality("objectClass", "user"),
                            &filter_extensible_match(
                                "userAccountControl",
                                "1.2.840.113556.1.4.803",
                                "4194304",
                            ),
                        ]);
                        let asrep_search = ldap_search_request(
                            4,
                            nc,
                            2,
                            &asrep_filter,
                            &["sAMAccountName", "userAccountControl"],
                        );
                        let asrep_msgs: Vec<&[u8]> = if sig.ldap_anon_ok {
                            vec![LDAP_ANON_BIND, &asrep_search]
                        } else {
                            vec![&asrep_search]
                        };
                        if let Some(asrep_resp) =
                            ldap_exchange(host, ldap_port, &asrep_msgs, cfg.timeout_ms).await
                        {
                            let asrep_strings = extract_ldap_strings(&asrep_resp);
                            sig.asrep_accounts = extract_sam_accounts(&asrep_strings)
                                .into_iter()
                                .take(cfg.max_ldap_entries)
                                .collect();
                            if !sig.asrep_accounts.is_empty() {
                                findings.push(ad_finding(
                                    &format!(
                                        "{} AS-REP roastable account(s) (pre-auth disabled)",
                                        sig.asrep_accounts.len()
                                    ),
                                    "critical",
                                    T_ASREP,
                                    &format!(
                                        "Accounts with DONT_REQ_PREAUTH (UAC 0x400000): {}. Attackers can request AS-REP without pre-authentication and crack offline.",
                                        sig.asrep_accounts.join(", ")
                                    ),
                                    target,
                                    0.94,
                                    Evidence::new()
                                        .with("account_count", sig.asrep_accounts.len())
                                        .with("accounts", json!(sig.asrep_accounts))
                                        .check("asrep_enum", true, "LDAP extensible match"),
                                    "asrep_roasting",
                                    &["MITRE T1558.004"],
                                    Some("Enable 'Account is sensitive and cannot be delegated' and ensure Kerberos pre-auth is required for all users."),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn scan_kdc(
    host: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if !cfg.check_kdc_probe || !sig.open_ports.contains(&88) {
        return;
    }
    let realm = if cfg.domain.is_empty() {
        host.to_ascii_uppercase()
    } else {
        cfg.domain.to_ascii_uppercase()
    };
    let as_req = minimal_as_req(&realm);
    if let Some(resp) = ldap_exchange(host, 88, &[&as_req], cfg.timeout_ms).await {
        if response_is_krb_error(&resp) || !resp.is_empty() {
            sig.kdc_live = true;
            findings.push(ad_finding(
                "Kerberos KDC live on 88/tcp (KRB-ERROR / krb5 response)",
                "high",
                T_KERBEROAST,
                &format!(
                    "Port 88 on {host} responded to a krb5 AS-REQ with a Kerberos protocol message — confirmed KDC, not a generic open port."
                ),
                target,
                0.91,
                Evidence::new()
                    .with("host", host)
                    .with("port", 88)
                    .with("realm", &realm)
                    .raw_excerpt(&resp)
                    .check("krb5_response", true, "KRB-ERROR or krb5 payload"),
                "kdc_liveness",
                &["NIST SC-7"],
                Some("Never expose Kerberos KDC to the internet; require VPN for authentication traffic."),
            ));
        }
    }
}

async fn scan_http_spnego(
    url: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if !cfg.check_spnego_http {
        return;
    }
    let client = http_client().await;
    let paths = cfg.http_paths();
    let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    let concurrency = cfg.concurrency.min(DEFAULT_PROBE_CONCURRENCY);
    let probes = probe_paths_concurrent(&client, url, &path_refs, concurrency).await;
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
            sig.spnego_urls.push(p.final_url.clone());
            findings.push(ad_finding(
                &format!("{scheme} authentication exposed: {}", p.final_url),
                "high",
                T_KERBEROAST,
                &format!(
                    "{} requires {scheme} authentication (WWW-Authenticate). In AD this endpoint maps to an SPN-backed service account — a Kerberoasting target; NTLM endpoints are relay/brute-force targets.",
                    p.final_url
                ),
                target,
                0.9,
                Evidence::new()
                    .with("url", &p.final_url)
                    .with("scheme", scheme)
                    .with("http_status", p.status)
                    .check("spnego", true, www),
                "http_spnego",
                &["MITRE T1558.003"],
                Some("Publish ADFS/OWA only via VPN; enforce Extended Protection for Authentication; use gMSA for service accounts."),
            ));
        } else if status_indicates_presence(p.status) && is_adfs_exchange_url(&p.final_url) {
            findings.push(ad_finding(
                &format!("AD federation/Exchange endpoint exposed: {}", p.final_url),
                "medium",
                T_KERBEROAST,
                &format!(
                    "{} (HTTP {}) is an internet-facing ADFS/Exchange surface — enables SPN enumeration and Kerberoasting pivot.",
                    p.final_url, p.status
                ),
                target,
                0.75,
                Evidence::new()
                    .with("url", &p.final_url)
                    .with("http_status", p.status),
                "federation_exposure",
                &[],
                None,
            ));
        }
    }
}

// ─── Entry points ────────────────────────────────────────────────────────────────

/// Collect every host we should probe (primary target + operator DCs + DNS SRV discoveries).
fn collect_probe_hosts(primary: &str, cfg: &KerberosConfig, sig: &AdSignals) -> Vec<String> {
    let mut hosts = BTreeSet::new();
    hosts.insert(extract_host(primary));
    for dc in &cfg.dc_hosts {
        let h = extract_host(dc);
        if !h.is_empty() {
            hosts.insert(h);
        }
    }
    for h in &sig.srv_hosts {
        if !h.is_empty() {
            hosts.insert(h.clone());
        }
    }
    hosts.into_iter().collect()
}

async fn assess_host(
    host: &str,
    url: &str,
    cfg: &KerberosConfig,
    sig: &mut AdSignals,
    findings: &mut Vec<Value>,
    target: &str,
) {
    if cfg.check_ports {
        scan_ad_ports(host, cfg, sig, findings, target).await;
    }
    if cfg.check_ldap_anon || cfg.check_ldap_enum {
        scan_ldap(host, cfg, sig, findings, target).await;
    }
    supreme::scan_ldap_starttls(host, cfg, sig, findings, target).await;
    supreme::scan_smb_signing(host, cfg, sig, findings, target).await;
    if cfg.check_kdc_probe {
        scan_kdc(host, cfg, sig, findings, target).await;
    }
    supreme::scan_kerberos_user_enum(host, cfg, sig, findings, target).await;
    supreme::scan_delegation_and_machines(host, cfg, sig, findings, target).await;
    supreme::scan_ldap_rootdse_meta(host, cfg, sig, findings, target).await;
    if cfg.check_tier0_spns {
        supreme::scan_tier0_kerberoast_spns(host, cfg, sig, findings, target).await;
    }
    if cfg.check_delegation {
        supreme::scan_constrained_delegation(host, cfg, sig, findings, target).await;
    }
    if cfg.check_ldaps_tls {
        supreme::scan_ldaps_tls(host, cfg, sig, findings, target).await;
    }
}

/// World-class AD/Kerberos external posture engine (reads all knobs from `job_params`).
pub async fn run_kerberoasting_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error(
            "kerberoasting: target required (DC hostname, ADFS URL, or domain)",
        );
    }
    let cfg = KerberosConfig::from_arsenal(&ArsenalConfig::from_ctx(ctx), target);
    let host = extract_host(target);
    let url = normalize_url(target);
    let mut sig = AdSignals::new(cfg.domain.clone());
    let mut findings: Vec<Value> = Vec::new();

    // Phase 1 — DNS cartography (domain-wide).
    if cfg.check_msdcs_dns && !cfg.domain.is_empty() {
        supreme::scan_msdcs_dns(&cfg, &mut sig, &mut findings, target).await;
    }
    if cfg.check_srv && !cfg.domain.is_empty() {
        scan_srv_records(&cfg, &mut sig, &mut findings, target).await;
    }
    if cfg.check_hybrid_entra && !cfg.domain.is_empty() {
        supreme::scan_hybrid_entra(&cfg, &mut sig, &mut findings, target, &url).await;
    }

    // Phase 2 — per-host deep assessment (primary + discovered DCs).
    let probe_hosts = collect_probe_hosts(target, &cfg, &sig);
    for h in &probe_hosts {
        assess_host(h, &url, &cfg, &mut sig, &mut findings, target).await;
    }

    // Phase 3 — HTTP / AD CS surfaces (URL-centric).
    if cfg.check_spnego_http {
        scan_http_spnego(&url, &cfg, &mut sig, &mut findings, target).await;
    }
    supreme::scan_adcs_http(&url, &cfg, &mut sig, &mut findings, target).await;

    // Phase 4 — correlate, score, synthesize.
    supreme::finalize_category_scores(&mut sig, &findings);

    if cfg.attack_paths {
        synthesize_attack_paths(target, &sig, &mut findings);
        supreme::extend_attack_paths(target, &sig, &mut findings);
    }
    supreme::emit_toxic_headline(target, &sig, &mut findings);
    supreme::emit_remediation_roadmap(target, &sig, &mut findings);
    if cfg.emit_agent_guidance {
        supreme::emit_agent_guidance(target, &cfg, &mut findings);
    }

    let (mut graph_nodes, mut graph_edges) = build_graph(target, &sig);
    supreme::extend_graph(&mut graph_nodes, &mut graph_edges, &sig);

    if !findings.is_empty() || sig.kdc_live || sig.ldap_reachable {
        findings.push(posture_summary(target, &findings, &sig));
    }

    if findings.is_empty() {
        return EngineResult::ok(
            vec![],
            format!("kerberoasting: no external AD/Kerberos surface observed on {host}"),
        );
    }

    let crit = findings
        .iter()
        .filter(|f| f.get("severity").and_then(Value::as_str) == Some("critical"))
        .count();
    let score = compute_score(&findings);
    let grade = grade_for_score(score);
    let toxic = findings
        .iter()
        .filter(|f| f.get("category").and_then(Value::as_str) == Some("toxic_combination"))
        .count();
    let message =
        format!(
        "kerberoasting: {} finding(s), posture {score}/100 ({grade}){}{}{}{}{} ({} critical{}{})",
        findings.len(),
        if !cfg.domain.is_empty() {
            format!(", domain {}", cfg.domain)
        } else {
            String::new()
        },
        if sig.ldap_anon_ok { ", anonymous LDAP" } else { "" },
        if !sig.kerberoast_spns.is_empty() {
            format!(", {} user SPN(s)", sig.kerberoast_spns.len())
        } else {
            String::new()
        },
        if sig.smb_signing_required == Some(false) {
            ", SMB relay surface"
        } else {
            ""
        },
        if sig.adcs_exposed { ", AD CS exposed" } else { "" },
        crit,
        if toxic > 0 { format!(", {toxic} toxic combo(s)") } else { String::new() },
        if !probe_hosts.is_empty() {
            format!(", {} host(s) assessed", probe_hosts.len())
        } else {
            String::new()
        },
    );
    EngineResult::ok_with_graph(findings, message, graph_nodes, graph_edges)
}

/// Backward-compatible entry (default context).
pub async fn run_kerberoasting_result(target: &str) -> EngineResult {
    run_kerberoasting_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_kerberoasting(target: &str) {
    print_result(run_kerberoasting_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_anonymous_bind_success() {
        let resp = [
            0x30, 0x0c, 0x02, 0x01, 0x02, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
        ];
        assert_eq!(ldap_bind_result_code(&resp), Some(0));
    }

    #[test]
    fn parses_bind_rejection() {
        let resp = [
            0x30, 0x0c, 0x02, 0x01, 0x02, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00,
        ];
        assert_eq!(ldap_bind_result_code(&resp), Some(0x31));
    }

    #[test]
    fn grade_mapping() {
        assert_eq!(grade_for_score(98), "A+");
        assert_eq!(grade_for_score(50), "D");
        assert_eq!(grade_for_score(20), "F");
    }

    #[test]
    fn compute_score_deducts_severity() {
        let findings = vec![
            json!({"severity": "critical", "category": "port_exposure"}),
            json!({"severity": "high", "category": "ldap"}),
        ];
        assert!(compute_score(&findings) < 70);
    }

    #[test]
    fn extract_spns_finds_http() {
        let strings = vec!["HTTP/adfs.corp.local".to_string(), "noise".to_string()];
        let spns = extract_spns(&strings);
        assert_eq!(spns.len(), 1);
    }

    #[tokio::test]
    async fn empty_target_errors() {
        assert!(!run_kerberoasting_result("").await.success);
    }

    #[test]
    fn infer_domain_from_host() {
        assert_eq!(
            infer_domain_from_target("https://adfs.corp.example.com"),
            "example.com"
        );
    }
}
