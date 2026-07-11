//! Advanced APT / threat-actor engines — evidence-based external initial-access mapping.
//!
//! A remote, unauthenticated scanner cannot "become" APT41. What it *can* do at a
//! world-class level is map a target's externally-observable attack surface to the
//! **specific software each actor is publicly documented (CISA / Mandiant) to exploit
//! for initial access**, and report only when that software is actually exposed — with
//! a live HTTP/TCP response as evidence and the relevant CVE/KEV reference attached.
//!
//! Every finding here is backed by a real probe: an exposed Exchange/OWA endpoint, an
//! internet-facing Citrix/Fortinet/Ivanti gateway, an open RDP/SMB port, a confirmed
//! product fingerprint, weak email-auth on a live MX domain, or a TLS hygiene gap.
//! No simulated findings; no payloads are delivered to the target.

use crate::engine_probes::{
    dns_mx, dns_txt, empty_ok, extract_host, finding_with_probe_depth, fingerprint_stack,
    has_header, header_value, http_client, http_get_retry, normalize_url, probe_matched_token,
    probe_paths_concurrent, status_indicates_presence, tcp_scan, tls_cert_summary, HttpProbe,
    DEFAULT_PROBE_CONCURRENCY,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

const PROBE_DEPTH: &str = "actor_initial_access_surface";

/// An externally-observable initial-access surface (a product/service a threat
/// actor is documented to exploit). Detection is confirmed by a live response on
/// one of `paths` whose body/headers match one of `tokens`, or by an open TCP
/// port in `ports`.
struct EdgeSurface {
    /// Human-readable product name (e.g. "Microsoft Exchange / OWA").
    name: &'static str,
    /// MITRE technique for the initial-access vector.
    mitre: &'static str,
    /// CVE / KEV reference for the publicly-exploited weakness.
    cve: &'static str,
    /// HTTP paths that expose the product's login/management surface.
    paths: &'static [&'static str],
    /// TCP ports that, if open, indicate the service is reachable.
    ports: &'static [u16],
    /// Body/header tokens that confirm the product (case-insensitive).
    tokens: &'static [&'static str],
    /// Severity to assign when the surface is confirmed exposed.
    severity: &'static str,
}

struct ActorProfile {
    engine_id: &'static str,
    actor: &'static str,
    mitre: &'static str,
    /// Initial-access surfaces this actor is documented to exploit.
    surfaces: Vec<&'static EdgeSurface>,
    /// Public IOC strings occasionally observable in a defaced/ransom page or
    /// artifact (secondary, low-confidence signal).
    iocs: &'static [&'static str],
}

// ── Catalogue of internet-facing initial-access surfaces (CISA-KEV backed) ──────

static EXCHANGE_OWA: EdgeSurface = EdgeSurface {
    name: "Microsoft Exchange / Outlook Web Access",
    mitre: "T1190",
    cve: "ProxyLogon/ProxyShell (CVE-2021-26855, CVE-2021-34473) + Outlook EoP CVE-2023-23397 — CISA KEV",
    paths: &[
        "/owa/",
        "/ecp/",
        "/autodiscover/autodiscover.xml",
        "/EWS/Exchange.asmx",
        "/mapi/",
    ],
    ports: &[],
    tokens: &["x-owa-version", "outlook", "x-feserver", "microsoft-iis", "exchange"],
    severity: "high",
};

static ROUNDCUBE_WEBMAIL: EdgeSurface = EdgeSurface {
    name: "Roundcube Webmail",
    mitre: "T1190",
    cve: "CVE-2023-43770 / CVE-2020-35730 stored-XSS (APT28 webmail harvesting)",
    paths: &["/roundcube/", "/webmail/", "/mail/", "/?_task=login"],
    ports: &[],
    tokens: &["roundcube", "rcmail", "x-roundcube"],
    severity: "medium",
};

static CITRIX_NETSCALER: EdgeSurface = EdgeSurface {
    name: "Citrix NetScaler / Gateway (ADC)",
    mitre: "T1190",
    cve: "Citrix Bleed CVE-2023-4966 + CVE-2019-19781 — CISA KEV",
    paths: &[
        "/vpn/index.html",
        "/citrix/",
        "/Citrix/",
        "/cgi/login",
        "/nf/auth/doAuthentication.do",
        "/logon/LogonPoint/tmindex.html",
    ],
    ports: &[],
    tokens: &["citrix", "netscaler", "ns_gui", "nsc_", "vpn"],
    severity: "high",
};

static FORTINET_SSLVPN: EdgeSurface = EdgeSurface {
    name: "Fortinet FortiGate SSL-VPN",
    mitre: "T1190",
    cve: "CVE-2024-21762 + CVE-2018-13379 path traversal — CISA KEV",
    paths: &[
        "/remote/login",
        "/remote/fgt_lang",
        "/sslvpn/",
        "/remote/info",
    ],
    ports: &[],
    tokens: &["fortinet", "fortigate", "sslvpn", "fgt_lang"],
    severity: "high",
};

static PULSE_IVANTI: EdgeSurface = EdgeSurface {
    name: "Ivanti Connect Secure / Pulse VPN",
    mitre: "T1190",
    cve: "CVE-2023-46805 + CVE-2024-21887 auth-bypass/RCE — CISA KEV",
    paths: &[
        "/dana-na/auth/url_default/welcome.cgi",
        "/dana-na/",
        "/api/v1/totp/user-backup-code",
    ],
    ports: &[],
    tokens: &["pulse secure", "ivanti", "dana-na", "dana_na"],
    severity: "high",
};

static CISCO_IOSXE: EdgeSurface = EdgeSurface {
    name: "Cisco IOS XE Web UI",
    mitre: "T1190",
    cve: "CVE-2023-20198 implant chain — CISA KEV",
    paths: &[
        "/webui/",
        "/webui/logoutconfirm.html?logon_hash=1",
        "/%2577ebui/",
    ],
    ports: &[],
    tokens: &["cisco", "ios xe", "webui", "ios-xe"],
    severity: "high",
};

static ZOHO_MANAGEENGINE: EdgeSurface = EdgeSurface {
    name: "Zoho ManageEngine",
    mitre: "T1190",
    cve: "CVE-2022-47966 SAML RCE + CVE-2020-10189 — CISA KEV",
    paths: &["/RestAPI/", "/servlet/", "/desktop/", "/adfs/ls/"],
    ports: &[],
    tokens: &["manageengine", "zoho", "servicedesk", "adselfservice"],
    severity: "high",
};

static MOVEIT_TRANSFER: EdgeSurface = EdgeSurface {
    name: "Progress MOVEit Transfer",
    mitre: "T1190",
    cve: "CVE-2023-34362 SQLi→RCE (Cl0p mass-exfil) — CISA KEV",
    paths: &[
        "/human.aspx",
        "/moveitisapi/moveitisapi.dll",
        "/guestaccess.aspx",
        "/api/v1/token",
    ],
    ports: &[],
    tokens: &["moveit", "ipswitch", "human.aspx", "moveitisapi"],
    severity: "critical",
};

static GOANYWHERE_MFT: EdgeSurface = EdgeSurface {
    name: "Fortra GoAnywhere MFT",
    mitre: "T1190",
    cve: "CVE-2023-0669 deserialization RCE (Cl0p) — CISA KEV",
    paths: &["/goanywhere/", "/sweb/", "/goanywhere/login.xhtml"],
    ports: &[],
    tokens: &["goanywhere", "fortra", "linoma"],
    severity: "critical",
};

static SOLARWINDS_ORION: EdgeSurface = EdgeSurface {
    name: "SolarWinds Orion Platform",
    mitre: "T1195.002",
    cve: "SUNBURST supply-chain backdoor (CVE-2020-10148)",
    paths: &["/Orion/", "/web/", "/api2/", "/Orion/Login.aspx"],
    ports: &[],
    tokens: &["solarwinds", "orion"],
    severity: "high",
};

static VMWARE_HORIZON: EdgeSurface = EdgeSurface {
    name: "VMware Horizon / vCenter",
    mitre: "T1190",
    cve: "Log4Shell CVE-2021-44228 against Horizon — CISA KEV",
    paths: &["/portal/", "/broker/xml", "/ui/", "/websso/"],
    ports: &[],
    tokens: &["vmware", "horizon", "vmware-view", "vcenter"],
    severity: "high",
};

static RDP_SERVICE: EdgeSurface = EdgeSurface {
    name: "Internet-exposed RDP",
    mitre: "T1133",
    cve: "BlueKeep CVE-2019-0708 + brute-force initial access — CISA KEV",
    paths: &[],
    ports: &[3389],
    tokens: &[],
    severity: "high",
};

static SMB_SERVICE: EdgeSurface = EdgeSurface {
    name: "Internet-exposed SMB",
    mitre: "T1210",
    cve: "EternalBlue CVE-2017-0144 (Equation Group / DoublePulsar) — CISA KEV",
    paths: &[],
    ports: &[445],
    tokens: &[],
    severity: "high",
};

// ── Finding builders ────────────────────────────────────────────────────────

fn actor_finding(
    profile: &ActorProfile,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    evidence_url: Option<&str>,
    cve: &str,
) -> Value {
    let mut f = finding_with_probe_depth(
        profile.engine_id,
        title,
        severity,
        mitre,
        description,
        target,
        PROBE_DEPTH,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("threat_actor".to_string(), json!(profile.actor));
        if !cve.is_empty() {
            obj.insert("exploited_cve".to_string(), json!(cve));
        }
        if let Some(u) = evidence_url {
            obj.insert("evidence_url".to_string(), json!(u));
        }
    }
    f
}

/// Attach quantitative, actor-specific intelligence to a surface finding so each of the
/// actor engines produces distinct, prioritized analysis rather than the same probe under a
/// different name. The confidence is weighted by how central this surface is to *this
/// actor's* documented playbook (its rank in `profile.surfaces`), whether the weakness is on
/// the CISA KEV list, and the surface severity — so two actors sharing a surface score it
/// differently.
fn annotate_actor_intel(f: &mut Value, profile: &ActorProfile, surface: &EdgeSurface) {
    let Some(obj) = f.as_object_mut() else { return };
    let rank = profile
        .surfaces
        .iter()
        .position(|s| std::ptr::eq(*s, surface))
        .unwrap_or(profile.surfaces.len());
    let primary = rank == 0;
    let kev = surface.cve.contains("KEV");
    let sev_weight: u32 = match surface.severity {
        "critical" => 40,
        "high" => 30,
        "medium" => 18,
        _ => 10,
    };
    let rank_weight: u32 = if primary {
        24
    } else {
        18u32.saturating_sub((rank as u32).saturating_mul(3))
    };
    let confidence = (sev_weight + if kev { 35 } else { 10 } + rank_weight).min(99);
    obj.insert("actor_confidence".to_string(), json!(confidence));
    obj.insert("kev_listed".to_string(), json!(kev));
    obj.insert("actor_playbook_rank".to_string(), json!(rank + 1));
    obj.insert(
        "actor_playbook_size".to_string(),
        json!(profile.surfaces.len()),
    );
    obj.insert("actor_primary_ttp".to_string(), json!(primary));
}

fn surface_http_finding(
    profile: &ActorProfile,
    surface: &EdgeSurface,
    probe: &HttpProbe,
    matched: &str,
    target: &str,
) -> Value {
    let desc = format!(
        "{} is internet-exposed at {} (HTTP {}; confirmed by token '{}'). {} is publicly documented to gain initial access through this software [{}]. Restrict the surface to a VPN/allow-list and apply the relevant patch.",
        surface.name, probe.final_url, probe.status, matched, profile.actor, surface.cve
    );
    let mut f = actor_finding(
        profile,
        &format!(
            "{}: exposed initial-access surface — {}",
            profile.actor, surface.name
        ),
        surface.severity,
        surface.mitre,
        &desc,
        target,
        Some(&probe.final_url),
        surface.cve,
    );
    annotate_actor_intel(&mut f, profile, surface);
    f
}

fn surface_port_finding(
    profile: &ActorProfile,
    surface: &EdgeSurface,
    port: u16,
    target: &str,
    host: &str,
) -> Value {
    let desc = format!(
        "{}/tcp is open on {} — {} is reachable from the probe. {} leverages this service for initial access [{}]. Remove direct internet exposure; require VPN + MFA.",
        port, host, surface.name, profile.actor, surface.cve
    );
    let mut f = actor_finding(
        profile,
        &format!(
            "{}: exposed service — {} ({}/tcp)",
            profile.actor, surface.name, port
        ),
        surface.severity,
        surface.mitre,
        &desc,
        target,
        None,
        surface.cve,
    );
    annotate_actor_intel(&mut f, profile, surface);
    f
}

// ── Perimeter hygiene (relevant to nation-state phishing / watering-hole) ──────

fn scan_http_hygiene(profile: &ActorProfile, probe: &HttpProbe, target: &str) -> Vec<Value> {
    let mut findings = Vec::new();

    for disclose in ["server", "x-powered-by", "x-aspnet-version"] {
        if let Some(v) = header_value(&probe.headers, disclose) {
            if !v.trim().is_empty() {
                findings.push(actor_finding(
                    profile,
                    &format!("{}: infrastructure disclosure header '{}'", profile.actor, disclose),
                    "low",
                    profile.mitre,
                    &format!(
                        "Response from {} exposes {}: {} — aids {} infrastructure fingerprinting and exploit targeting.",
                        probe.final_url, disclose, v, profile.actor
                    ),
                    target,
                    Some(&probe.final_url),
                    "",
                ));
            }
        }
    }

    let fp = fingerprint_stack(probe);
    for (prod, ver) in fp.products.iter().take(3) {
        findings.push(actor_finding(
            profile,
            &format!("{}: software version disclosed — {} {}", profile.actor, prod, ver),
            "low",
            profile.mitre,
            &format!(
                "{} advertises {} {} via response headers at {} — cross-reference against KEV/EPSS for {}-exploited CVEs.",
                target, prod, ver, probe.final_url, profile.actor
            ),
            target,
            Some(&probe.final_url),
            "",
        ));
    }

    if probe.final_url.starts_with("https://")
        && (200..400).contains(&probe.status)
        && !has_header(&probe.headers, "strict-transport-security")
        && !has_header(&probe.headers, "content-security-policy")
    {
        findings.push(actor_finding(
            profile,
            &format!("{}: perimeter gap — missing HSTS and CSP", profile.actor),
            "low",
            profile.mitre,
            &format!(
                "HTTPS response from {} lacks both Strict-Transport-Security and Content-Security-Policy — weakens drive-by / watering-hole defenses associated with {}.",
                probe.final_url, profile.actor
            ),
            target,
            Some(&probe.final_url),
            "",
        ));
    }
    findings
}

async fn scan_tls_surface(profile: &ActorProfile, target: &str, host: &str) -> Vec<Value> {
    let mut findings = Vec::new();
    if let Some(cert) = tls_cert_summary(host).await {
        if cert.self_signed {
            findings.push(actor_finding(
                profile,
                &format!("{}: self-signed TLS certificate", profile.actor),
                "medium",
                profile.mitre,
                &format!(
                    "TLS certificate for {} is self-signed (subject={}). Weak PKI is abused by {} for credential harvesting / MITM.",
                    host, cert.subject, profile.actor
                ),
                target,
                None,
                "",
            ));
        } else if cert.expired {
            findings.push(actor_finding(
                profile,
                &format!("{}: expired TLS certificate", profile.actor),
                "medium",
                profile.mitre,
                &format!(
                    "TLS certificate for {} is expired (issuer={}). Expired certs flag neglected perimeter assets targeted by {}.",
                    host, cert.issuer, profile.actor
                ),
                target,
                None,
                "",
            ));
        }
    }
    findings
}

async fn scan_email_auth_surface(profile: &ActorProfile, target: &str, host: &str) -> Vec<Value> {
    let mut findings = Vec::new();
    let mx = dns_mx(host).await;
    if mx.is_empty() {
        return findings;
    }
    let txt = dns_txt(host).await;
    let has_spf = txt.iter().any(|t| t.contains("v=spf1"));
    let has_dmarc = txt.iter().any(|t| t.contains("DMARC1"))
        || !dns_txt(&format!("_dmarc.{host}")).await.is_empty();
    if !has_spf {
        findings.push(actor_finding(
            profile,
            &format!("{}: MX domain without SPF", profile.actor),
            "medium",
            "T1566.001",
            &format!(
                "Domain {} has MX ({}) but no SPF record — enables spoofed spear-phishing aligned with {} tradecraft.",
                host,
                mx.join(","),
                profile.actor
            ),
            target,
            None,
            "",
        ));
    }
    if !has_dmarc {
        findings.push(actor_finding(
            profile,
            &format!("{}: MX domain without DMARC", profile.actor),
            "low",
            "T1566.001",
            &format!(
                "Domain {} publishes MX but no DMARC policy — weak email authentication for {}-style phishing.",
                host, profile.actor
            ),
            target,
            None,
            "",
        ));
    }
    findings
}

// ── Core scan ─────────────────────────────────────────────────────────────────

async fn actor_exposure_scan(target: &str, profile: &ActorProfile) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let host = extract_host(target);
    let mut findings: Vec<Value> = Vec::new();

    // 1. Live base response → hygiene + version disclosure + IOC artifact match.
    if let Some(p) = http_get_retry(&client, &url, 2).await {
        findings.extend(scan_http_hygiene(profile, &p, target));
        if let Some(tok) = probe_matched_token(&p, profile.iocs) {
            findings.push(actor_finding(
                profile,
                &format!("{}: public IOC artifact '{}' observed", profile.actor, tok),
                "medium",
                profile.mitre,
                &format!(
                    "Response from {} contains indicator '{}' publicly attributed to {} (possible defacement / ransom note / known artifact).",
                    p.final_url, tok, profile.actor
                ),
                target,
                Some(&p.final_url),
                "",
            ));
        }
    }

    // 2. Email-auth + TLS perimeter (phishing / watering-hole relevance).
    findings.extend(scan_tls_surface(profile, target, &host).await);
    findings.extend(scan_email_auth_surface(profile, target, &host).await);

    // 3. Actor-specific externally-observable initial-access surfaces.
    for surface in &profile.surfaces {
        if !surface.paths.is_empty() {
            let probes =
                probe_paths_concurrent(&client, &url, surface.paths, DEFAULT_PROBE_CONCURRENCY)
                    .await;
            if let Some((p, tok)) = probes.iter().find_map(|p| {
                if status_indicates_presence(p.status) {
                    probe_matched_token(p, surface.tokens).map(|t| (p, t))
                } else {
                    None
                }
            }) {
                findings.push(surface_http_finding(profile, surface, p, &tok, target));
            }
        }
        if !surface.ports.is_empty() {
            for port in tcp_scan(&host, surface.ports, 16).await {
                findings.push(surface_port_finding(profile, surface, port, target, &host));
            }
        }
    }

    if findings.is_empty() {
        return empty_ok(profile.engine_id, target);
    }
    findings.sort_by(|a, b| {
        a["title"]
            .as_str()
            .unwrap_or("")
            .cmp(b["title"].as_str().unwrap_or(""))
    });
    findings.dedup_by(|a, b| a["title"] == b["title"]);
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!(
            "{}: {} surface/exposure finding(s) for {}",
            profile.engine_id, n, profile.actor
        ),
    )
}

fn profile(
    engine_id: &'static str,
    actor: &'static str,
    mitre: &'static str,
    surfaces: Vec<&'static EdgeSurface>,
    iocs: &'static [&'static str],
) -> ActorProfile {
    ActorProfile {
        engine_id,
        actor,
        mitre,
        surfaces,
        iocs,
    }
}

// ── Actor profiles (initial-access surfaces per public CISA/Mandiant reporting) ─

pub async fn run_apt28_techniques_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "apt28_techniques",
            "APT28 (Fancy Bear / GRU 26165)",
            "T1566.001",
            vec![&EXCHANGE_OWA, &ROUNDCUBE_WEBMAIL, &CISCO_IOSXE],
            &["sofacy", "x-agent", "seduploader"],
        ),
    )
    .await
}
cli_wrapper!(run_apt28_techniques, run_apt28_techniques_result);

pub async fn run_apt29_techniques_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "apt29_techniques",
            "APT29 (Cozy Bear / SVR)",
            "T1190",
            vec![
                &EXCHANGE_OWA,
                &PULSE_IVANTI,
                &CITRIX_NETSCALER,
                &SOLARWINDS_ORION,
            ],
            &["sunburst", "teardrop", "wellmess"],
        ),
    )
    .await
}
cli_wrapper!(run_apt29_techniques, run_apt29_techniques_result);

pub async fn run_apt41_techniques_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "apt41_techniques",
            "APT41 (Winnti / China MSS)",
            "T1190",
            vec![&CITRIX_NETSCALER, &ZOHO_MANAGEENGINE, &CISCO_IOSXE],
            &["winnti", "x-acidpour", "x-deadeye"],
        ),
    )
    .await
}
cli_wrapper!(run_apt41_techniques, run_apt41_techniques_result);

pub async fn run_lazarus_group_ttps_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "lazarus_group_ttps",
            "Lazarus (DPRK)",
            "T1190",
            vec![&ZOHO_MANAGEENGINE, &VMWARE_HORIZON, &MOVEIT_TRANSFER],
            &["applejeus", "3cx", "magicline"],
        ),
    )
    .await
}
cli_wrapper!(run_lazarus_group_ttps, run_lazarus_group_ttps_result);

pub async fn run_volt_typhoon_ttps_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "volt_typhoon_ttps",
            "Volt Typhoon (China)",
            "T1190",
            vec![
                &FORTINET_SSLVPN,
                &CISCO_IOSXE,
                &PULSE_IVANTI,
                &ZOHO_MANAGEENGINE,
            ],
            &["fortiguard", "fortinet"],
        ),
    )
    .await
}
cli_wrapper!(run_volt_typhoon_ttps, run_volt_typhoon_ttps_result);

pub async fn run_scattered_spider_ttps_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "scattered_spider_ttps",
            "Scattered Spider (UNC3944)",
            "T1566.004",
            vec![&CITRIX_NETSCALER, &VMWARE_HORIZON, &EXCHANGE_OWA],
            &["okta", "duo"],
        ),
    )
    .await
}
cli_wrapper!(run_scattered_spider_ttps, run_scattered_spider_ttps_result);

pub async fn run_salt_typhoon_ttps_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "salt_typhoon_ttps",
            "Salt Typhoon (China)",
            "T1190",
            vec![&CISCO_IOSXE, &FORTINET_SSLVPN],
            &["cisco"],
        ),
    )
    .await
}
cli_wrapper!(run_salt_typhoon_ttps, run_salt_typhoon_ttps_result);

pub async fn run_fin7_techniques_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "fin7_techniques",
            "FIN7",
            "T1190",
            vec![&RDP_SERVICE, &EXCHANGE_OWA],
            &["carbanak", "badusb"],
        ),
    )
    .await
}
cli_wrapper!(run_fin7_techniques, run_fin7_techniques_result);

pub async fn run_conti_ransomware_ttps_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "conti_ransomware_ttps",
            "Conti",
            "T1486",
            vec![&FORTINET_SSLVPN, &EXCHANGE_OWA, &RDP_SERVICE],
            &["readme.conti", ".conti"],
        ),
    )
    .await
}
cli_wrapper!(run_conti_ransomware_ttps, run_conti_ransomware_ttps_result);

pub async fn run_lockbit_techniques_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "lockbit_techniques",
            "LockBit",
            "T1486",
            vec![&FORTINET_SSLVPN, &CITRIX_NETSCALER, &RDP_SERVICE],
            &["lockbit", "restore-my-files"],
        ),
    )
    .await
}
cli_wrapper!(run_lockbit_techniques, run_lockbit_techniques_result);

pub async fn run_cl0p_techniques_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "cl0p_techniques",
            "Cl0p (TA505 / FIN11)",
            "T1190",
            vec![&MOVEIT_TRANSFER, &GOANYWHERE_MFT],
            &["cl0p", "clop_", "!_readme"],
        ),
    )
    .await
}
cli_wrapper!(run_cl0p_techniques, run_cl0p_techniques_result);

pub async fn run_blackcat_alphv_ttps_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "blackcat_alphv_ttps",
            "BlackCat/ALPHV",
            "T1486",
            vec![&EXCHANGE_OWA, &FORTINET_SSLVPN, &RDP_SERVICE],
            &["alphv", "blackcat", "recover-files"],
        ),
    )
    .await
}
cli_wrapper!(run_blackcat_alphv_ttps, run_blackcat_alphv_ttps_result);

pub async fn run_midnight_blizzard_ttps_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "midnight_blizzard_ttps",
            "Midnight Blizzard (APT29 / SVR)",
            "T1078",
            vec![&EXCHANGE_OWA, &PULSE_IVANTI, &CITRIX_NETSCALER],
            &["nobelium", "midnight"],
        ),
    )
    .await
}
cli_wrapper!(
    run_midnight_blizzard_ttps,
    run_midnight_blizzard_ttps_result
);

pub async fn run_earth_longzhi_ttps_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "earth_longzhi_ttps",
            "Earth Longzhi (APT41 subgroup)",
            "T1190",
            vec![&EXCHANGE_OWA, &ZOHO_MANAGEENGINE],
            &["earth_longzhi", "croxloader"],
        ),
    )
    .await
}
cli_wrapper!(run_earth_longzhi_ttps, run_earth_longzhi_ttps_result);

pub async fn run_equation_group_ttps_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "equation_group_ttps",
            "Equation Group",
            "T1210",
            vec![&SMB_SERVICE, &CISCO_IOSXE],
            &["doublepulsar", "eternalblue"],
        ),
    )
    .await
}
cli_wrapper!(run_equation_group_ttps, run_equation_group_ttps_result);

pub async fn run_sandworm_techniques_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "sandworm_techniques",
            "Sandworm (GRU 74455)",
            "T1190",
            vec![&EXCHANGE_OWA, &CISCO_IOSXE],
            &["industroyer", "blackenergy"],
        ),
    )
    .await
}
cli_wrapper!(run_sandworm_techniques, run_sandworm_techniques_result);

pub async fn run_carbon_spider_ttps_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "carbon_spider_ttps",
            "Carbon Spider (FIN7)",
            "T1190",
            vec![&RDP_SERVICE, &EXCHANGE_OWA],
            &["carbanak"],
        ),
    )
    .await
}
cli_wrapper!(run_carbon_spider_ttps, run_carbon_spider_ttps_result);

pub async fn run_wizard_spider_ttps_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "wizard_spider_ttps",
            "Wizard Spider (TrickBot/Ryuk/Conti)",
            "T1486",
            vec![&EXCHANGE_OWA, &RDP_SERVICE, &FORTINET_SSLVPN],
            &["trickbot", "ryuk", "conti"],
        ),
    )
    .await
}
cli_wrapper!(run_wizard_spider_ttps, run_wizard_spider_ttps_result);

pub async fn run_unc2452_ttps_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "unc2452_ttps",
            "UNC2452 (SolarWinds / APT29)",
            "T1195.002",
            vec![&SOLARWINDS_ORION, &EXCHANGE_OWA],
            &["solarwinds", "orion", "sunburst"],
        ),
    )
    .await
}
cli_wrapper!(run_unc2452_ttps, run_unc2452_ttps_result);

pub async fn run_unc3944_ttps_result(t: &str) -> EngineResult {
    actor_exposure_scan(
        t,
        &profile(
            "unc3944_ttps",
            "UNC3944 (Scattered Spider)",
            "T1566.004",
            vec![&CITRIX_NETSCALER, &VMWARE_HORIZON],
            &["mgm", "caesars"],
        ),
    )
    .await
}
cli_wrapper!(run_unc3944_ttps, run_unc3944_ttps_result);

pub async fn run_quantum_sovereign_nexus_result(t: &str) -> EngineResult {
    crate::pqc_scanner_engine::run_pqc_scanner_result(t).await
}
cli_wrapper!(
    run_quantum_sovereign_nexus,
    run_quantum_sovereign_nexus_result
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_reference_known_surfaces() {
        let p = profile(
            "apt29_techniques",
            "APT29",
            "T1190",
            vec![&EXCHANGE_OWA, &CITRIX_NETSCALER],
            &["sunburst"],
        );
        assert_eq!(p.surfaces.len(), 2);
        assert_eq!(p.surfaces[0].name, EXCHANGE_OWA.name);
        assert_eq!(p.engine_id, "apt29_techniques");
    }

    #[test]
    fn actor_finding_carries_actor_and_cve() {
        let p = profile(
            "cl0p_techniques",
            "Cl0p",
            "T1190",
            vec![&MOVEIT_TRANSFER],
            &[],
        );
        let f = surface_http_finding(
            &p,
            &MOVEIT_TRANSFER,
            &HttpProbe {
                status: 200,
                headers: vec![],
                body: "MOVEit Transfer human.aspx".to_string(),
                final_url: "https://x.test/human.aspx".to_string(),
            },
            "moveit",
            "https://x.test",
        );
        assert_eq!(f["threat_actor"], "Cl0p");
        assert_eq!(f["severity"], "critical");
        assert_eq!(f["probe_depth"], PROBE_DEPTH);
        assert!(f["exploited_cve"]
            .as_str()
            .unwrap()
            .contains("CVE-2023-34362"));
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_apt28_techniques_result("").await;
        assert!(!r.success);
    }
}
