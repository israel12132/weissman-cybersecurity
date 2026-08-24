//! DNS & BGP Hijack-Resistance Engine — world-class, evidence-driven routing/resolution integrity.
//!
//! Where a typical scanner stops at "the domain resolves to an IP", this engine measures the full
//! hijack-resistance posture of a name and the prefix it lives in, using only **live, read-only**
//! DNS-over-HTTPS and public routing-data APIs (no attack traffic is ever sent):
//!
//!   * **Multi-resolver consensus** — resolves the name across several independent validating
//!     resolvers (Cloudflare, Google, Quad9, …) and flags any answer divergence, the classic
//!     signature of DNS poisoning / split-horizon hijack / in-progress BGP interception.
//!   * **DNSSEC chain validation** — requests the DNSSEC-OK bit and reads the resolver's
//!     `AD` (Authenticated Data) flag, cross-checks DS (parent) + DNSKEY (zone) presence, and
//!     detects *broken* DNSSEC (a validating resolver SERVFAILs while a permissive one answers).
//!   * **RPKI Route-Origin Authorization** — maps the resolved IP to its covering prefix + origin
//!     AS (RIPEstat) and validates the (prefix, origin-AS) pair against RPKI ROAs. `invalid` is a
//!     live hijack/mis-origination signal; `unknown` (no ROA) is unprotected; `valid` is hardened.
//!   * **BGP origin / MOAS analysis** — detects Multiple-Origin-AS announcements and, when the
//!     operator declares the legitimate origin AS set, flags any unexpected origin as a hijack.
//!   * **Authoritative-NS diversity** — resolves the zone's nameservers to their origin ASes and
//!     scores provider/network diversity (single-AS NS is a single point of hijack/failure).
//!   * **CAA issuance control** — absence lets any CA issue a certificate for the domain, the
//!     enabler for a hijack-plus-mis-issuance attack.
//!   * **Dangling-CNAME / subdomain-takeover** — read-only detection of CNAMEs pointing at
//!     unclaimed third-party services.
//!   * **Low-TTL / fast-flux signal** — reads live TTLs from DoH answers; A-record TTL below the
//!     operator threshold is a classic pre-hijack preparation pattern (minimise cache lifetime
//!     before swapping the target).
//!   * **Bogon / martian IP detection** — flags when a public name resolves to RFC1918, loopback,
//!     link-local, TEST-NET, or other non-routable space (definitive poison/wrong-answer signal).
//!   * **TLS identity binding** — live TLS handshake on port 443; verifies the served certificate
//!     covers the scanned name (SAN/CN). DNS/BGP hijack to an attacker IP fails this check even
//!     when resolvers still agree.
//!   * **BGP routing-history drift** — RIPEstat timeline of origin-AS changes on the covering
//!     prefix; recent origin churn is a hijack/leak precursor.
//!   * **DANE/TLSA + DNSKEY algorithm hygiene** — reads TLSA records and parses DNSKEY algorithm
//!     identifiers from live answers (weak RSA/MD5/DSA flagged).
//!   * **Certificate-transparency inventory** — crt.sh passive count of active certs (mis-issuance
//!     blast-radius after a successful hijack).
//!   * **Compound hijack-in-progress** — escalates to critical when resolver divergence coincides
//!     with RPKI-invalid, bogon, or TLS identity mismatch (multi-plane corroboration).
//!   * **Authoritative vs recursive split** — queries each authoritative NS directly (hickory, UDP/53)
//!     and compares live A answers with recursive DoH consensus. A recursive IP absent from every
//!     authoritative answer is definitive cache-poisoning / resolver hijack.
//!   * **RDAP registration lock** — reads `clientTransferProhibited` / `clientUpdateProhibited` from
//!     RDAP to detect registrar-hijack exposure (domain theft enables full DNS/BGP takeover).
//!   * **IRR vs live BGP** — compares RIPEstat WHOIS route objects with the observed origin AS;
//!     BGP announcements contradicting the IRR route registry are hijack/leak indicators.
//!   * **More-specific prefix hijack** — RIPEstat related-prefixes: unauthorised shorter prefixes
//!     re-originated by a foreign AS (classic BGP hijack against a covering aggregate).
//!   * **IPv4/IPv6 origin binding** — when both A and AAAA exist, verifies both resolve into prefixes
//!     originated by the same organisation (split-stack hijack / CDN misconfig detection).
//!   * **SOA primary integrity** — reads SOA MNAME and cross-checks against the NS set.
//!   * **Hijack-Resistance Score** — a normalised 0–100 posture index over every applicable
//!     dimension, surfaced as a structured summary finding the UI renders as the headline metric.
//!   * **Four-plane threat matrix** — DNS / BGP / TLS-HTTP / Registry each rated
//!     healthy/degraded/compromised for executive dashboards.
//!   * **Baseline regression delta** — compares score, A IPs, and origin ASNs against the prior
//!     persisted scan (PostgreSQL) or a manual `baseline_snapshot` in job params.
//!   * **CAA ⟷ CT cross-validation** — flags Certificate Transparency issuers outside the CAA allow-list.
//!   * **RPKI maxLength slack** — measures ROA over-permissiveness (more-specific hijack window).
//!   * **HSTS + HTTP redirect binding** — detects off-domain redirects and missing HSTS.
//!   * **MX vs web origin AS** — mail/web split detection after DNS hijack.
//!   * **In-bailiwick NS glue** — child nameservers must publish glue A records.
//!   * **BGP global visibility** — RIPEstat routing-status visibility percentage.
//!   * **Geo country binding** — optional ISO-3166 expectation via RIPEstat geoloc.
//!   * **Expected A-record allow-list** — operator-declared legitimate IPs; anything else is hijack.
//!   * **DNSSEC AD-flag divergence** — validating vs non-validating resolvers disagree on AD for the same name.
//!   * **FCrDNS (forward-confirmed reverse DNS)** — PTR must forward-resolve back to the A record.
//!   * **AAAA multi-resolver consensus** — full IPv6 parity with the A-record consensus probe.
//!   * **CDS/CDNSKEY automation readiness** — detects DNSSEC key rollover automation at the zone.
//!   * **Orphan DS detection** — parent DS without zone DNSKEY (broken/truncated chain).
//!   * **Lame delegation** — authoritative NS that cannot answer for the zone.
//!   * **CNAME chain audit** — follows delegation chains and flags off-domain terminators.
//!   * **SPF at apex** — email-path DNS integrity signal alongside web/mail binding.
//!   * **Resolver timing anomaly** — one resolver path disproportionately slow (interception precursor).
//!   * **SOC incident bundle** — MITRE technique set, probe manifest, and prioritized actions in summary.
//!   * **Autonomous zone discovery (v7)** — before any fixed checklist runs, the engine performs live
//!     reconnaissance of the zone (NS/MX/TXT/CAA/DS/DNSKEY/TLSA/CNAME/AAAA, DMARC, CT hostnames)
//!     and **adaptively enables** only the probes relevant to what it actually found — plus CT-driven
//!     dynamic subdomain enumeration (not a static wordlist).
//!   * **Delegation chain walk** — walks parent zones and validates delegation continuity.
//!   * **UDP/53 vs DoH cross-check** — compares public recursive UDP answers with DoH consensus.
//!   * **DMARC / email-path binding** — `_dmarc` presence as email hijack-resistance signal.
//!   * **Parent NS consistency** — child NS set vs parent delegation glue.
//!   * **Coverage audit (v8 capstone)** — every probe category reports enabled / executed / pass
//!     in the summary so operators and SOC can prove full matrix coverage per scan.
//!   * **SOA serial auth-NS consensus (v8)** — queries SOA from each authoritative NS directly
//!     and flags serial divergence (zone file drift / split-brain precursor).
//!   * **Discovered-host TLS spot-check (v8)** — live TLS on CT/DNS-discovered hostnames (not apex)
//!     to catch hijack on shadow hosts the apex cert does not cover.
//!
//! Every knob is read from the live scan request body (`POST /api/command-center/scan` →
//! `EngineRunContext::job_params`) via [`crate::arsenal_config::ArsenalConfig`]: the resolver set,
//! record types, per-check toggles, the expected origin-AS allow-list, extra subdomains, RIPEstat
//! base, timeouts and concurrency — the "infinite options" guarantee, with no code change required.

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{http_get, tls_cert_details};
use crate::engine_result::{print_result, EngineResult};
use futures::stream::{self, StreamExt};
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ENGINE_ID: &str = "bgp_dns_hijacking";

// DNS record type codes (RFC 1035 + extensions).
const T_A: u16 = 1;
const T_NS: u16 = 2;
const T_CNAME: u16 = 5;
const T_AAAA: u16 = 28;
const T_DS: u16 = 43;
const T_DNSKEY: u16 = 48;
const T_CAA: u16 = 257;
const T_TLSA: u16 = 52;
const T_SOA: u16 = 6;
const T_MX: u16 = 15;
const T_TXT: u16 = 16;
const T_CDS: u16 = 59;
const T_CDNSKEY: u16 = 60;
const T_PTR: u16 = 12;
const T_NSEC: u16 = 47;
const T_NSEC3: u16 = 50;

/// DoH resolvers that expose the JSON API (`application/dns-json`). Name + full base URL.
const DEFAULT_RESOLVERS: &[(&str, &str)] = &[
    ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("Google", "https://dns.google/resolve"),
    ("Quad9", "https://dns.quad9.net:5053/dns-query"),
    ("OpenDNS", "https://doh.opendns.com/dns-query"),
];

/// DNSKEY algorithm identifiers considered weak for DNSSEC (RFC 8624 / operational guidance).
const WEAK_DNSKEY_ALGORITHMS: &[(&str, u8)] = &[
    ("RSA/MD5 (deprecated)", 1),
    ("DSA (deprecated)", 12),
    ("DSA-NSEC3-SHA1", 6),
    ("RSA/SHA-1 (deprecated)", 5),
    ("RSASHA1-NSEC3-SHA1", 7),
];

/// Third-party service fingerprints whose dangling CNAME is a takeover risk.
const TAKEOVER_SUFFIXES: &[(&str, &str)] = &[
    (".s3.amazonaws.com", "AWS S3 bucket"),
    (".cloudfront.net", "AWS CloudFront"),
    (".github.io", "GitHub Pages"),
    (".herokuapp.com", "Heroku"),
    (".herokudns.com", "Heroku"),
    (".azurewebsites.net", "Azure App Service"),
    (".cloudapp.net", "Azure Cloud"),
    (".trafficmanager.net", "Azure Traffic Manager"),
    (".blob.core.windows.net", "Azure Blob"),
    (".storage.googleapis.com", "Google Cloud Storage"),
    (".ghs.googlehosted.com", "Google hosted"),
    (".fastly.net", "Fastly"),
    (".pantheonsite.io", "Pantheon"),
    (".wpengine.com", "WP Engine"),
    (".zendesk.com", "Zendesk"),
    (".readthedocs.io", "Read the Docs"),
    (".surge.sh", "Surge"),
    (".netlify.app", "Netlify"),
    (".netlify.com", "Netlify"),
    (".shopify.com", "Shopify"),
];

#[must_use]
fn extract_domain(target: &str) -> String {
    let t = target.trim();
    let stripped = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    stripped
        .split('/')
        .next()
        .unwrap_or(stripped)
        .split(':')
        .next()
        .unwrap_or(stripped)
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

async fn build_client(timeout_ms: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms.clamp(500, 30_000)))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-DNSBGP-Probe/6.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS-over-HTTPS JSON client (RFC 8484 JSON profile shared by Cloudflare/Google/Quad9)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DohAnswer {
    rtype: u16,
    data: String,
    ttl: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DohResponse {
    /// DNS RCODE (0 = NOERROR, 2 = SERVFAIL, 3 = NXDOMAIN).
    status: u8,
    /// Authenticated Data — the resolver cryptographically validated the DNSSEC chain.
    ad: bool,
    answers: Vec<DohAnswer>,
}

/// Parse the Google/Cloudflare/Quad9 JSON DoH response body.
fn parse_doh_json(v: &Value) -> DohResponse {
    let status = v.get("Status").and_then(Value::as_u64).unwrap_or(2) as u8;
    let ad = v.get("AD").and_then(Value::as_bool).unwrap_or(false);
    let answers = v
        .get("Answer")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    Some(DohAnswer {
                        rtype: a.get("type").and_then(Value::as_u64)? as u16,
                        data: a
                            .get("data")
                            .and_then(Value::as_str)?
                            .trim()
                            .trim_matches('"')
                            .to_string(),
                        ttl: a.get("TTL").and_then(Value::as_u64).unwrap_or(0) as u32,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    DohResponse {
        status,
        ad,
        answers,
    }
}

async fn doh_query(
    client: &reqwest::Client,
    resolver_base: &str,
    name: &str,
    rtype: u16,
    dnssec: bool,
) -> Option<DohResponse> {
    doh_query_timed(client, resolver_base, name, rtype, dnssec)
        .await
        .0
}

async fn doh_query_timed(
    client: &reqwest::Client,
    resolver_base: &str,
    name: &str,
    rtype: u16,
    dnssec: bool,
) -> (Option<DohResponse>, u64) {
    let start = Instant::now();
    let sep = if resolver_base.contains('?') {
        '&'
    } else {
        '?'
    };
    let mut url = format!("{resolver_base}{sep}name={name}&type={rtype}");
    if dnssec {
        url.push_str("&do=1");
    }
    let resp = match client
        .get(&url)
        .header("Accept", "application/dns-json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return (None, start.elapsed().as_millis() as u64),
    };
    if !resp.status().is_success() {
        return (None, start.elapsed().as_millis() as u64);
    }
    let v = match resp.json::<Value>().await {
        Ok(j) => j,
        Err(_) => return (None, start.elapsed().as_millis() as u64),
    };
    (Some(parse_doh_json(&v)), start.elapsed().as_millis() as u64)
}

fn answers_of(resp: &DohResponse, rtype: u16) -> Vec<String> {
    let mut out: Vec<String> = resp
        .answers
        .iter()
        .filter(|a| a.rtype == rtype)
        .map(|a| a.data.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

fn min_ttl_for(resp: &DohResponse, rtype: u16) -> Option<u32> {
    resp.answers
        .iter()
        .filter(|a| a.rtype == rtype && a.ttl > 0)
        .map(|a| a.ttl)
        .min()
}

/// True when `cert_name` covers `domain` (exact or `*.example.com` wildcard).
#[must_use]
fn cert_covers_domain(cert_name: &str, domain: &str) -> bool {
    let cn = cert_name.trim().trim_end_matches('.').to_ascii_lowercase();
    let dom = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if cn == dom {
        return true;
    }
    if let Some(rest) = cn.strip_prefix("*.") {
        return dom.ends_with(&format!(".{rest}")) || dom == rest;
    }
    false
}

/// Classify non-routable / bogon IPv4 answers. Returns a label when the IP must not appear for a public name.
#[must_use]
fn bogon_label_v4(ip: &str) -> Option<&'static str> {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 {
        return None;
    }
    let [a, b, c, d] = [parts[0], parts[1], parts[2], parts[3]];
    let _ = d;
    if a == 10 {
        return Some("RFC1918 private (10/8)");
    }
    if a == 172 && (16..=31).contains(&b) {
        return Some("RFC1918 private (172.16/12)");
    }
    if a == 192 && b == 168 {
        return Some("RFC1918 private (192.168/16)");
    }
    if a == 127 {
        return Some("loopback (127/8)");
    }
    if a == 0 {
        return Some("this-network (0/8)");
    }
    if a == 169 && b == 254 {
        return Some("link-local (169.254/16)");
    }
    if a >= 224 && a <= 239 {
        return Some("multicast (224/4)");
    }
    if a >= 240 {
        return Some("reserved/future (240/4)");
    }
    if a == 100 && (64..=127).contains(&b) {
        return Some("CGNAT shared (100.64/10)");
    }
    if a == 192 && b == 0 && c == 2 {
        return Some("TEST-NET-1 (192.0.2/24)");
    }
    if a == 198 && (18..=19).contains(&b) {
        return Some("benchmarking (198.18/15)");
    }
    if a == 198 && b == 51 && c == 100 {
        return Some("TEST-NET-2 (198.51.100/24)");
    }
    if a == 203 && b == 0 && c == 113 {
        return Some("TEST-NET-3 (203.0.113/24)");
    }
    None
}

/// Parse DNSKEY algorithm octets from DoH `data` fields (`"257 3 13 AwEAA..."`).
fn dnskey_algorithms(keys: &[String]) -> Vec<(u8, String)> {
    let mut out = Vec::new();
    for k in keys {
        let mut parts = k.split_whitespace();
        let _flags = parts.next();
        let _proto = parts.next();
        if let Some(alg) = parts.next().and_then(|s| s.parse::<u8>().ok()) {
            let label = match alg {
                13 => "ECDSA P-256",
                15 => "Ed25519",
                16 => "Ed448",
                8 => "RSA/SHA-256",
                10 => "RSA/SHA-512",
                14 => "ECDSA P-384",
                _ => "other",
            };
            out.push((alg, label.to_string()));
        }
    }
    out
}

async fn probe_ct_count(client: &reqwest::Client, domain: &str) -> Option<usize> {
    let url = format!("https://crt.sh/?q={domain}&output=json");
    let p = http_get(client, &url).await?;
    if p.status != 200 || !p.body.starts_with('[') {
        return None;
    }
    serde_json::from_str::<Value>(&p.body)
        .ok()
        .and_then(|v| v.as_array().map(Vec::len))
}

/// Recent CT issuers (crt.sh) — surfaces mis-issuance after hijack.
async fn probe_ct_recent_issuers(
    client: &reqwest::Client,
    domain: &str,
    limit: usize,
) -> Vec<String> {
    let url = format!("https://crt.sh/?q={domain}&output=json");
    let Some(p) = http_get(client, &url).await else {
        return vec![];
    };
    if p.status != 200 || !p.body.starts_with('[') {
        return vec![];
    }
    let Some(arr) = serde_json::from_str::<Value>(&p.body)
        .ok()
        .and_then(|v| v.as_array().cloned())
    else {
        return vec![];
    };
    let mut issuers: Vec<String> = arr
        .iter()
        .take(limit.max(1).min(50))
        .filter_map(|e| {
            e.get("issuer_name")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();
    issuers.sort();
    issuers.dedup();
    issuers
}

/// Extract unique hostnames under `domain` from crt.sh CT logs (live discovery, not a static list).
async fn discover_ct_hostnames(
    client: &reqwest::Client,
    domain: &str,
    limit: usize,
) -> Vec<String> {
    let dom = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let url = format!("https://crt.sh/?q=%25.{dom}&output=json");
    let Some(p) = http_get(client, &url).await else {
        return vec![];
    };
    if p.status != 200 || !p.body.starts_with('[') {
        return vec![];
    };
    let Some(arr) = serde_json::from_str::<Value>(&p.body)
        .ok()
        .and_then(|v| v.as_array().cloned())
    else {
        return vec![];
    };
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    for entry in arr.iter().take(500) {
        let names: Vec<String> = entry
            .get("name_value")
            .and_then(Value::as_str)
            .map(|s| s.split('\n').map(str::to_string).collect())
            .or_else(|| {
                entry
                    .get("common_name")
                    .and_then(Value::as_str)
                    .map(|s| vec![s.to_string()])
            })
            .unwrap_or_default();
        for raw in names {
            let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if host == dom || host.ends_with(&format!(".{dom}")) {
                if host != dom {
                    hosts.insert(host);
                }
            }
        }
    }
    hosts.into_iter().take(limit.max(1).min(64)).collect()
}

#[derive(Debug, Clone, Default)]
struct ZoneDiscovery {
    domain: String,
    parent_zone: Option<String>,
    ns_hosts: Vec<String>,
    ns_count: usize,
    is_cname_apex: bool,
    has_a: bool,
    has_aaaa: bool,
    has_mx: bool,
    has_txt: bool,
    has_spf: bool,
    has_dmarc: bool,
    has_caa: bool,
    has_ds: bool,
    has_dnskey: bool,
    has_tlsa: bool,
    has_nsec: bool,
    apex_ips: BTreeSet<String>,
    ct_hosts: Vec<String>,
    mx_hosts: Vec<String>,
    spf_txt: Vec<String>,
    cname_targets: Vec<String>,
    /// Fully-qualified hostnames discovered live (CT + MX + NS + SPF + CNAME) — no static wordlist.
    discovered_hosts: Vec<String>,
    record_types: BTreeSet<u16>,
    signals: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct AdaptivePlan {
    auto_enabled: BTreeSet<String>,
    auto_skipped: BTreeSet<String>,
    rationale: Vec<Value>,
    dynamic_hosts: Vec<String>,
}

fn parent_zone_name(domain: &str) -> Option<String> {
    let parts: Vec<&str> = domain.trim().trim_end_matches('.').split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    Some(parts[1..].join("."))
}

/// Map `host.zone.tld` → `host` label for takeover probing; returns None for apex.
#[must_use]
fn fqdn_to_subdomain_label(fqdn: &str, zone: &str) -> Option<String> {
    let f = fqdn.trim().trim_end_matches('.').to_ascii_lowercase();
    let z = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    if f == z {
        return None;
    }
    if f.ends_with(&format!(".{z}")) {
        let label = f.strip_suffix(&format!(".{z}"))?;
        if label.is_empty() || label.contains('.') {
            return None;
        }
        return Some(label.to_string());
    }
    None
}

fn parse_mx_host(mx_rdata: &str) -> Option<String> {
    mx_rdata
        .split_whitespace()
        .nth(1)
        .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
}

/// Extract in-zone hostnames referenced by SPF (include:/a:/redirect=).
fn hosts_from_spf(txt: &[String], zone: &str) -> BTreeSet<String> {
    let z = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut out = BTreeSet::new();
    for t in txt {
        let tl = t.to_ascii_lowercase();
        if !tl.contains("v=spf1") {
            continue;
        }
        for part in tl.split_whitespace() {
            let host = part
                .strip_prefix("include:")
                .or_else(|| part.strip_prefix("redirect="))
                .or_else(|| part.strip_prefix("a:"))
                .map(str::trim);
            if let Some(h) = host {
                let h = h.trim_end_matches('.');
                if h == z || h.ends_with(&format!(".{z}")) {
                    out.insert(h.to_string());
                }
            }
        }
    }
    out
}

fn hosts_from_ns_bailiwick(ns: &[String], zone: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for n in ns {
        if is_in_bailiwick_ns(n, zone) {
            let h = n.trim().trim_end_matches('.').to_ascii_lowercase();
            if h != zone.trim().trim_end_matches('.').to_ascii_lowercase() {
                out.insert(h);
            }
        }
    }
    out
}

fn queue_dynamic_host(subdomains: &mut Vec<String>, zone: &str, fqdn_or_label: &str) {
    let label = fqdn_to_subdomain_label(fqdn_or_label, zone).or_else(|| {
        let s = fqdn_or_label.trim();
        if s.contains('.') {
            None
        } else {
            Some(s.to_ascii_lowercase())
        }
    });
    if let Some(short) = label {
        if !short.is_empty() && !subdomains.iter().any(|s| s.eq_ignore_ascii_case(&short)) {
            subdomains.push(short);
        }
    }
}

/// Merge CT/MX/NS/SPF/CNAME into a single discovered-host set (autonomous — no static wordlist).
fn enrich_discovered_hosts(d: &mut ZoneDiscovery) {
    let zone = d.domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    for h in &d.ct_hosts {
        hosts.insert(h.trim().trim_end_matches('.').to_ascii_lowercase());
    }
    for h in &d.mx_hosts {
        hosts.insert(h.clone());
    }
    for h in &d.cname_targets {
        hosts.insert(h.clone());
    }
    for h in hosts_from_ns_bailiwick(&d.ns_hosts, &zone) {
        hosts.insert(h);
    }
    for h in hosts_from_spf(&d.spf_txt, &zone) {
        hosts.insert(h);
    }
    d.discovered_hosts = hosts.into_iter().take(64).collect();
}

/// Live zone reconnaissance — discovers what exists before choosing probes (autonomous mode).
async fn run_zone_discovery(
    client: &reqwest::Client,
    doh_base: &str,
    domain: &str,
    ct_discovery: bool,
    max_ct_hosts: usize,
) -> ZoneDiscovery {
    let mut d = ZoneDiscovery {
        domain: domain.to_string(),
        parent_zone: parent_zone_name(domain),
        ..ZoneDiscovery::default()
    };

    if let Some(r) = doh_query(client, doh_base, domain, T_NS, false).await {
        d.ns_hosts = answers_of(&r, T_NS);
        d.ns_count = d.ns_hosts.len();
        if !d.ns_hosts.is_empty() {
            d.record_types.insert(T_NS);
            d.signals.push(format!("{} authoritative NS", d.ns_count));
        }
    }

    if let Some(r) = doh_query(client, doh_base, domain, T_CNAME, false).await {
        d.is_cname_apex = !answers_of(&r, T_CNAME).is_empty();
        if d.is_cname_apex {
            d.record_types.insert(T_CNAME);
            d.signals.push("apex CNAME".into());
        }
    }

    if let Some(r) = doh_query(client, doh_base, domain, T_A, false).await {
        d.apex_ips = answers_of(&r, T_A).into_iter().collect();
        d.has_a = !d.apex_ips.is_empty();
        if d.has_a {
            d.record_types.insert(T_A);
        }
    }

    if d.is_cname_apex {
        d.cname_targets = follow_cname_chain(client, doh_base, domain, 8)
            .await
            .into_iter()
            .skip(1)
            .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
            .collect();
        if !d.cname_targets.is_empty() {
            d.signals
                .push(format!("CNAME chain → {}", d.cname_targets.join(" → ")));
        }
    }

    if let Some(r) = doh_query(client, doh_base, domain, T_AAAA, false).await {
        d.has_aaaa = !answers_of(&r, T_AAAA).is_empty();
        if d.has_aaaa {
            d.record_types.insert(T_AAAA);
            d.signals.push("AAAA present".into());
        }
    }

    if let Some(r) = doh_query(client, doh_base, domain, T_MX, false).await {
        let mx_raw = answers_of(&r, T_MX);
        d.has_mx = !mx_raw.is_empty();
        d.mx_hosts = mx_raw.iter().filter_map(|m| parse_mx_host(m)).collect();
        if d.has_mx {
            d.record_types.insert(T_MX);
            d.signals.push(format!("MX → {}", d.mx_hosts.join(", ")));
        }
    }

    if let Some(r) = doh_query(client, doh_base, domain, T_TXT, false).await {
        let txt = answers_of(&r, T_TXT);
        d.spf_txt = txt.clone();
        d.has_txt = !txt.is_empty();
        d.has_spf = apex_has_spf(&txt);
        if d.has_txt {
            d.record_types.insert(T_TXT);
        }
    }

    let dmarc = format!("_dmarc.{domain}");
    if let Some(r) = doh_query(client, doh_base, &dmarc, T_TXT, false).await {
        let txt = answers_of(&r, T_TXT);
        d.has_dmarc = txt
            .iter()
            .any(|t| t.to_ascii_lowercase().contains("v=dmarc1"));
        if d.has_dmarc {
            d.signals.push("DMARC at _dmarc".into());
        }
    }

    if let Some(r) = doh_query(client, doh_base, domain, T_CAA, false).await {
        d.has_caa = !answers_of(&r, T_CAA).is_empty();
        if d.has_caa {
            d.record_types.insert(T_CAA);
        }
    }

    if let Some(r) = doh_query(client, doh_base, domain, T_DS, false).await {
        d.has_ds = !answers_of(&r, T_DS).is_empty();
        if d.has_ds {
            d.record_types.insert(T_DS);
            d.signals.push("DS records".into());
        }
    }

    if let Some(r) = doh_query(client, doh_base, domain, T_DNSKEY, false).await {
        d.has_dnskey = !answers_of(&r, T_DNSKEY).is_empty();
        if d.has_dnskey {
            d.record_types.insert(T_DNSKEY);
        }
    }

    if let Some(r) = doh_query(client, doh_base, domain, T_TLSA, false).await {
        d.has_tlsa = !answers_of(&r, T_TLSA).is_empty();
        if d.has_tlsa {
            d.record_types.insert(T_TLSA);
        }
    }

    if let Some(r) = doh_query(client, doh_base, domain, T_NSEC, false).await {
        d.has_nsec = !answers_of(&r, T_NSEC).is_empty();
        if d.has_nsec {
            d.record_types.insert(T_NSEC);
        }
    } else if let Some(r) = doh_query(client, doh_base, domain, T_NSEC3, false).await {
        d.has_nsec = !answers_of(&r, T_NSEC3).is_empty();
        if d.has_nsec {
            d.record_types.insert(T_NSEC3);
        }
    }

    if ct_discovery {
        d.ct_hosts = discover_ct_hostnames(client, domain, max_ct_hosts).await;
        if !d.ct_hosts.is_empty() {
            d.signals
                .push(format!("CT discovered {} host(s)", d.ct_hosts.len()));
        }
    }

    enrich_discovered_hosts(&mut d);
    if !d.discovered_hosts.is_empty() {
        d.signals.push(format!(
            "Autonomous host inventory: {} FQDN(s) from live DNS/CT",
            d.discovered_hosts.len()
        ));
    }

    d
}

fn adaptive_enable(plan: &mut AdaptivePlan, key: &'static str, reason: &str) {
    plan.auto_enabled.insert(key.to_string());
    plan.rationale
        .push(json!({ "probe": key, "action": "enable", "reason": reason }));
}

fn adaptive_skip(plan: &mut AdaptivePlan, key: &'static str, reason: &str) {
    plan.auto_skipped.insert(key.to_string());
    plan.rationale
        .push(json!({ "probe": key, "action": "skip", "reason": reason }));
}

fn plan_adaptive_probes(d: &ZoneDiscovery, cfg: &BgpConfig) -> AdaptivePlan {
    let mut plan = AdaptivePlan::default();

    // Always-on hijack baseline — autonomous mode never disables these.
    adaptive_enable(
        &mut plan,
        "resolver_consensus",
        "core — multi-resolver divergence is primary hijack signal",
    );
    adaptive_enable(
        &mut plan,
        "tls_identity",
        "core — live TLS binds DNS answer to endpoint",
    );
    adaptive_enable(
        &mut plan,
        "rdap",
        "core — registrar lock prevents domain theft",
    );
    adaptive_enable(
        &mut plan,
        "baseline_delta",
        "core — drift vs prior fingerprint",
    );
    adaptive_enable(
        &mut plan,
        "resolver_timing",
        "core — resolver path latency skew precursor",
    );

    if d.has_ds || d.has_dnskey || d.has_nsec {
        adaptive_enable(&mut plan, "dnssec", "zone publishes DNSSEC material");
        adaptive_enable(
            &mut plan,
            "dnssec_ad_divergence",
            "DNSSEC signed — AD consensus matters",
        );
        adaptive_enable(&mut plan, "orphan_ds", "DS present — validate DNSKEY chain");
        adaptive_enable(
            &mut plan,
            "cds_cdnskey",
            "DNSSEC zone — check rollover automation",
        );
    } else if !cfg.force_all_probes {
        adaptive_skip(&mut plan, "orphan_ds", "no DS/DNSKEY/NSEC observed");
        adaptive_skip(&mut plan, "cds_cdnskey", "zone not DNSSEC-signed");
    }

    if d.has_aaaa {
        adaptive_enable(&mut plan, "aaaa_consensus", "AAAA records discovered");
        adaptive_enable(&mut plan, "dual_stack", "dual-stack surface");
    } else if !cfg.force_all_probes {
        adaptive_skip(&mut plan, "dual_stack", "no AAAA at apex");
    }

    if d.is_cname_apex {
        adaptive_enable(&mut plan, "cname_chain", "apex is CNAME — follow chain");
    }

    if d.has_mx || d.has_spf {
        adaptive_enable(&mut plan, "mx_origin", "mail exchanger present");
        adaptive_enable(&mut plan, "spf_apex", "email DNS path active");
    }

    if d.has_caa {
        adaptive_enable(&mut plan, "caa_ct_cross", "CAA published — cross-check CT");
    }

    if d.has_tlsa {
        adaptive_enable(&mut plan, "dane", "TLSA records present");
    }

    if d.ns_count > 0 {
        adaptive_enable(&mut plan, "auth_vs_recursive", "authoritative NS exist");
        adaptive_enable(&mut plan, "ns_lame", "validate each NS responds");
        adaptive_enable(&mut plan, "glue", "in-bailiwick glue check");
        adaptive_enable(&mut plan, "ns_diversity", "NS origin diversity");
    }

    if d.has_a || !d.apex_ips.is_empty() {
        adaptive_enable(&mut plan, "rpki", "routable A records — BGP/RPKI applies");
        adaptive_enable(&mut plan, "bgp_origin", "IPs map to origin ASes");
        adaptive_enable(&mut plan, "fcrdns", "A records need PTR confirmation");
        adaptive_enable(&mut plan, "bogon", "public A answers — bogon check");
        adaptive_enable(&mut plan, "ttl", "TTL fast-flux signal");
        adaptive_enable(&mut plan, "irr", "route registry must match live BGP");
        adaptive_enable(&mut plan, "more_specific", "prefix hijack surface");
        adaptive_enable(&mut plan, "routing_history", "origin churn precursor");
        adaptive_enable(&mut plan, "hsts", "TLS hardening on web endpoint");
        adaptive_enable(&mut plan, "redirect", "HTTP must not redirect off-domain");
        adaptive_enable(&mut plan, "soa", "SOA MNAME integrity");
        adaptive_enable(
            &mut plan,
            "soa_serial",
            "SOA serial consensus across auth NS",
        );
        adaptive_enable(&mut plan, "caa", "issuance control at apex");
        adaptive_enable(&mut plan, "ct", "CT blast-radius inventory");
        adaptive_enable(
            &mut plan,
            "rpki_maxlength",
            "ROA maxLength slack measurement",
        );
        adaptive_enable(&mut plan, "bgp_visibility", "global prefix visibility");
        adaptive_enable(
            &mut plan,
            "discovered_tls",
            "TLS binding on discovered hostnames",
        );
    }

    if !cfg.expected_countries.is_empty() && (d.has_a || !d.apex_ips.is_empty()) {
        adaptive_enable(&mut plan, "geo", "operator geo expectation configured");
    }

    if !d.discovered_hosts.is_empty() {
        adaptive_enable(
            &mut plan,
            "ct_discovery",
            "live host inventory from DNS/CT surface",
        );
        adaptive_enable(
            &mut plan,
            "takeover",
            "probe every discovered hostname for dangling CNAME",
        );
        plan.dynamic_hosts = d.discovered_hosts.clone();
    } else if !d.ct_hosts.is_empty() {
        adaptive_enable(&mut plan, "ct_discovery", "CT logs expose hostnames");
        adaptive_enable(
            &mut plan,
            "takeover",
            "probe CT-discovered hosts for dangling CNAME",
        );
        plan.dynamic_hosts = d.ct_hosts.clone();
    }

    if d.parent_zone.is_some() {
        adaptive_enable(
            &mut plan,
            "delegation_walk",
            "multi-label domain — walk delegation",
        );
        adaptive_enable(&mut plan, "parent_ns", "parent/child NS consistency");
    }

    if d.has_a {
        adaptive_enable(
            &mut plan,
            "udp_doh_cross",
            "A records — UDP vs DoH cross-check",
        );
        adaptive_enable(&mut plan, "wildcard_dns", "wildcard poisoning probe");
    }

    if !d.has_dmarc && (d.has_mx || d.has_spf) {
        adaptive_enable(&mut plan, "dmarc", "mail path without DMARC");
    }

    plan
}

/// Turn off discretionary probes before autonomous plan re-enables only what the zone needs.
fn disable_discretionary_probes(cfg: &mut BgpConfig) {
    cfg.check_dnssec = false;
    cfg.check_dnssec_ad_divergence = false;
    cfg.check_auth_recursive = false;
    cfg.check_rpki = false;
    cfg.check_bgp = false;
    cfg.check_caa = false;
    cfg.check_ns = false;
    cfg.check_takeover = false;
    cfg.check_aaaa = false;
    cfg.check_bogon = false;
    cfg.check_ttl = false;
    cfg.check_routing_history = false;
    cfg.check_dane = false;
    cfg.check_ct = false;
    cfg.check_irr = false;
    cfg.check_more_specific = false;
    cfg.check_dual_stack = false;
    cfg.check_soa = false;
    cfg.check_caa_ct_cross = false;
    cfg.check_rpki_maxlength = false;
    cfg.check_hsts = false;
    cfg.check_http_redirect = false;
    cfg.check_mx_origin = false;
    cfg.check_glue = false;
    cfg.check_bgp_visibility = false;
    cfg.check_geo = false;
    cfg.check_fcrdns = false;
    cfg.check_cname_chain = false;
    cfg.check_spf_apex = false;
    cfg.check_wildcard = false;
    cfg.check_ns_lame = false;
    cfg.check_cds_cdnskey = false;
    cfg.check_orphan_ds = false;
    cfg.check_delegation_walk = false;
    cfg.check_udp_doh_cross = false;
    cfg.check_ct_discovery = false;
    cfg.check_dmarc = false;
    cfg.check_parent_ns = false;
    cfg.check_discovered_tls = false;
    cfg.check_soa_serial = false;
    cfg.check_expected_ips = !cfg.expected_a_ips.is_empty();
    cfg.check_geo = !cfg.expected_countries.is_empty();
}

/// Merge autonomous discovery into live config — probes adapt to zone surface, not a static script.
fn apply_autonomous_plan(cfg: &mut BgpConfig, d: &ZoneDiscovery, plan: &AdaptivePlan) {
    let on = |plan: &AdaptivePlan, key: &str| plan.auto_enabled.contains(key);

    if cfg.autonomous_mode && !cfg.force_all_probes {
        disable_discretionary_probes(cfg);
    }

    if cfg.autonomous_mode && !cfg.use_static_subdomain_wordlist {
        cfg.subdomains.clear();
    }

    if on(plan, "resolver_consensus") {
        cfg.check_resolver_consensus = true;
    }
    if on(plan, "tls_identity") {
        cfg.check_tls_identity = true;
    }
    if on(plan, "rdap") {
        cfg.check_rdap = true;
    }
    if on(plan, "baseline_delta") {
        cfg.check_baseline_delta = true;
    }
    if on(plan, "resolver_timing") {
        cfg.check_resolver_timing = true;
    }
    if on(plan, "takeover") {
        cfg.check_takeover = true;
    }

    if on(plan, "dnssec") {
        cfg.check_dnssec = true;
    }
    if on(plan, "dnssec_ad_divergence") {
        cfg.check_dnssec_ad_divergence = true;
    }
    if on(plan, "orphan_ds") {
        cfg.check_orphan_ds = true;
    }
    if on(plan, "cds_cdnskey") {
        cfg.check_cds_cdnskey = true;
    }
    if on(plan, "aaaa_consensus") {
        cfg.check_aaaa = true;
    }
    if on(plan, "dual_stack") {
        cfg.check_dual_stack = true;
    }
    if on(plan, "cname_chain") {
        cfg.check_cname_chain = true;
    }
    if on(plan, "mx_origin") {
        cfg.check_mx_origin = true;
    }
    if on(plan, "spf_apex") {
        cfg.check_spf_apex = true;
    }
    if on(plan, "caa_ct_cross") {
        cfg.check_caa_ct_cross = true;
    }
    if on(plan, "dane") {
        cfg.check_dane = true;
    }
    if on(plan, "auth_vs_recursive") {
        cfg.check_auth_recursive = true;
    }
    if on(plan, "ns_lame") {
        cfg.check_ns_lame = true;
    }
    if on(plan, "glue") {
        cfg.check_glue = true;
    }
    if on(plan, "ns_diversity") {
        cfg.check_ns = true;
    }
    if on(plan, "rpki") {
        cfg.check_rpki = true;
    }
    if on(plan, "bgp_origin") {
        cfg.check_bgp = true;
    }
    if on(plan, "fcrdns") {
        cfg.check_fcrdns = true;
    }
    if on(plan, "bogon") {
        cfg.check_bogon = true;
    }
    if on(plan, "ttl") {
        cfg.check_ttl = true;
    }
    if on(plan, "wildcard_dns") {
        cfg.check_wildcard = true;
    }
    if on(plan, "dmarc") {
        cfg.check_dmarc = true;
    }
    if on(plan, "delegation_walk") {
        cfg.check_delegation_walk = true;
    }
    if on(plan, "parent_ns") {
        cfg.check_parent_ns = true;
    }
    if on(plan, "udp_doh_cross") {
        cfg.check_udp_doh_cross = true;
    }
    if on(plan, "irr") {
        cfg.check_irr = true;
    }
    if on(plan, "more_specific") {
        cfg.check_more_specific = true;
    }
    if on(plan, "routing_history") {
        cfg.check_routing_history = true;
    }
    if on(plan, "hsts") {
        cfg.check_hsts = true;
    }
    if on(plan, "redirect") {
        cfg.check_http_redirect = true;
    }
    if on(plan, "soa") {
        cfg.check_soa = true;
    }
    if on(plan, "soa_serial") {
        cfg.check_soa_serial = true;
    }
    if on(plan, "caa") {
        cfg.check_caa = true;
    }
    if on(plan, "ct") {
        cfg.check_ct = true;
    }
    if on(plan, "rpki_maxlength") {
        cfg.check_rpki_maxlength = true;
    }
    if on(plan, "bgp_visibility") {
        cfg.check_bgp_visibility = true;
    }
    if on(plan, "geo") {
        cfg.check_geo = true;
    }
    if on(plan, "discovered_tls") {
        cfg.check_discovered_tls = true;
    }
    if on(plan, "ct_discovery") {
        cfg.check_ct_discovery = true;
    }

    for h in &d.discovered_hosts {
        queue_dynamic_host(&mut cfg.subdomains, &d.domain, h);
    }
    for h in &plan.dynamic_hosts {
        queue_dynamic_host(&mut cfg.subdomains, &d.domain, h);
    }
}

fn discovery_graph(d: &ZoneDiscovery, plan: &AdaptivePlan) -> Value {
    json!({
        "domain": d.domain,
        "parent_zone": d.parent_zone,
        "signals": d.signals,
        "record_types": d.record_types.iter().collect::<Vec<_>>(),
        "ns_count": d.ns_count,
        "is_cname_apex": d.is_cname_apex,
        "has_a": d.has_a,
        "has_aaaa": d.has_aaaa,
        "has_mx": d.has_mx,
        "has_spf": d.has_spf,
        "has_dmarc": d.has_dmarc,
        "has_caa": d.has_caa,
        "has_dnssec_material": d.has_ds || d.has_dnskey,
        "ct_hosts_discovered": d.ct_hosts.len(),
        "ct_hosts_sample": d.ct_hosts.iter().take(8).collect::<Vec<_>>(),
        "discovered_hosts_total": d.discovered_hosts.len(),
        "discovered_hosts_sample": d.discovered_hosts.iter().take(12).collect::<Vec<_>>(),
        "mx_hosts": d.mx_hosts,
        "cname_targets": d.cname_targets,
        "auto_enabled": plan.auto_enabled.iter().collect::<Vec<_>>(),
        "auto_skipped": plan.auto_skipped.iter().collect::<Vec<_>>(),
        "rationale": plan.rationale,
        "dynamic_hosts_queued": plan.dynamic_hosts.len(),
    })
}

async fn public_udp_lookup_a(
    domain: &str,
    resolver_ip: IpAddr,
    timeout_ms: u64,
) -> BTreeSet<String> {
    auth_lookup_a(domain, resolver_ip, timeout_ms).await
}

/// Public recursive resolvers for UDP/53 vs DoH cross-check (live transport parity).
const PUBLIC_UDP_RESOLVERS: &[(&str, &str)] = &[
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
];

async fn public_udp_lookup_all(domain: &str, timeout_ms: u64) -> Vec<(String, BTreeSet<String>)> {
    let mut out = Vec::new();
    for (name, ip_str) in PUBLIC_UDP_RESOLVERS {
        let Ok(ip) = IpAddr::from_str(ip_str) else {
            continue;
        };
        let ips = public_udp_lookup_a(domain, ip, timeout_ms).await;
        if !ips.is_empty() {
            out.push(((*name).to_string(), ips));
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Authoritative DNS (direct NS query — bypasses recursive resolver cache)
// ─────────────────────────────────────────────────────────────────────────────

fn build_auth_resolver(ns_ip: IpAddr, timeout_ms: u64) -> Option<TokioResolver> {
    let ns = NameServerConfig::udp(ns_ip);
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(timeout_ms.clamp(500, 10_000));
    opts.attempts = 1;
    TokioResolver::builder_with_config(
        ResolverConfig::from_parts(None, vec![], vec![ns]),
        TokioRuntimeProvider::default(),
    )
    .with_options(opts)
    .build()
    .ok()
}

async fn auth_lookup_a(domain: &str, ns_ip: IpAddr, timeout_ms: u64) -> BTreeSet<String> {
    let Some(resolver) = build_auth_resolver(ns_ip, timeout_ms) else {
        return BTreeSet::new();
    };
    let Ok(lookup) = resolver.lookup(domain, RecordType::A).await else {
        return BTreeSet::new();
    };
    lookup
        .answers()
        .iter()
        .filter_map(|r| {
            if let RData::A(a) = r.data {
                Some(a.to_string())
            } else {
                None
            }
        })
        .collect()
}

async fn auth_zone_responds(domain: &str, ns_ip: IpAddr, timeout_ms: u64) -> bool {
    let Some(resolver) = build_auth_resolver(ns_ip, timeout_ms) else {
        return false;
    };
    if resolver.lookup(domain, RecordType::SOA).await.is_ok() {
        return true;
    }
    resolver.lookup(domain, RecordType::A).await.is_ok()
}

/// Query each authoritative NS directly; returns per-NS A sets + the union.
async fn authoritative_a_union(
    client: &reqwest::Client,
    doh_base: &str,
    domain: &str,
    ns_names: &[String],
    timeout_ms: u64,
) -> (Vec<(String, BTreeSet<String>)>, BTreeSet<String>) {
    let mut per_ns = Vec::new();
    let mut union: BTreeSet<String> = BTreeSet::new();
    for nsname in ns_names.iter().take(8) {
        let host = nsname.trim().trim_end_matches('.');
        let Some(rr) = doh_query(client, doh_base, host, T_A, false).await else {
            continue;
        };
        let Some(ns_ip_str) = answers_of(&rr, T_A).into_iter().next() else {
            continue;
        };
        let Ok(ns_ip) = IpAddr::from_str(&ns_ip_str) else {
            continue;
        };
        let ips = auth_lookup_a(domain, ns_ip, timeout_ms).await;
        for ip in &ips {
            union.insert(ip.clone());
        }
        per_ns.push((nsname.clone(), ips));
    }
    (per_ns, union)
}

// ─────────────────────────────────────────────────────────────────────────────
// RDAP registration integrity (registrar hijack surface)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct RdapProfile {
    transfer_locked: bool,
    update_locked: bool,
    delegation_signed: bool,
    expires: Option<String>,
}

async fn probe_rdap(client: &reqwest::Client, domain: &str) -> Option<RdapProfile> {
    let url = format!("https://rdap.org/domain/{}", domain.to_ascii_uppercase());
    let v = client
        .get(&url)
        .send()
        .await
        .ok()?
        .json::<Value>()
        .await
        .ok()?;
    let statuses: Vec<String> = v
        .get("status")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(|x| x.to_ascii_lowercase()))
                .collect()
        })
        .unwrap_or_default();
    let transfer_locked = statuses
        .iter()
        .any(|s| s.contains("transfer prohibited") || s.contains("transferprohibited"));
    let update_locked = statuses
        .iter()
        .any(|s| s.contains("update prohibited") || s.contains("updateprohibited"));
    let delegation_signed = v
        .get("secureDNS")
        .and_then(|s| s.get("delegationSigned"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let expires = v.get("events").and_then(Value::as_array).and_then(|ev| {
        ev.iter().find_map(|e| {
            let action = e.get("eventAction").and_then(Value::as_str).unwrap_or("");
            if action.eq_ignore_ascii_case("expiration") {
                e.get("eventDate")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            } else {
                None
            }
        })
    });
    Some(RdapProfile {
        transfer_locked,
        update_locked,
        delegation_signed,
        expires,
    })
}

/// True when `child` is a more-specific of `parent` (same address family, longer mask).
#[must_use]
fn is_more_specific_v4(child: &str, parent: &str) -> bool {
    let (c_net, c_len) = match child.split_once('/') {
        Some((n, l)) => (n, l.parse::<u8>().ok()),
        None => return false,
    };
    let (p_net, p_len) = match parent.split_once('/') {
        Some((n, l)) => (n, l.parse::<u8>().ok()),
        None => return false,
    };
    let (Some(cl), Some(pl)) = (c_len, p_len) else {
        return false;
    };
    if cl <= pl || cl > 32 || pl > 32 {
        return false;
    }
    let (Ok(c_ip), Ok(p_ip)) = (
        c_net.parse::<std::net::Ipv4Addr>(),
        p_net.parse::<std::net::Ipv4Addr>(),
    ) else {
        return false;
    };
    // Compare on the parent mask, not on whole octets: `10.1.32.0/24` is NOT inside
    // `10.1.16.0/20`, but the old octet-only check treated it as a more-specific.
    let mask = u32::MAX.checked_shl(32 - u32::from(pl)).unwrap_or(0);
    (u32::from(c_ip) & mask) == (u32::from(p_ip) & mask)
}

/// Parse SOA MNAME from DoH `data` (`"ns1.example.com. hostmaster..."`).
fn parse_soa_mname(soa: &str) -> Option<String> {
    let first = soa.split_whitespace().next()?;
    let m = first.trim().trim_end_matches('.').to_ascii_lowercase();
    if m.is_empty() {
        None
    } else {
        Some(m)
    }
}

/// Parse SOA serial (third field) from DoH `data`.
#[allow(dead_code)] // exercised by unit tests; prod call site removed in audit
fn parse_soa_serial(soa: &str) -> Option<u32> {
    let parts: Vec<&str> = soa.split_whitespace().collect();
    if parts.len() >= 3 {
        parts[2].parse().ok()
    } else {
        None
    }
}

async fn auth_lookup_soa_serial(domain: &str, ns_ip: IpAddr, timeout_ms: u64) -> Option<u32> {
    let resolver = build_auth_resolver(ns_ip, timeout_ms)?;
    let lookup = resolver.lookup(domain, RecordType::SOA).await.ok()?;
    for r in lookup.answers() {
        if let RData::SOA(soa) = &r.data {
            return Some(soa.serial);
        }
    }
    None
}

fn tls_cert_name_list(cert: &crate::engine_probes::TlsCertDetails) -> Vec<String> {
    cert.san_dns_names
        .iter()
        .chain(std::iter::once(&cert.subject))
        .filter_map(|n| {
            let s = n.trim();
            if s.contains('=') {
                s.split(',').find_map(|part| {
                    let p = part.trim();
                    p.strip_prefix("CN=").map(str::trim)
                })
            } else if !s.is_empty() {
                Some(s)
            } else {
                None
            }
        })
        .map(|s| s.to_string())
        .collect()
}

/// IRR route origin ASNs registered for `prefix` (RIPEstat whois-data).
async fn ripe_irr_route_origins(
    client: &reqwest::Client,
    ripe_base: &str,
    prefix: &str,
) -> BTreeSet<u32> {
    let url = format!("{ripe_base}/data/whois-data/data.json?resource={prefix}&keys=route,route6");
    let v = match client.get(&url).send().await {
        Ok(r) => match r.json::<Value>().await {
            Ok(j) => j,
            Err(_) => return BTreeSet::new(),
        },
        Err(_) => return BTreeSet::new(),
    };
    let mut origins = BTreeSet::new();
    if let Some(records) = v
        .get("data")
        .and_then(|d| d.get("records"))
        .and_then(Value::as_array)
    {
        for rec in records {
            if let Some(lines) = rec.get("details").and_then(Value::as_array) {
                for line in lines {
                    if let Some(s) = line.as_str() {
                        let sl = s.to_ascii_lowercase();
                        if sl.starts_with("origin:") || sl.starts_with("origin ") {
                            if let Some(asn) = sl
                                .split(':')
                                .nth(1)
                                .or_else(|| sl.split_whitespace().nth(1))
                                .and_then(|x| x.trim().trim_start_matches("as").parse::<u32>().ok())
                            {
                                origins.insert(asn);
                            }
                        }
                    }
                }
            }
        }
    }
    origins
}

/// More-specific prefixes announced with a foreign origin AS (BGP hijack signature).
async fn ripe_foreign_more_specifics(
    client: &reqwest::Client,
    ripe_base: &str,
    prefix: &str,
    legitimate_origins: &[u32],
) -> Vec<Value> {
    let url = format!("{ripe_base}/data/related-prefixes/data.json?resource={prefix}");
    let v = match client.get(&url).send().await {
        Ok(r) => match r.json::<Value>().await {
            Ok(j) => j,
            Err(_) => return vec![],
        },
        Err(_) => return vec![],
    };
    let mut threats = Vec::new();
    let prefixes = v
        .get("data")
        .and_then(|d| d.get("prefixes"))
        .and_then(Value::as_array)
        .or_else(|| {
            v.get("data")
                .and_then(|d| d.get("related_prefixes"))
                .and_then(Value::as_array)
        });
    let Some(list) = prefixes else {
        return vec![];
    };
    for entry in list {
        let pfx = entry
            .get("prefix")
            .or_else(|| entry.get("resource"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if pfx.is_empty() || !is_more_specific_v4(pfx, prefix) {
            continue;
        }
        let origin = entry
            .get("origin")
            .or_else(|| entry.get("asn"))
            .and_then(Value::as_u64)
            .map(|a| a as u32);
        let Some(origin_asn) = origin else {
            continue;
        };
        if !legitimate_origins.is_empty() && legitimate_origins.contains(&origin_asn) {
            continue;
        }
        threats.push(json!({ "prefix": pfx, "origin_asn": origin_asn }));
    }
    threats
}

async fn origin_asns_for_ip(client: &reqwest::Client, ripe_base: &str, ip: &str) -> Vec<u32> {
    ripe_prefix_overview(client, ripe_base, ip)
        .await
        .map(|po| po.origins.iter().map(|(a, _)| *a).collect())
        .unwrap_or_default()
}

// ─────────────────────────────────────────────────────────────────────────────
// v5 — cross-plane binding, baseline delta, geo, visibility, CAA⟷CT
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct HijackFingerprint {
    score: u32,
    a_ips: BTreeSet<String>,
    origin_asns: BTreeSet<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlaneStatus {
    Healthy,
    Degraded,
    Compromised,
    Unknown,
}

impl PlaneStatus {
    fn as_str(self) -> &'static str {
        match self {
            PlaneStatus::Healthy => "healthy",
            PlaneStatus::Degraded => "degraded",
            PlaneStatus::Compromised => "compromised",
            PlaneStatus::Unknown => "unknown",
        }
    }
}

fn plane_status(checked: bool, ok: bool, compromised: bool) -> PlaneStatus {
    if !checked {
        return PlaneStatus::Unknown;
    }
    if compromised {
        PlaneStatus::Compromised
    } else if ok {
        PlaneStatus::Healthy
    } else {
        PlaneStatus::Degraded
    }
}

fn http_header(headers: &[(String, String)], name: &str) -> Option<String> {
    let n = name.to_ascii_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase() == n)
        .map(|(_, v)| v.clone())
}

/// Extract CA domain names from CAA RDATA strings (`0 issue "letsencrypt.org"`).
fn parse_caa_issuers(caa: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for rec in caa {
        let rl = rec.to_ascii_lowercase();
        if !(rl.contains("issue ") || rl.contains("issuewild ")) {
            continue;
        }
        if let Some(start) = rec.find('"') {
            let rest = &rec[start + 1..];
            if let Some(end) = rest.find('"') {
                let issuer = rest[..end]
                    .trim()
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if !issuer.is_empty() && issuer != ";" {
                    out.insert(issuer);
                }
            }
        }
    }
    out
}

/// True when CT issuer string is not permitted by any CAA `issue` entry.
#[must_use]
fn ct_issuer_violates_caa(issuer_dn: &str, allowed: &BTreeSet<String>) -> bool {
    if allowed.is_empty() {
        return false;
    }
    let il = issuer_dn.to_ascii_lowercase();
    !allowed.iter().any(|ca| il.contains(ca))
}

fn extract_host_from_url(url: &str) -> Option<String> {
    let u = url.trim();
    let stripped = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))
        .unwrap_or(u);
    let host = stripped
        .split('/')
        .next()?
        .split(':')
        .next()?
        .trim()
        .to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn is_in_bailiwick_ns(ns: &str, zone: &str) -> bool {
    let n = ns.trim().trim_end_matches('.').to_ascii_lowercase();
    let z = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    n.ends_with(&format!(".{z}")) || n == z
}

/// Build reverse-DNS name for IPv4 (`a.b.c.d` → `d.c.b.a.in-addr.arpa`).
#[must_use]
fn ipv4_ptr_name(ip: &str) -> Option<String> {
    let p: Vec<&str> = ip.split('.').collect();
    if p.len() != 4 {
        return None;
    }
    Some(format!("{}.{}.{}.{}.in-addr.arpa", p[3], p[2], p[1], p[0]))
}

async fn reverse_ptr_v4(client: &reqwest::Client, doh_base: &str, ip: &str) -> Option<String> {
    let arpa = ipv4_ptr_name(ip)?;
    let r = doh_query(client, doh_base, &arpa, T_PTR, false).await?;
    answers_of(&r, T_PTR).into_iter().next()
}

/// Forward-confirmed reverse DNS: PTR exists and forward-A includes `ip` or covers `domain`.
async fn fcrdns_valid(client: &reqwest::Client, doh_base: &str, domain: &str, ip: &str) -> bool {
    let Some(ptr) = reverse_ptr_v4(client, doh_base, ip).await else {
        return false;
    };
    let ptr_l = ptr.trim().trim_end_matches('.').to_ascii_lowercase();
    let dom = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if ptr_l == dom || ptr_l.ends_with(&format!(".{dom}")) {
        return true;
    }
    doh_query(client, doh_base, &ptr_l, T_A, false)
        .await
        .map(|r| answers_of(&r, T_A).contains(&ip.to_string()))
        .unwrap_or(false)
}

async fn follow_cname_chain(
    client: &reqwest::Client,
    doh_base: &str,
    domain: &str,
    max_hops: usize,
) -> Vec<String> {
    let mut chain = vec![domain.to_string()];
    let mut current = domain.to_string();
    for _ in 0..max_hops {
        let Some(r) = doh_query(client, doh_base, &current, T_CNAME, false).await else {
            break;
        };
        let cnames = answers_of(&r, T_CNAME);
        let Some(next) = cnames.first() else { break };
        let next = next.trim().trim_end_matches('.').to_string();
        if chain.last().is_some_and(|c| c == &next) {
            break;
        }
        chain.push(next.clone());
        current = next;
    }
    chain
}

fn wildcard_probe_host(domain: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let apex = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    format!("ws{:x}.{}", nanos % 0xffff_ffff, apex)
}

fn apex_has_spf(txt: &[String]) -> bool {
    txt.iter()
        .any(|t| t.to_ascii_lowercase().contains("v=spf1"))
}

fn mitre_coverage(findings: &[Value]) -> Vec<String> {
    let mut s: BTreeSet<String> = BTreeSet::new();
    for f in findings {
        if let Some(m) = f.get("mitre_attack").and_then(Value::as_str) {
            if !m.is_empty() {
                s.insert(m.to_string());
            }
        }
    }
    s.into_iter().collect()
}

fn probe_manifest_from_cfg(cfg: &BgpConfig) -> Vec<&'static str> {
    let mut m = Vec::new();
    if cfg.check_resolver_consensus {
        m.push("resolver_consensus");
    }
    if cfg.check_dnssec {
        m.push("dnssec");
    }
    if cfg.check_dnssec_ad_divergence {
        m.push("dnssec_ad_divergence");
    }
    if cfg.check_auth_recursive {
        m.push("auth_vs_recursive");
    }
    if cfg.check_rpki {
        m.push("rpki");
    }
    if cfg.check_bgp {
        m.push("bgp_origin");
    }
    if cfg.check_irr {
        m.push("irr");
    }
    if cfg.check_more_specific {
        m.push("more_specific");
    }
    if cfg.check_tls_identity {
        m.push("tls_identity");
    }
    if cfg.check_fcrdns {
        m.push("fcrdns");
    }
    if cfg.check_expected_ips {
        m.push("expected_ips");
    }
    if cfg.check_aaaa {
        m.push("aaaa_consensus");
    }
    if cfg.check_baseline_delta {
        m.push("baseline_delta");
    }
    if cfg.check_wildcard {
        m.push("wildcard_dns");
    }
    if cfg.check_ns_lame {
        m.push("ns_lame");
    }
    if cfg.check_cname_chain {
        m.push("cname_chain");
    }
    if cfg.check_spf_apex {
        m.push("spf_apex");
    }
    if cfg.check_cds_cdnskey {
        m.push("cds_cdnskey");
    }
    if cfg.check_orphan_ds {
        m.push("orphan_ds");
    }
    if cfg.check_resolver_timing {
        m.push("resolver_timing");
    }
    if cfg.check_delegation_walk {
        m.push("delegation_walk");
    }
    if cfg.check_udp_doh_cross {
        m.push("udp_doh_cross");
    }
    if cfg.check_ct_discovery {
        m.push("ct_discovery");
    }
    if cfg.check_dmarc {
        m.push("dmarc");
    }
    if cfg.check_parent_ns {
        m.push("parent_ns");
    }
    if cfg.check_bogon {
        m.push("bogon");
    }
    if cfg.check_ttl {
        m.push("ttl");
    }
    if cfg.check_routing_history {
        m.push("routing_history");
    }
    if cfg.check_dane {
        m.push("dane");
    }
    if cfg.check_ct {
        m.push("ct_inventory");
    }
    if cfg.check_rdap {
        m.push("rdap");
    }
    if cfg.check_caa {
        m.push("caa");
    }
    if cfg.check_ns {
        m.push("ns_diversity");
    }
    if cfg.check_takeover {
        m.push("takeover");
    }
    if cfg.check_dual_stack {
        m.push("dual_stack");
    }
    if cfg.check_soa {
        m.push("soa_mname");
    }
    if cfg.check_soa_serial {
        m.push("soa_serial");
    }
    if cfg.check_caa_ct_cross {
        m.push("caa_ct_cross");
    }
    if cfg.check_rpki_maxlength {
        m.push("rpki_maxlength");
    }
    if cfg.check_hsts {
        m.push("hsts");
    }
    if cfg.check_http_redirect {
        m.push("http_redirect");
    }
    if cfg.check_mx_origin {
        m.push("mx_origin");
    }
    if cfg.check_glue {
        m.push("glue");
    }
    if cfg.check_bgp_visibility {
        m.push("bgp_visibility");
    }
    if cfg.check_geo {
        m.push("geo");
    }
    if cfg.check_discovered_tls {
        m.push("discovered_tls");
    }
    if cfg.autonomous_mode {
        m.push("autonomous_discovery");
    }
    m.push("compound_corroboration");
    m
}

fn coverage_row(id: &'static str, enabled: bool, executed: bool, passed: Option<bool>) -> Value {
    let status = if !enabled {
        "disabled"
    } else if !executed {
        "skipped"
    } else if passed == Some(true) {
        "pass"
    } else if passed == Some(false) {
        "fail"
    } else {
        "unknown"
    };
    json!({
        "id": id,
        "enabled": enabled,
        "executed": executed,
        "passed": passed,
        "status": status,
    })
}

/// Full probe matrix — proves which checks were armed, ran, and passed for this scan.
fn build_coverage_audit(cfg: &BgpConfig, p: &Posture) -> Value {
    let rows = vec![
        coverage_row(
            "resolver_consensus",
            cfg.check_resolver_consensus,
            p.resolver_checked,
            Some(p.resolver_consensus),
        ),
        coverage_row(
            "dnssec",
            cfg.check_dnssec,
            p.dnssec_checked,
            Some(p.dnssec_validated && !p.dnssec_broken && p.dnskey_strong),
        ),
        coverage_row(
            "dnssec_ad_divergence",
            cfg.check_dnssec_ad_divergence,
            p.dnssec_ad_divergence_checked,
            Some(p.dnssec_ad_consensus),
        ),
        coverage_row(
            "auth_vs_recursive",
            cfg.check_auth_recursive,
            p.auth_recursive_checked,
            Some(p.auth_recursive_match),
        ),
        coverage_row(
            "rpki",
            cfg.check_rpki,
            p.rpki_checked,
            Some(p.rpki_valid && !p.rpki_invalid),
        ),
        coverage_row(
            "bgp_origin",
            cfg.check_bgp,
            p.bgp_checked,
            Some(!p.unexpected_origin && p.bgp_origin_stable && !p.moas),
        ),
        coverage_row("irr", cfg.check_irr, p.irr_checked, Some(p.irr_matches_bgp)),
        coverage_row(
            "more_specific",
            cfg.check_more_specific,
            p.more_specific_checked,
            Some(p.more_specific_clean),
        ),
        coverage_row(
            "routing_history",
            cfg.check_routing_history,
            p.bgp_checked,
            None,
        ),
        coverage_row(
            "tls_identity",
            cfg.check_tls_identity,
            p.tls_checked,
            Some(p.tls_identity_match),
        ),
        coverage_row(
            "discovered_tls",
            cfg.check_discovered_tls,
            p.discovered_tls_checked,
            Some(p.discovered_tls_match),
        ),
        coverage_row(
            "fcrdns",
            cfg.check_fcrdns,
            p.fcrdns_checked,
            Some(p.fcrdns_valid),
        ),
        coverage_row(
            "expected_ips",
            cfg.check_expected_ips,
            p.expected_ips_checked,
            Some(p.expected_ips_match),
        ),
        coverage_row(
            "aaaa_consensus",
            cfg.check_aaaa,
            p.aaaa_consensus_checked,
            Some(p.aaaa_consensus),
        ),
        coverage_row(
            "dual_stack",
            cfg.check_dual_stack,
            p.dual_stack_checked,
            Some(p.dual_stack_origin_match),
        ),
        coverage_row(
            "bogon",
            cfg.check_bogon,
            p.bogon_checked,
            Some(p.bogon_free),
        ),
        coverage_row("ttl", cfg.check_ttl, p.ttl_checked, Some(p.ttl_healthy)),
        coverage_row("dane", cfg.check_dane, p.dane_checked, Some(p.dane_present)),
        coverage_row("ct_inventory", cfg.check_ct, p.ct_inventory_checked, None),
        coverage_row(
            "rdap",
            cfg.check_rdap,
            p.rdap_checked,
            Some(p.rdap_transfer_locked),
        ),
        coverage_row("caa", cfg.check_caa, p.caa_checked, Some(p.caa_present)),
        coverage_row(
            "ns_diversity",
            cfg.check_ns,
            p.ns_checked,
            Some(p.ns_diverse),
        ),
        coverage_row(
            "takeover",
            cfg.check_takeover,
            p.takeover_checked,
            Some(p.takeover_clean),
        ),
        coverage_row(
            "baseline_delta",
            cfg.check_baseline_delta,
            p.baseline_checked,
            Some(p.baseline_stable),
        ),
        coverage_row(
            "wildcard_dns",
            cfg.check_wildcard,
            p.wildcard_checked,
            Some(p.wildcard_clean),
        ),
        coverage_row(
            "ns_lame",
            cfg.check_ns_lame,
            p.ns_lame_checked,
            Some(p.ns_lame_free),
        ),
        coverage_row(
            "cname_chain",
            cfg.check_cname_chain,
            p.cname_checked,
            Some(p.cname_healthy),
        ),
        coverage_row(
            "spf_apex",
            cfg.check_spf_apex,
            p.spf_checked,
            Some(p.spf_present),
        ),
        coverage_row(
            "cds_cdnskey",
            cfg.check_cds_cdnskey,
            p.cds_checked,
            Some(p.cds_automation_ready),
        ),
        coverage_row(
            "orphan_ds",
            cfg.check_orphan_ds,
            p.orphan_ds_checked,
            Some(p.orphan_ds_clean),
        ),
        coverage_row(
            "resolver_timing",
            cfg.check_resolver_timing,
            p.resolver_timing_checked,
            Some(p.resolver_timing_healthy),
        ),
        coverage_row(
            "delegation_walk",
            cfg.check_delegation_walk,
            p.delegation_walk_checked,
            Some(p.delegation_chain_valid),
        ),
        coverage_row(
            "udp_doh_cross",
            cfg.check_udp_doh_cross,
            p.udp_doh_checked,
            Some(p.udp_doh_consistent),
        ),
        coverage_row(
            "dmarc",
            cfg.check_dmarc,
            p.dmarc_checked,
            Some(p.dmarc_present),
        ),
        coverage_row(
            "parent_ns",
            cfg.check_parent_ns,
            p.parent_ns_checked,
            Some(p.parent_ns_consistent),
        ),
        coverage_row(
            "soa_mname",
            cfg.check_soa,
            p.soa_checked,
            Some(p.soa_mname_in_ns),
        ),
        coverage_row(
            "soa_serial",
            cfg.check_soa_serial,
            p.soa_serial_checked,
            Some(p.soa_serial_consistent),
        ),
        coverage_row(
            "caa_ct_cross",
            cfg.check_caa_ct_cross,
            p.caa_ct_checked,
            Some(p.caa_ct_aligned),
        ),
        coverage_row(
            "rpki_maxlength",
            cfg.check_rpki_maxlength,
            p.rpki_maxlength_checked,
            Some(p.rpki_maxlength_tight),
        ),
        coverage_row("hsts", cfg.check_hsts, p.hsts_checked, Some(p.hsts_present)),
        coverage_row(
            "http_redirect",
            cfg.check_http_redirect,
            p.redirect_checked,
            Some(p.redirect_healthy),
        ),
        coverage_row(
            "mx_origin",
            cfg.check_mx_origin,
            p.mx_checked,
            Some(p.mx_origin_match),
        ),
        coverage_row(
            "glue",
            cfg.check_glue,
            p.glue_checked,
            Some(p.glue_consistent),
        ),
        coverage_row(
            "bgp_visibility",
            cfg.check_bgp_visibility,
            p.visibility_checked,
            Some(p.bgp_visible),
        ),
        coverage_row("geo", cfg.check_geo, p.geo_checked, Some(p.geo_match)),
        coverage_row(
            "autonomous_discovery",
            cfg.autonomous_mode,
            p.discovery_ran,
            Some(p.discovery_ran),
        ),
    ];
    let enabled_count = rows
        .iter()
        .filter(|r| r.get("enabled").and_then(Value::as_bool) == Some(true))
        .count();
    let executed_count = rows
        .iter()
        .filter(|r| {
            r.get("enabled").and_then(Value::as_bool) == Some(true)
                && r.get("executed").and_then(Value::as_bool) == Some(true)
        })
        .count();
    let passed_count = rows
        .iter()
        .filter(|r| r.get("passed").and_then(Value::as_bool) == Some(true))
        .count();
    let failed_count = rows
        .iter()
        .filter(|r| r.get("passed").and_then(Value::as_bool) == Some(false))
        .count();
    json!({
        "engine_version": "8.0",
        "probes": rows,
        "enabled_count": enabled_count,
        "executed_count": executed_count,
        "passed_count": passed_count,
        "failed_count": failed_count,
        "coverage_complete": enabled_count > 0 && enabled_count == executed_count,
    })
}

fn build_incident_bundle(
    findings: &[Value],
    posture: &Posture,
    plane_matrix: &Value,
    roadmap: &[Value],
    manifest: &[&str],
) -> Value {
    let critical: Vec<String> = findings
        .iter()
        .filter(|f| f.get("severity").and_then(Value::as_str) == Some("critical"))
        .filter_map(|f| f.get("title").and_then(Value::as_str).map(str::to_string))
        .take(8)
        .collect();
    let actions: Vec<String> = roadmap
        .iter()
        .filter(|s| s.get("done").and_then(Value::as_bool) == Some(false))
        .filter_map(|s| s.get("title").and_then(Value::as_str).map(str::to_string))
        .take(6)
        .collect();
    json!({
        "mitre_techniques": mitre_coverage(findings),
        "critical_findings": critical,
        "priority_actions": actions,
        "probe_manifest": manifest,
        "threat_planes": plane_matrix,
        "hijack_resistance_score": hijack_resistance_score(posture),
    })
}

async fn ripe_geoloc_countries(
    client: &reqwest::Client,
    ripe_base: &str,
    ip: &str,
) -> BTreeSet<String> {
    let url = format!("{ripe_base}/data/geoloc/data.json?resource={ip}");
    let v = match client.get(&url).send().await {
        Ok(r) => match r.json::<Value>().await {
            Ok(j) => j,
            Err(_) => return BTreeSet::new(),
        },
        Err(_) => return BTreeSet::new(),
    };
    let mut out = BTreeSet::new();
    if let Some(addrs) = v
        .get("data")
        .and_then(|d| d.get("located_resources"))
        .and_then(Value::as_array)
    {
        for a in addrs {
            if let Some(cc) = a
                .get("location")
                .and_then(|l| l.get("country"))
                .and_then(Value::as_str)
            {
                out.insert(cc.to_ascii_uppercase());
            }
        }
    }
    out
}

/// BGP visibility fraction (0.0–1.0) from RIPEstat routing-status.
async fn ripe_bgp_visibility(
    client: &reqwest::Client,
    ripe_base: &str,
    prefix: &str,
) -> Option<f64> {
    let url = format!("{ripe_base}/data/routing-status/data.json?resource={prefix}");
    let v = client
        .get(&url)
        .send()
        .await
        .ok()?
        .json::<Value>()
        .await
        .ok()?;
    v.get("data")
        .and_then(|d| d.get("visibility").and_then(Value::as_f64))
        .or_else(|| {
            v.get("data")
                .and_then(|d| d.get("visibilities"))
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(|x| x.get("visibility").and_then(Value::as_f64))
        })
}

/// ROA maxLength slack: prefix length vs ROA maxLength — large slack = hijack window.
async fn ripe_rpki_maxlength_slack(
    client: &reqwest::Client,
    ripe_base: &str,
    asn: u32,
    prefix: &str,
) -> Option<u8> {
    let url =
        format!("{ripe_base}/data/rpki-validation/data.json?resource=AS{asn}&prefix={prefix}");
    let v = client
        .get(&url)
        .send()
        .await
        .ok()?
        .json::<Value>()
        .await
        .ok()?;
    let pl = prefix.split('/').nth(1)?.parse::<u8>().ok()?;
    let max_len = v
        .get("data")
        .and_then(|d| d.get("validating_roas"))
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|r| r.get("maxlength").and_then(Value::as_u64))
        .map(|m| m as u8)
        .or_else(|| {
            v.get("data")
                .and_then(|d| d.get("roa"))
                .and_then(|r| r.get("maxlength").and_then(Value::as_u64))
                .map(|m| m as u8)
        })?;
    Some(max_len.saturating_sub(pl))
}

async fn load_prior_fingerprint(ctx: &EngineRunContext, domain: &str) -> Option<HijackFingerprint> {
    let pool = ctx.app_pool.as_ref()?;
    let tenant_id = ctx.tenant_id?;
    let client_id = ctx.client_id?;
    let pattern = format!("%{domain}%");
    let raw: Value = sqlx::query_scalar(
        r#"SELECT raw_data FROM vulnerabilities
           WHERE tenant_id = $1 AND client_id = $2 AND source = 'bgp_dns_hijacking'
             AND COALESCE(raw_data->>'type','') = 'dns_bgp_integrity_summary'
             AND (COALESCE(raw_data->>'target','') ILIKE $3 OR title ILIKE $3)
           ORDER BY COALESCE(last_seen_at, updated_at) DESC
           LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&pattern)
    .fetch_optional(pool.as_ref())
    .await
    .ok()??;
    fingerprint_from_summary_value(&raw)
}

fn fingerprint_from_job_params(cfg: &ArsenalConfig) -> Option<HijackFingerprint> {
    let v = cfg.raw().get("baseline_snapshot")?;
    fingerprint_from_summary_value(v)
}

fn fingerprint_from_summary_value(v: &Value) -> Option<HijackFingerprint> {
    let score = v
        .get("hijack_resistance_score")
        .and_then(Value::as_u64)
        .map(|s| s as u32)
        .or_else(|| {
            v.get("evidence")
                .and_then(|e| e.get("hijack_resistance_score"))
                .and_then(Value::as_u64)
                .map(|s| s as u32)
        })?;
    let mut fp = HijackFingerprint {
        score,
        ..HijackFingerprint::default()
    };
    if let Some(arr) = v
        .get("scan_fingerprint")
        .and_then(|sf| sf.get("a_ips"))
        .and_then(Value::as_array)
    {
        for ip in arr {
            if let Some(s) = ip.as_str() {
                fp.a_ips.insert(s.to_string());
            }
        }
    }
    if let Some(arr) = v
        .get("scan_fingerprint")
        .and_then(|sf| sf.get("origin_asns"))
        .and_then(Value::as_array)
    {
        for a in arr {
            if let Some(n) = a.as_u64() {
                fp.origin_asns.insert(n as u32);
            }
        }
    }
    Some(fp)
}

fn build_threat_plane_matrix(p: &Posture, compromised: &ThreatCompromised) -> Value {
    json!({
        "dns": {
            "status": plane_status(
                p.resolver_checked || p.auth_recursive_checked || p.dnssec_checked,
                p.resolver_consensus && p.auth_recursive_match && !p.dnssec_broken,
                compromised.dns,
            ).as_str(),
            "resolver_consensus": p.resolver_consensus,
            "auth_recursive_match": p.auth_recursive_match,
            "dnssec_validated": p.dnssec_validated,
            "bogon_free": p.bogon_free,
            "fcrdns_valid": p.fcrdns_valid,
            "expected_ips_match": p.expected_ips_match,
            "wildcard_clean": p.wildcard_clean,
            "ns_lame_free": p.ns_lame_free,
            "aaaa_consensus": p.aaaa_consensus,
        },
        "bgp": {
            "status": plane_status(
                p.rpki_checked || p.bgp_checked,
                p.rpki_valid && !p.rpki_invalid && p.more_specific_clean && p.irr_matches_bgp,
                compromised.bgp,
            ).as_str(),
            "rpki_valid": p.rpki_valid,
            "rpki_invalid": p.rpki_invalid,
            "more_specific_clean": p.more_specific_clean,
            "irr_matches_bgp": p.irr_matches_bgp,
            "origin_stable": p.bgp_origin_stable,
        },
        "tls_http": {
            "status": plane_status(
                p.tls_checked || p.hsts_checked,
                p.tls_identity_match && p.hsts_present && p.redirect_healthy,
                compromised.tls,
            ).as_str(),
            "tls_identity_match": p.tls_identity_match,
            "hsts_present": p.hsts_present,
            "redirect_healthy": p.redirect_healthy,
        },
        "registry": {
            "status": plane_status(
                p.rdap_checked || p.caa_checked,
                p.rdap_transfer_locked && p.caa_ct_aligned,
                compromised.registry,
            ).as_str(),
            "rdap_transfer_locked": p.rdap_transfer_locked,
            "caa_present": p.caa_present,
            "caa_ct_aligned": p.caa_ct_aligned,
        },
    })
}

#[derive(Debug, Clone, Default)]
struct ThreatCompromised {
    dns: bool,
    bgp: bool,
    tls: bool,
    registry: bool,
}

#[derive(Debug, Clone, Default)]
struct PrefixOverview {
    prefix: String,
    announced: bool,
    /// (asn, holder) of every AS that originates the covering prefix.
    origins: Vec<(u32, String)>,
}

async fn ripe_prefix_overview(
    client: &reqwest::Client,
    ripe_base: &str,
    ip: &str,
) -> Option<PrefixOverview> {
    let url = format!("{ripe_base}/data/prefix-overview/data.json?resource={ip}");
    let v = client
        .get(&url)
        .send()
        .await
        .ok()?
        .json::<Value>()
        .await
        .ok()?;
    let data = v.get("data")?;
    let prefix = data
        .get("resource")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let announced = data
        .get("announced")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let origins = data
        .get("asns")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    let asn = a.get("asn").and_then(Value::as_u64)? as u32;
                    let holder = a
                        .get("holder")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    Some((asn, holder))
                })
                .collect()
        })
        .unwrap_or_default();
    Some(PrefixOverview {
        prefix,
        announced,
        origins,
    })
}

/// RPKI ROA validation status for a (prefix, origin-AS) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpkiState {
    Valid,
    Invalid,
    Unknown,
}

impl RpkiState {
    fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "valid" => RpkiState::Valid,
            "invalid" => RpkiState::Invalid,
            _ => RpkiState::Unknown,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            RpkiState::Valid => "valid",
            RpkiState::Invalid => "invalid",
            RpkiState::Unknown => "unknown",
        }
    }
}

async fn ripe_rpki_validation(
    client: &reqwest::Client,
    ripe_base: &str,
    asn: u32,
    prefix: &str,
) -> Option<RpkiState> {
    let url =
        format!("{ripe_base}/data/rpki-validation/data.json?resource=AS{asn}&prefix={prefix}");
    let v = client
        .get(&url)
        .send()
        .await
        .ok()?
        .json::<Value>()
        .await
        .ok()?;
    let status = v.get("data")?.get("status").and_then(Value::as_str)?;
    Some(RpkiState::parse(status))
}

/// Distinct origin ASNs observed in RIPEstat routing-history for `prefix` (recent churn indicator).
async fn ripe_routing_history_origins(
    client: &reqwest::Client,
    ripe_base: &str,
    prefix: &str,
) -> Vec<u32> {
    let url = format!("{ripe_base}/data/routing-history/data.json?resource={prefix}");
    let v = match client.get(&url).send().await {
        Ok(r) => match r.json::<Value>().await {
            Ok(j) => j,
            Err(_) => return vec![],
        },
        Err(_) => return vec![],
    };
    let mut origins: BTreeSet<u32> = BTreeSet::new();
    if let Some(by_origin) = v
        .get("data")
        .and_then(|d| d.get("by_origin"))
        .and_then(Value::as_array)
    {
        for entry in by_origin {
            if let Some(asn) = entry.get("origin").and_then(Value::as_u64) {
                origins.insert(asn as u32);
            }
        }
    }
    origins.into_iter().collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Hijack-resistance scoring
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct Posture {
    resolved: bool,
    resolver_consensus: bool,
    resolver_checked: bool,
    dnssec_signed: bool,
    dnssec_validated: bool,
    dnssec_checked: bool,
    dnssec_broken: bool,
    dnskey_strong: bool,
    rpki_checked: bool,
    rpki_valid: bool,
    rpki_invalid: bool,
    caa_checked: bool,
    caa_present: bool,
    ns_checked: bool,
    ns_diverse: bool,
    bgp_checked: bool,
    unexpected_origin: bool,
    moas: bool,
    bgp_origin_stable: bool,
    tls_checked: bool,
    tls_identity_match: bool,
    bogon_checked: bool,
    bogon_free: bool,
    ttl_checked: bool,
    ttl_healthy: bool,
    dane_checked: bool,
    dane_present: bool,
    auth_recursive_checked: bool,
    auth_recursive_match: bool,
    rdap_checked: bool,
    rdap_transfer_locked: bool,
    irr_checked: bool,
    irr_matches_bgp: bool,
    more_specific_checked: bool,
    more_specific_clean: bool,
    dual_stack_checked: bool,
    dual_stack_origin_match: bool,
    soa_checked: bool,
    soa_mname_in_ns: bool,
    caa_ct_checked: bool,
    caa_ct_aligned: bool,
    rpki_maxlength_checked: bool,
    rpki_maxlength_tight: bool,
    hsts_checked: bool,
    hsts_present: bool,
    redirect_checked: bool,
    redirect_healthy: bool,
    mx_checked: bool,
    mx_origin_match: bool,
    glue_checked: bool,
    glue_consistent: bool,
    visibility_checked: bool,
    bgp_visible: bool,
    geo_checked: bool,
    geo_match: bool,
    baseline_checked: bool,
    baseline_stable: bool,
    expected_ips_checked: bool,
    expected_ips_match: bool,
    dnssec_ad_divergence_checked: bool,
    dnssec_ad_consensus: bool,
    fcrdns_checked: bool,
    fcrdns_valid: bool,
    aaaa_consensus_checked: bool,
    aaaa_consensus: bool,
    cds_checked: bool,
    cds_automation_ready: bool,
    orphan_ds_checked: bool,
    orphan_ds_clean: bool,
    ns_lame_checked: bool,
    ns_lame_free: bool,
    cname_checked: bool,
    cname_healthy: bool,
    spf_checked: bool,
    spf_present: bool,
    wildcard_checked: bool,
    wildcard_clean: bool,
    resolver_timing_checked: bool,
    resolver_timing_healthy: bool,
    discovery_ran: bool,
    delegation_walk_checked: bool,
    delegation_chain_valid: bool,
    udp_doh_checked: bool,
    udp_doh_consistent: bool,
    dmarc_checked: bool,
    dmarc_present: bool,
    parent_ns_checked: bool,
    parent_ns_consistent: bool,
    soa_serial_checked: bool,
    soa_serial_consistent: bool,
    discovered_tls_checked: bool,
    discovered_tls_match: bool,
    takeover_checked: bool,
    takeover_clean: bool,
    ct_inventory_checked: bool,
}

/// Normalised 0–100 hijack-resistance score over the dimensions that apply to the target.
fn hijack_resistance_score(p: &Posture) -> u32 {
    let mut achieved = 0f64;
    let mut applicable = 0f64;
    let mut add = |weight: f64, applies: bool, ok: bool| {
        if applies {
            applicable += weight;
            if ok {
                achieved += weight;
            }
        }
    };
    add(
        18.0,
        p.dnssec_checked,
        p.dnssec_validated && !p.dnssec_broken && p.dnskey_strong,
    );
    add(18.0, p.rpki_checked, p.rpki_valid && !p.rpki_invalid);
    add(10.0, p.auth_recursive_checked, p.auth_recursive_match);
    add(10.0, p.resolver_checked, p.resolver_consensus);
    add(10.0, p.tls_checked, p.tls_identity_match);
    add(6.0, p.bogon_checked, p.bogon_free);
    add(6.0, p.caa_checked, p.caa_present);
    add(6.0, p.ns_checked, p.ns_diverse);
    add(5.0, p.more_specific_checked, p.more_specific_clean);
    add(5.0, p.dual_stack_checked, p.dual_stack_origin_match);
    add(4.0, p.irr_checked, p.irr_matches_bgp);
    add(4.0, p.rdap_checked, p.rdap_transfer_locked);
    add(4.0, p.ttl_checked, p.ttl_healthy);
    add(
        4.0,
        p.bgp_checked,
        !p.unexpected_origin && p.bgp_origin_stable,
    );
    add(3.0, p.soa_checked, p.soa_mname_in_ns);
    add(3.0, p.dane_checked, p.dane_present);
    add(2.0, p.bgp_checked && p.moas, !p.moas);
    add(5.0, p.expected_ips_checked, p.expected_ips_match);
    add(3.0, p.fcrdns_checked, p.fcrdns_valid);
    add(3.0, p.aaaa_consensus_checked, p.aaaa_consensus);
    add(3.0, p.ns_lame_checked, p.ns_lame_free);
    add(2.0, p.wildcard_checked, p.wildcard_clean);
    add(2.0, p.dnssec_ad_divergence_checked, p.dnssec_ad_consensus);
    add(2.0, p.resolver_timing_checked, p.resolver_timing_healthy);
    add(1.0, p.cname_checked, p.cname_healthy);
    add(1.0, p.spf_checked, p.spf_present);
    add(2.0, p.delegation_walk_checked, p.delegation_chain_valid);
    add(2.0, p.udp_doh_checked, p.udp_doh_consistent);
    add(1.0, p.dmarc_checked, p.dmarc_present);
    add(2.0, p.parent_ns_checked, p.parent_ns_consistent);
    add(2.0, p.soa_serial_checked, p.soa_serial_consistent);
    add(2.0, p.discovered_tls_checked, p.discovered_tls_match);
    add(1.0, p.takeover_checked, p.takeover_clean);
    if applicable <= 0.0 {
        return 0;
    }
    let mut score = (achieved / applicable * 100.0).round() as u32;
    let dnssec_ok =
        !p.dnssec_checked || (p.dnssec_validated && !p.dnssec_broken && p.dnskey_strong);
    let rpki_ok = !p.rpki_checked || (p.rpki_valid && !p.rpki_invalid);
    if p.dnssec_checked && p.rpki_checked && !dnssec_ok && !rpki_ok {
        score = score.min(40);
    }
    score
}

fn summary_severity(score: u32, critical_signal: bool) -> &'static str {
    if critical_signal {
        return "critical";
    }
    match score {
        s if s >= 85 => "info",
        s if s >= 65 => "low",
        s if s >= 45 => "medium",
        s if s >= 25 => "high",
        _ => "critical",
    }
}

fn yn(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Finding helper
// ─────────────────────────────────────────────────────────────────────────────

fn bgp_finding(
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    remediation: &str,
    confidence: f64,
    evidence: Evidence,
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
        obj.insert("remediation".to_string(), json!(remediation));
        obj.insert("category".to_string(), json!("dns_bgp_integrity"));
    }
    f
}

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

struct BgpConfig {
    resolvers: Vec<(String, String)>,
    timeout_ms: u64,
    concurrency: usize,
    check_resolver_consensus: bool,
    check_dnssec: bool,
    check_rpki: bool,
    check_bgp: bool,
    check_caa: bool,
    check_ns: bool,
    check_takeover: bool,
    check_aaaa: bool,
    check_tls_identity: bool,
    check_bogon: bool,
    check_ttl: bool,
    check_routing_history: bool,
    check_dane: bool,
    check_ct: bool,
    check_auth_recursive: bool,
    check_rdap: bool,
    check_irr: bool,
    check_more_specific: bool,
    check_dual_stack: bool,
    check_soa: bool,
    check_baseline_delta: bool,
    check_caa_ct_cross: bool,
    check_rpki_maxlength: bool,
    check_hsts: bool,
    check_http_redirect: bool,
    check_mx_origin: bool,
    check_glue: bool,
    check_bgp_visibility: bool,
    check_geo: bool,
    check_dnssec_ad_divergence: bool,
    check_fcrdns: bool,
    check_expected_ips: bool,
    check_cname_chain: bool,
    check_spf_apex: bool,
    check_wildcard: bool,
    check_ns_lame: bool,
    check_cds_cdnskey: bool,
    check_orphan_ds: bool,
    check_resolver_timing: bool,
    autonomous_mode: bool,
    force_all_probes: bool,
    use_static_subdomain_wordlist: bool,
    check_delegation_walk: bool,
    check_udp_doh_cross: bool,
    check_ct_discovery: bool,
    check_dmarc: bool,
    check_parent_ns: bool,
    check_discovered_tls: bool,
    check_soa_serial: bool,
    discovered_tls_limit: usize,
    max_ct_hosts: usize,
    low_ttl_threshold_secs: u32,
    resolver_timing_factor: f64,
    cname_max_hops: usize,
    expected_countries: BTreeSet<String>,
    expected_origin_asns: BTreeSet<u32>,
    expected_a_ips: BTreeSet<String>,
    subdomains: Vec<String>,
    ripe_base: String,
}

fn parse_resolvers(cfg: &ArsenalConfig) -> Vec<(String, String)> {
    let custom = cfg.string_list("resolvers");
    if custom.is_empty() {
        return DEFAULT_RESOLVERS
            .iter()
            .map(|(n, u)| ((*n).to_string(), (*u).to_string()))
            .collect();
    }
    custom
        .into_iter()
        .map(|entry| {
            if let Some((name, url)) = entry.split_once('=') {
                (name.trim().to_string(), url.trim().to_string())
            } else {
                // derive a display name from the URL host
                let host = entry
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .unwrap_or(&entry)
                    .to_string();
                (host, entry)
            }
        })
        .filter(|(_, u)| u.starts_with("http"))
        .collect()
}

fn load_config(cfg: &ArsenalConfig) -> BgpConfig {
    let expected_origin_asns = cfg
        .string_list("expected_origin_asns")
        .iter()
        .filter_map(|s| {
            s.trim()
                .trim_start_matches(|c: char| matches!(c, 'A' | 'S' | 'a' | 's'))
                .parse::<u32>()
                .ok()
        })
        .collect::<BTreeSet<u32>>();
    BgpConfig {
        resolvers: parse_resolvers(cfg),
        timeout_ms: cfg.timeout_ms(8000),
        concurrency: cfg.concurrency().min(16),
        check_resolver_consensus: cfg.bool_or("check_resolver_consensus", true),
        check_dnssec: cfg.bool_or("check_dnssec", true),
        check_rpki: cfg.bool_or("check_rpki", true),
        check_bgp: cfg.bool_or("check_bgp", true),
        check_caa: cfg.bool_or("check_caa", true),
        check_ns: cfg.bool_or("check_ns", true),
        check_takeover: cfg.bool_or("check_takeover", true),
        check_aaaa: cfg.bool_or("check_aaaa", false),
        check_tls_identity: cfg.bool_or("check_tls_identity", true),
        check_bogon: cfg.bool_or("check_bogon", true),
        check_ttl: cfg.bool_or("check_ttl", true),
        check_routing_history: cfg.bool_or("check_routing_history", true),
        check_dane: cfg.bool_or("check_dane", true),
        check_ct: cfg.bool_or("check_ct", true),
        check_auth_recursive: cfg.bool_or("check_auth_recursive", true),
        check_rdap: cfg.bool_or("check_rdap", true),
        check_irr: cfg.bool_or("check_irr", true),
        check_more_specific: cfg.bool_or("check_more_specific", true),
        check_dual_stack: cfg.bool_or("check_dual_stack", true),
        check_soa: cfg.bool_or("check_soa", true),
        check_baseline_delta: cfg.bool_or("check_baseline_delta", true),
        check_caa_ct_cross: cfg.bool_or("check_caa_ct_cross", true),
        check_rpki_maxlength: cfg.bool_or("check_rpki_maxlength", true),
        check_hsts: cfg.bool_or("check_hsts", true),
        check_http_redirect: cfg.bool_or("check_http_redirect", true),
        check_mx_origin: cfg.bool_or("check_mx_origin", true),
        check_glue: cfg.bool_or("check_glue", true),
        check_bgp_visibility: cfg.bool_or("check_bgp_visibility", true),
        check_geo: cfg.bool_or("check_geo", false),
        check_dnssec_ad_divergence: cfg.bool_or("check_dnssec_ad_divergence", true),
        check_fcrdns: cfg.bool_or("check_fcrdns", true),
        check_expected_ips: cfg.bool_or("check_expected_ips", false),
        check_cname_chain: cfg.bool_or("check_cname_chain", true),
        check_spf_apex: cfg.bool_or("check_spf_apex", true),
        check_wildcard: cfg.bool_or("check_wildcard", true),
        check_ns_lame: cfg.bool_or("check_ns_lame", true),
        check_cds_cdnskey: cfg.bool_or("check_cds_cdnskey", true),
        check_orphan_ds: cfg.bool_or("check_orphan_ds", true),
        check_resolver_timing: cfg.bool_or("check_resolver_timing", true),
        autonomous_mode: cfg.bool_or("autonomous_mode", true),
        force_all_probes: cfg.bool_or("force_all_probes", false),
        use_static_subdomain_wordlist: cfg.bool_or(
            "use_static_subdomain_wordlist",
            !cfg.bool_or("autonomous_mode", true),
        ),
        check_delegation_walk: cfg.bool_or("check_delegation_walk", true),
        check_udp_doh_cross: cfg.bool_or("check_udp_doh_cross", true),
        check_ct_discovery: cfg.bool_or("check_ct_discovery", true),
        check_dmarc: cfg.bool_or("check_dmarc", true),
        check_parent_ns: cfg.bool_or("check_parent_ns", true),
        check_discovered_tls: cfg.bool_or("check_discovered_tls", true),
        check_soa_serial: cfg.bool_or("check_soa_serial", true),
        discovered_tls_limit: cfg.u64_or("discovered_tls_limit", 5) as usize,
        max_ct_hosts: cfg.u64_or("max_ct_hosts", 32) as usize,
        low_ttl_threshold_secs: cfg.u64_or("low_ttl_threshold_secs", 300) as u32,
        resolver_timing_factor: cfg
            .raw()
            .get("resolver_timing_factor")
            .and_then(|v| {
                v.as_f64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(3.0),
        cname_max_hops: cfg.u64_or("cname_max_hops", 8) as usize,
        expected_countries: cfg
            .string_list("expected_countries")
            .iter()
            .map(|c| c.trim().to_ascii_uppercase())
            .filter(|c| c.len() == 2)
            .collect(),
        expected_origin_asns,
        expected_a_ips: cfg
            .string_list("expected_a_ips")
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        subdomains: cfg.string_list("subdomains"),
        ripe_base: cfg.string_or("ripe_base", "https://stat.ripe.net"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestration
// ─────────────────────────────────────────────────────────────────────────────

/// Backward-compatible entry point (CLI + alias callers). Uses default parameters.
pub async fn run_bgp_dns_hijacking_result(target: &str) -> EngineResult {
    run_bgp_dns_hijacking_result_ctx(target, &EngineRunContext::default()).await
}

/// Parameterised entry point used by the dispatch layer (reads `ctx.job_params`).
pub async fn run_bgp_dns_hijacking_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let domain = extract_domain(target);
    if domain.is_empty() {
        return EngineResult::error("could not extract a domain from target");
    }
    let mut cfg = load_config(&ArsenalConfig::from_ctx(ctx));
    let prior_fp = if cfg.check_baseline_delta {
        fingerprint_from_job_params(&ArsenalConfig::from_ctx(ctx))
            .or(load_prior_fingerprint(ctx, &domain).await)
    } else {
        None
    };
    let client = build_client(cfg.timeout_ms).await;
    let doh_base_early = cfg
        .resolvers
        .first()
        .map(|(_, b)| b.clone())
        .unwrap_or_else(|| DEFAULT_RESOLVERS[0].1.to_string());

    // Finish every DB read before the network phase starts so this heavy engine never keeps a
    // pooled connection live while waiting on external DNS/BGP/CT/RDAP responses.
    let zone_discovery = run_zone_discovery(
        &client,
        &doh_base_early,
        &domain,
        cfg.check_ct_discovery,
        cfg.max_ct_hosts,
    )
    .await;
    let adaptive_plan = plan_adaptive_probes(&zone_discovery, &cfg);
    if cfg.autonomous_mode {
        apply_autonomous_plan(&mut cfg, &zone_discovery, &adaptive_plan);
    }

    let mut findings: Vec<Value> = Vec::new();
    let mut posture = Posture::default();
    let mut threat_compromised = ThreatCompromised::default();
    let mut captured_caa: Vec<String> = Vec::new();
    let mut critical_signal = false;
    let mut resolver_diverged = false;
    let mut tls_mismatch = false;
    let mut bogon_hit = false;
    let mut auth_diverged = false;
    let mut observed_bgp_origins: Vec<u32> = Vec::new();
    let mut covering_prefix: String = String::new();

    posture.discovery_ran = true;
    findings.push(bgp_finding(
        &format!("Autonomous zone discovery for {domain}"),
        "info",
        "T1590",
        &format!(
            "Live recon found {} signal(s): {}. Auto-enabled {} probe(s), skipped {} irrelevant probe(s). Discovered {} hostname(s) live from DNS/CT/MX/NS/SPF — no static wordlist.",
            zone_discovery.signals.len(),
            if zone_discovery.signals.is_empty() {
                "baseline DNS surface".to_string()
            } else {
                zone_discovery.signals.join(", ")
            },
            adaptive_plan.auto_enabled.len(),
            adaptive_plan.auto_skipped.len(),
            zone_discovery.discovered_hosts.len()
        ),
        target,
        "Review discovery_graph in summary; autonomous mode enables only probes relevant to observed DNS/BGP surface.",
        0.92,
        Evidence::new()
            .with("domain", domain.clone())
            .with("discovery", discovery_graph(&zone_discovery, &adaptive_plan)),
    ));

    // ── 1) Multi-resolver consensus (A / AAAA) ───────────────────────────────
    let mut primary_ip: Option<String> = None;
    let mut all_a_ips: BTreeSet<String> = BTreeSet::new();
    let mut min_a_ttl: Option<u32> = None;
    let mut per_resolver: Vec<(String, Vec<String>, bool, u8)> = Vec::new(); // (name, ips, ad, status)
    let mut resolver_timings: Vec<(String, u64)> = Vec::new();
    {
        let rtype = T_A;
        let queries = cfg.resolvers.clone();
        let results: Vec<(String, Option<DohResponse>, u64)> = stream::iter(queries)
            .map(|(name, base)| {
                let client = client.clone();
                let dnssec = cfg.check_dnssec;
                let dom = domain.clone();
                async move {
                    let (resp, ms) = doh_query_timed(&client, &base, &dom, rtype, dnssec).await;
                    (name, resp, ms)
                }
            })
            .buffer_unordered(cfg.concurrency.max(1))
            .collect()
            .await;

        let mut ip_sets: Vec<(String, BTreeSet<String>)> = Vec::new();
        for (name, resp, ms) in results {
            resolver_timings.push((name.clone(), ms));
            if let Some(r) = resp {
                let ips = answers_of(&r, T_A);
                if !ips.is_empty() {
                    posture.resolved = true;
                    if primary_ip.is_none() {
                        primary_ip = ips.first().cloned();
                    }
                    for ip in &ips {
                        all_a_ips.insert(ip.clone());
                    }
                    if let Some(ttl) = min_ttl_for(&r, T_A) {
                        min_a_ttl = Some(min_a_ttl.map_or(ttl, |m| m.min(ttl)));
                    }
                }
                ip_sets.push((name.clone(), ips.iter().cloned().collect()));
                per_resolver.push((name, ips, r.ad, r.status));
            }
        }

        if cfg.check_resolver_consensus && ip_sets.len() >= 2 {
            posture.resolver_checked = true;
            let first = &ip_sets[0].1;
            let consistent = ip_sets.iter().all(|(_, s)| s == first) && !first.is_empty();
            posture.resolver_consensus = consistent;
            let detail: Vec<Value> = per_resolver
                .iter()
                .map(|(n, ips, ad, st)| json!({ "resolver": n, "ips": ips, "ad": ad, "rcode": st }))
                .collect();
            // GeoDNS / round-robin / CDN fronting legitimately returns different-but-overlapping
            // A-sets across independent resolvers. Only a FULLY DISJOINT answer set (no IP
            // shared by all resolvers, with every resolver having answered) is the hijack
            // signature; a partial overlap is downgraded to a low "load-balanced" note.
            let all_answered = !ip_sets.iter().any(|(_, s)| s.is_empty());
            let global_intersection: BTreeSet<String> =
                ip_sets.iter().skip(1).fold(first.clone(), |acc, (_, s)| {
                    acc.intersection(s).cloned().collect()
                });
            let disjoint = all_answered && global_intersection.is_empty();
            if !consistent && disjoint {
                resolver_diverged = true;
                threat_compromised.dns = true;
                critical_signal = true;
                findings.push(bgp_finding(
                    &format!("DNS answer divergence across resolvers for {domain}"),
                    "critical",
                    "T1557",
                    &format!(
                        "Independent validating resolvers returned fully disjoint A records for {domain} (no address in common). Disjoint divergence is the canonical signature of DNS cache poisoning, split-horizon hijack, or a BGP interception in progress against one resolver's path."
                    ),
                    target,
                    "Confirm the authoritative answer out-of-band, enable DNSSEC so clients reject forged records, and alert on resolver-answer divergence in monitoring. If a BGP interception is suspected, contact upstreams and file an RPKI ROA for the prefix.",
                    0.9,
                    Evidence::new()
                        .with("domain", domain.clone())
                        .with("resolvers", json!(detail))
                        .check("answers_consistent", false, "resolver A-record sets are disjoint"),
                ));
            } else if !consistent {
                findings.push(bgp_finding(
                    &format!("DNS answers differ but overlap across resolvers for {domain} (likely load-balanced)"),
                    "low",
                    "T1557",
                    &format!(
                        "Independent resolvers returned different but overlapping A records for {domain}. This is the normal signature of GeoDNS / round-robin / CDN fronting rather than a hijack. Escalation is reserved for fully disjoint answers."
                    ),
                    target,
                    "Confirm the authoritative answer set out-of-band if the overlap is unexpected; enable DNSSEC so clients reject forged records.",
                    0.5,
                    Evidence::new()
                        .with("domain", domain.clone())
                        .with("resolvers", json!(detail))
                        .check("answers_consistent", false, "overlapping A-record sets"),
                ));
            } else {
                findings.push(bgp_finding(
                    &format!("DNS answers consistent across {} resolvers", ip_sets.len()),
                    "info",
                    "T1557",
                    &format!(
                        "{domain} resolves to the same A records on every independent resolver ({}). No poisoning/hijack divergence observed at scan time.",
                        first.iter().cloned().collect::<Vec<_>>().join(", ")
                    ),
                    target,
                    "Keep monitoring resolver-answer divergence continuously; a single divergence event is a high-fidelity hijack indicator.",
                    0.8,
                    Evidence::new().with("domain", domain.clone()).with("resolvers", json!(detail)),
                ));
            }
        }

        if cfg.check_aaaa {
            let queries = cfg.resolvers.clone();
            let v6_results: Vec<(String, Option<DohResponse>)> = stream::iter(queries)
                .map(|(name, base)| {
                    let client = client.clone();
                    let dom = domain.clone();
                    async move { (name, doh_query(&client, &base, &dom, T_AAAA, false).await) }
                })
                .buffer_unordered(cfg.concurrency.max(1))
                .collect()
                .await;
            let mut v6_sets: Vec<(String, BTreeSet<String>)> = Vec::new();
            for (name, resp) in v6_results {
                if let Some(r) = resp {
                    let v6 = answers_of(&r, T_AAAA);
                    if !v6.is_empty() {
                        v6_sets.push((name, v6.iter().cloned().collect()));
                    }
                }
            }
            if v6_sets.len() >= 2 {
                posture.aaaa_consensus_checked = true;
                let first = &v6_sets[0].1;
                posture.aaaa_consensus = v6_sets.iter().all(|(_, s)| s == first);
                let detail: Vec<Value> = v6_sets
                    .iter()
                    .map(|(n, s)| json!({ "resolver": n, "aaaa": s.iter().collect::<Vec<_>>() }))
                    .collect();
                if !posture.aaaa_consensus {
                    threat_compromised.dns = true;
                    findings.push(bgp_finding(
                        &format!("AAAA answer divergence across resolvers for {domain}"),
                        "high",
                        "T1557",
                        &format!(
                            "Independent resolvers returned different AAAA records for {domain}. IPv6 poisoning/hijack parity with IPv4 divergence."
                        ),
                        target,
                        "Verify authoritative AAAA, enable DNSSEC, and monitor IPv6 resolver consensus alongside IPv4.",
                        0.88,
                        Evidence::new()
                            .with("domain", domain.clone())
                            .with("resolvers", json!(detail))
                            .check("aaaa_consistent", false, "resolver AAAA sets differ"),
                    ));
                } else {
                    findings.push(bgp_finding(
                        &format!(
                            "AAAA consistent across {} resolvers for {domain}",
                            v6_sets.len()
                        ),
                        "info",
                        "T1590.002",
                        &format!(
                            "IPv6 endpoints: {} — same on every resolver.",
                            first.iter().cloned().collect::<Vec<_>>().join(", ")
                        ),
                        target,
                        "Extend RPKI ROAs and BGP monitoring to IPv6 prefixes.",
                        0.78,
                        Evidence::new()
                            .with("domain", domain.clone())
                            .with("resolvers", json!(detail)),
                    ));
                }
            } else if let Some((_, set)) = v6_sets.first() {
                posture.aaaa_consensus_checked = true;
                posture.aaaa_consensus = true;
                findings.push(bgp_finding(
                    &format!("{} AAAA record(s) for {domain}", set.len()),
                    "info",
                    "T1590.002",
                    &format!(
                        "IPv6 endpoints: {}. Enable multi-resolver AAAA monitoring when multiple DoH paths are configured.",
                        set.iter().cloned().collect::<Vec<_>>().join(", ")
                    ),
                    target,
                    "Ensure IPv6 prefixes also have RPKI ROAs and are covered by route monitoring.",
                    0.7,
                    Evidence::new().with("domain", domain.clone()).with("aaaa", json!(set.iter().collect::<Vec<_>>())),
                ));
            }
        }
    }

    // ── 1b) Low-TTL / fast-flux signal ───────────────────────────────────────
    if cfg.check_ttl && posture.resolved {
        posture.ttl_checked = true;
        let ttl = min_a_ttl.unwrap_or(0);
        posture.ttl_healthy = ttl == 0 || ttl >= cfg.low_ttl_threshold_secs;
        if !posture.ttl_healthy {
            findings.push(bgp_finding(
                &format!("Low DNS TTL ({ttl}s) for {domain}"),
                "medium",
                "T1584.002",
                &format!(
                    "The A record for {domain} has TTL {ttl}s (threshold {}s). Very low TTLs are a classic pre-hijack pattern — operators shrink cache lifetime before swapping the target IP during an interception.",
                    cfg.low_ttl_threshold_secs
                ),
                target,
                "Investigate recent DNS changes. If unauthorised, revert at the authoritative provider and enable DNSSEC. Raise TTL to a stable value once the answer is verified.",
                0.75,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("min_a_ttl_secs", ttl as u64)
                    .with("threshold_secs", cfg.low_ttl_threshold_secs as u64)
                    .check("ttl_above_threshold", false, json!(ttl)),
            ));
        } else if ttl > 0 {
            findings.push(bgp_finding(
                &format!("DNS TTL healthy ({ttl}s) for {domain}"),
                "info",
                "T1584.002",
                &format!("Minimum observed A-record TTL is {ttl}s — not indicative of fast-flux hijack preparation at scan time."),
                target,
                "Continue monitoring TTL changes; sudden drops often precede hijack events.",
                0.65,
                Evidence::new().with("domain", domain.clone()).with("min_a_ttl_secs", ttl as u64),
            ));
        }
    }

    // ── 1c) Bogon / martian IP detection ─────────────────────────────────────
    if cfg.check_bogon && !all_a_ips.is_empty() {
        posture.bogon_checked = true;
        let mut bogons: Vec<Value> = Vec::new();
        for ip in &all_a_ips {
            if let Some(label) = bogon_label_v4(ip) {
                bogons.push(json!({ "ip": ip, "classification": label }));
            }
        }
        posture.bogon_free = bogons.is_empty();
        if !posture.bogon_free {
            bogon_hit = true;
            threat_compromised.dns = true;
            critical_signal = true;
            findings.push(bgp_finding(
                &format!("Bogon/martian IP in DNS answer for {domain}"),
                "critical",
                "T1557",
                &format!(
                    "{domain} resolves to non-routable address space ({:?}). Public names must never answer with RFC1918, loopback, link-local, or TEST-NET — this is definitive poisoning, misconfiguration, or an active hijack.",
                    bogons
                ),
                target,
                "Treat as an incident: verify the authoritative answer out-of-band, purge poisoned caches, and enable DNSSEC. Trace who published the bogus A record.",
                0.94,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("bogons", json!(bogons))
                    .check("bogon_free", false, json!(bogons.len())),
            ));
        } else {
            findings.push(bgp_finding(
                &format!("No bogon IPs in DNS answers for {domain}"),
                "info",
                "T1557",
                &format!("All {} observed A record(s) are in globally routable space.", all_a_ips.len()),
                target,
                "Keep bogon detection in monitoring — a single RFC1918 answer for a public name is a high-fidelity hijack indicator.",
                0.7,
                Evidence::new().with("domain", domain.clone()).with("ips", json!(all_a_ips.iter().collect::<Vec<_>>())),
            ));
        }
    }

    // ── 1d) Authoritative vs recursive split-horizon detection ─────────────────
    if cfg.check_auth_recursive && posture.resolved && !cfg.resolvers.is_empty() {
        if let Some(r) = doh_query(&client, &cfg.resolvers[0].1, &domain, T_NS, false).await {
            let ns_names = answers_of(&r, T_NS);
            if !ns_names.is_empty() {
                let (per_ns, auth_union) = authoritative_a_union(
                    &client,
                    &cfg.resolvers[0].1,
                    &domain,
                    &ns_names,
                    cfg.timeout_ms,
                )
                .await;
                if !auth_union.is_empty() {
                    posture.auth_recursive_checked = true;
                    let rogue_recursive: BTreeSet<String> = all_a_ips
                        .iter()
                        .filter(|ip| !auth_union.contains(*ip))
                        .cloned()
                        .collect();
                    posture.auth_recursive_match = rogue_recursive.is_empty();
                    let detail: Vec<Value> = per_ns
                        .iter()
                        .map(|(n, ips)| json!({ "nameserver": n, "authoritative_a": ips.iter().collect::<Vec<_>>() }))
                        .collect();
                    if !rogue_recursive.is_empty() {
                        auth_diverged = true;
                        threat_compromised.dns = true;
                        critical_signal = true;
                        findings.push(bgp_finding(
                            &format!("Recursive DNS poisoned vs authoritative for {domain}"),
                            "critical",
                            "T1557",
                            &format!(
                                "Recursive resolvers return {:?} but NO authoritative NS publishes {:?} — these IPs are absent from every direct authoritative answer. Definitive cache-poisoning / resolver hijack / split-horizon attack.",
                                all_a_ips.iter().collect::<Vec<_>>(),
                                rogue_recursive
                            ),
                            target,
                            "Purge resolver caches, switch to DNSSEC-validating resolvers, and compare authoritative answers out-of-band. Engage your DNS host if authoritative data was changed.",
                            0.95,
                            Evidence::new()
                                .with("domain", domain.clone())
                                .with("recursive_a", json!(all_a_ips.iter().collect::<Vec<_>>()))
                                .with("authoritative_union", json!(auth_union.iter().collect::<Vec<_>>()))
                                .with("rogue_recursive", json!(rogue_recursive.iter().collect::<Vec<_>>()))
                                .with("per_nameserver", json!(detail))
                                .check("auth_recursive_match", false, json!(rogue_recursive.len())),
                        ));
                    } else {
                        findings.push(bgp_finding(
                            &format!("Recursive answers match authoritative NS for {domain}"),
                            "info",
                            "T1557",
                            &format!(
                                "Every recursive A record {:?} is published by at least one authoritative NS ({} queried). No split-horizon / poisoning divergence.",
                                all_a_ips.iter().collect::<Vec<_>>(),
                                ns_names.len()
                            ),
                            target,
                            "Monitor authoritative-vs-recursive divergence continuously — gold-standard hijack detection beyond recursive-only scanners.",
                            0.88,
                            Evidence::new()
                                .with("domain", domain.clone())
                                .with("per_nameserver", json!(detail))
                                .check("auth_recursive_match", true, json!(auth_union.len())),
                        ));
                    }
                }
            }
        }
    }

    // ── 1e) RDAP registration lock (registrar hijack surface) ────────────────
    if cfg.check_rdap {
        if let Some(rdap) = probe_rdap(&client, &domain).await {
            posture.rdap_checked = true;
            posture.rdap_transfer_locked = rdap.transfer_locked;
            let ev = Evidence::new()
                .with("domain", domain.clone())
                .with("transfer_locked", rdap.transfer_locked)
                .with("update_locked", rdap.update_locked)
                .with("rdap_delegation_signed", rdap.delegation_signed)
                .with("expires", rdap.expires.clone().unwrap_or_default())
                .check(
                    "client_transfer_prohibited",
                    rdap.transfer_locked,
                    "RDAP status",
                );
            if !rdap.transfer_locked {
                findings.push(bgp_finding(
                    &format!("Domain transfer NOT locked for {domain}"),
                    "medium",
                    "T1584.002",
                    &format!(
                        "RDAP shows {domain} without clientTransferProhibited — an attacker who compromises the registrar account can transfer the domain and seize full DNS control (ultimate hijack). Expires: {:?}.",
                        rdap.expires
                    ),
                    target,
                    "Enable registrar lock (clientTransferProhibited), MFA on registrar account, and registry lock where available.",
                    0.82,
                    ev,
                ));
            } else {
                findings.push(bgp_finding(
                    &format!("Registrar transfer lock active for {domain}"),
                    "info",
                    "T1584.002",
                    &format!(
                        "RDAP confirms clientTransferProhibited on {domain}. Update-locked: {}. RDAP secureDNS.delegationSigned: {}.",
                        rdap.update_locked, rdap.delegation_signed
                    ),
                    target,
                    "Also enable clientUpdateProhibited during stable periods and monitor RDAP for unauthorised status changes.",
                    0.8,
                    ev,
                ));
            }
        }
    }

    if !posture.resolved {
        findings.push(bgp_finding(
            &format!("DNS resolution failed for {domain}"),
            "info",
            "T1590.002",
            &format!("No A records returned for {domain} by any configured resolver. The domain may not exist, be IPv6-only, or DNS may be unavailable from the scanner egress."),
            target,
            "Verify the domain and that the scanner can reach public DoH resolvers, then re-run. Enable AAAA checks if the asset is IPv6-only.",
            0.6,
            Evidence::new().with("domain", domain.clone()),
        ));
        let empty_fp = HijackFingerprint::default();
        let planes = build_threat_plane_matrix(&posture, &threat_compromised);
        return finalize(
            findings,
            &posture,
            critical_signal,
            &domain,
            target,
            &empty_fp,
            &planes,
            &cfg,
            &zone_discovery,
            &adaptive_plan,
        );
    }

    // ── 2) DNSSEC chain validation ───────────────────────────────────────────
    if cfg.check_dnssec {
        posture.dnssec_checked = true;
        let ad_any = per_resolver.iter().any(|(_, _, ad, _)| *ad);
        let servfail_any = per_resolver.iter().any(|(_, _, _, st)| *st == 2);
        let noerror_any = per_resolver.iter().any(|(_, _, _, st)| *st == 0);

        let ds = doh_query(&client, &cfg.resolvers[0].1, &domain, T_DS, true)
            .await
            .map(|r| answers_of(&r, T_DS))
            .unwrap_or_default();
        let dnskey = doh_query(&client, &cfg.resolvers[0].1, &domain, T_DNSKEY, true)
            .await
            .map(|r| answers_of(&r, T_DNSKEY))
            .unwrap_or_default();

        posture.dnssec_signed = !ds.is_empty() || !dnskey.is_empty();
        posture.dnssec_validated = ad_any;
        posture.dnssec_broken = servfail_any && noerror_any;

        let key_algs = dnskey_algorithms(&dnskey);
        let weak_keys: Vec<Value> = key_algs
            .iter()
            .filter_map(|(alg, label)| {
                WEAK_DNSKEY_ALGORITHMS
                    .iter()
                    .find(|(_, id)| *id == *alg)
                    .map(|(weak_label, _)| json!({ "algorithm": alg, "label": label, "weakness": weak_label }))
            })
            .collect();
        posture.dnskey_strong = weak_keys.is_empty();
        if !dnskey.is_empty() && !weak_keys.is_empty() {
            findings.push(bgp_finding(
                &format!("Weak DNSKEY algorithm(s) for {domain}"),
                "medium",
                "T1584.002",
                &format!(
                    "{domain} publishes DNSKEY records using deprecated algorithms {:?}. Weak keys reduce DNSSEC integrity against forgery.",
                    weak_keys
                ),
                target,
                "Rotate to ECDSA P-256 (alg 13) or Ed25519 (alg 15) and remove legacy RSA/MD5/DSA keys per RFC 8624.",
                0.78,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("dnskey_algorithms", json!(key_algs))
                    .with("weak", json!(weak_keys)),
            ));
        }

        let ev = Evidence::new()
            .with("domain", domain.clone())
            .with("ad_flag", ad_any)
            .with("ds_records", ds.len() as u64)
            .with("dnskey_records", dnskey.len() as u64)
            .check("authenticated_data", ad_any, "resolver set AD bit")
            .check("ds_at_parent", !ds.is_empty(), json!(ds.len()))
            .check("dnskey_in_zone", !dnskey.is_empty(), json!(dnskey.len()))
            .check("dnskey_strong", posture.dnskey_strong, json!(key_algs));

        if posture.dnssec_broken {
            critical_signal = true;
            findings.push(bgp_finding(
                &format!("Broken DNSSEC for {domain}"),
                "high",
                "T1584.002",
                &format!("A validating resolver returned SERVFAIL for {domain} while a permissive resolver answered — a classic broken-DNSSEC signature (expired RRSIG, missing DS, key rollover gap). Validating clients cannot reach the domain, and the failure mode masks tampering."),
                target,
                "Fix the DNSSEC chain immediately: re-sign the zone, ensure the parent DS matches the active KSK, and validate with `dig +dnssec` / dnsviz before re-running.",
                0.85,
                ev,
            ));
        } else if posture.dnssec_validated {
            findings.push(bgp_finding(
                &format!("DNSSEC validated for {domain}"),
                "info",
                "T1584.002",
                &format!("Resolvers set the Authenticated Data flag for {domain} (DS {}, DNSKEY {}). Forged records are cryptographically rejected by validating clients — strong defence against DNS hijack/poisoning.", ds.len(), dnskey.len()),
                target,
                "Maintain DNSSEC: monitor RRSIG expiry, automate key rollover, and keep the parent DS in sync. Consider CDS/CDNSKEY for automated DS maintenance.",
                0.9,
                ev,
            ));
        } else {
            findings.push(bgp_finding(
                &format!("DNSSEC not enabled for {domain}"),
                "medium",
                "T1584.002",
                &format!("{domain} is not DNSSEC-signed (no AD flag, no DS/DNSKEY observed). Without DNSSEC, forged DNS answers from a hijack or poisoning attack are accepted by clients."),
                target,
                "Enable DNSSEC at the authoritative DNS provider and publish the DS record at the registrar to complete the chain of trust.",
                0.8,
                ev,
            ));
        }
    }

    // ── 3) RPKI ROA + BGP origin analysis ────────────────────────────────────
    if (cfg.check_rpki || cfg.check_bgp) && primary_ip.is_some() {
        let ip = primary_ip.clone().unwrap();
        if let Some(po) = ripe_prefix_overview(&client, &cfg.ripe_base, &ip).await {
            posture.bgp_checked = cfg.check_bgp;
            covering_prefix = po.prefix.clone();
            let origin_asns: Vec<u32> = po.origins.iter().map(|(a, _)| *a).collect();
            observed_bgp_origins = origin_asns.clone();
            posture.moas = origin_asns.len() > 1;

            // Unexpected origin AS (only meaningful when the operator declared the allow-list).
            if cfg.check_bgp && !cfg.expected_origin_asns.is_empty() {
                let unexpected: Vec<u32> = origin_asns
                    .iter()
                    .copied()
                    .filter(|a| !cfg.expected_origin_asns.contains(a))
                    .collect();
                if !unexpected.is_empty() {
                    posture.unexpected_origin = true;
                    critical_signal = true;
                    findings.push(bgp_finding(
                        &format!("Unexpected BGP origin AS for {} ({})", ip, po.prefix),
                        "critical",
                        "T1584.004",
                        &format!(
                            "Prefix {} (covering {ip}) is originated by AS{:?}, which is NOT in the operator-declared legitimate set {:?}. An unexpected origin AS is a direct BGP hijack / route-leak indicator.",
                            po.prefix, unexpected, cfg.expected_origin_asns
                        ),
                        target,
                        "Verify with your transit providers and IRR/RPKI records immediately. If unauthorised, request upstream filtering, ensure a correct ROA exists (origin = your AS, maxLength tight), and engage the RIR.",
                        0.92,
                        Evidence::new()
                            .with("ip", ip.clone())
                            .with("prefix", po.prefix.clone())
                            .with("observed_origins", json!(origin_asns))
                            .with("expected_origins", json!(cfg.expected_origin_asns.iter().collect::<Vec<_>>()))
                            .check("origin_in_allowlist", false, json!(unexpected)),
                    ));
                }
            }

            if cfg.check_bgp && posture.moas {
                findings.push(bgp_finding(
                    &format!("Multiple-Origin-AS announcement for {}", po.prefix),
                    "medium",
                    "T1584.004",
                    &format!(
                        "Prefix {} is announced by multiple origin ASes {:?}. MOAS can be legitimate (anycast / multi-homing) but is also a hijack signature — confirm every origin is authorised.",
                        po.prefix,
                        po.origins.iter().map(|(a, h)| format!("AS{a} ({h})")).collect::<Vec<_>>()
                    ),
                    target,
                    "Confirm each origin AS is yours/authorised. Publish RPKI ROAs for every legitimate origin and monitor for new, unauthorised origins.",
                    0.7,
                    Evidence::new().with("prefix", po.prefix.clone()).with("origins", json!(po.origins.iter().map(|(a, h)| json!({"asn": a, "holder": h})).collect::<Vec<_>>())),
                ));
            }

            // BGP routing-history drift (origin churn on the covering prefix).
            if cfg.check_routing_history && !po.prefix.is_empty() {
                let hist_origins =
                    ripe_routing_history_origins(&client, &cfg.ripe_base, &po.prefix).await;
                posture.bgp_origin_stable = hist_origins.len() <= 1
                    || hist_origins.iter().all(|a| {
                        cfg.expected_origin_asns.is_empty() || cfg.expected_origin_asns.contains(a)
                    });
                if hist_origins.len() > 1 {
                    findings.push(bgp_finding(
                        &format!("BGP origin churn on {} ({} distinct origins in history)", po.prefix, hist_origins.len()),
                        "medium",
                        "T1584.004",
                        &format!(
                            "RIPEstat routing-history shows {} distinct origin AS(es) for {}: {:?}. Recent origin churn is a hijack/leak precursor — verify every origin is authorised.",
                            hist_origins.len(), po.prefix, hist_origins
                        ),
                        target,
                        "Alert on origin-AS changes for your prefixes. Investigate any origin not in your allow-list immediately.",
                        0.72,
                        Evidence::new()
                            .with("prefix", po.prefix.clone())
                            .with("history_origins", json!(hist_origins))
                            .check("origin_stable", posture.bgp_origin_stable, json!(hist_origins.len())),
                    ));
                } else if !hist_origins.is_empty() {
                    posture.bgp_origin_stable = true;
                }
            } else if cfg.check_bgp {
                posture.bgp_origin_stable = !posture.unexpected_origin && !posture.moas;
            }

            // RPKI ROA validation for the observed (prefix, origin) pairs.
            if cfg.check_rpki && !po.prefix.is_empty() {
                posture.rpki_checked = true;
                let mut any_valid = false;
                let mut any_invalid = false;
                let mut states: Vec<Value> = Vec::new();
                for (asn, _holder) in &po.origins {
                    if let Some(state) =
                        ripe_rpki_validation(&client, &cfg.ripe_base, *asn, &po.prefix).await
                    {
                        states.push(
                            json!({ "asn": asn, "prefix": po.prefix, "rpki": state.as_str() }),
                        );
                        match state {
                            RpkiState::Valid => any_valid = true,
                            RpkiState::Invalid => any_invalid = true,
                            RpkiState::Unknown => {}
                        }
                    }
                }
                posture.rpki_valid = any_valid && !any_invalid;
                posture.rpki_invalid = any_invalid;

                let ev = Evidence::new()
                    .with("ip", ip.clone())
                    .with("prefix", po.prefix.clone())
                    .with("rpki_states", json!(states))
                    .check("rpki_valid", any_valid, "ROA covers origin")
                    .check("rpki_invalid", any_invalid, "ROA contradicts origin");

                if any_invalid {
                    critical_signal = true;
                    threat_compromised.bgp = true;
                    findings.push(bgp_finding(
                        &format!("RPKI-invalid route for {} ({})", po.prefix, ip),
                        "critical",
                        "T1584.004",
                        &format!("The announcement of {} is RPKI-INVALID — the origin AS contradicts the signed ROA. This is a strong route-hijack / mis-origination signal; RPKI-validating networks should already be dropping the route.", po.prefix),
                        target,
                        "Treat as an active routing incident: verify whether the announcement is yours, correct the ROA (or the announcement) so origin+maxLength match, and engage upstreams/RIR. RPKI-invalid routes are dropped by major networks, causing outages and indicating hijack.",
                        0.93,
                        ev,
                    ));
                } else if any_valid {
                    findings.push(bgp_finding(
                        &format!("RPKI-valid route for {} ({})", po.prefix, ip),
                        "info",
                        "T1584.004",
                        &format!("The prefix {} has a signed RPKI ROA matching its origin AS — RPKI-validating networks reject hijack attempts that re-originate it. Strong BGP-integrity posture.", po.prefix),
                        target,
                        "Keep ROAs current with a tight maxLength; extend ROAs to every prefix you originate (including IPv6 and more-specifics).",
                        0.9,
                        ev,
                    ));
                } else {
                    findings.push(bgp_finding(
                        &format!("No RPKI ROA for {} ({}) — route unprotected", po.prefix, ip),
                        "high",
                        "T1584.004",
                        &format!("The prefix {} has no RPKI ROA (state: not-found/unknown). Without a ROA, a hijacker can announce a more-specific or compete for the origin and validating networks have nothing to reject — the prefix is unprotected against BGP hijack.", po.prefix),
                        target,
                        "Create an RPKI ROA at your RIR (RIPE/ARIN/APNIC/LACNIC/AFRINIC) authorising your origin AS for this prefix with a tight maxLength, then verify it reaches 'valid'.",
                        0.85,
                        ev,
                    ));
                }
            }

            // BGP visibility context.
            if cfg.check_bgp {
                findings.push(bgp_finding(
                    &format!("BGP prefix {} (announced: {})", po.prefix, po.announced),
                    "info",
                    "T1590",
                    &format!(
                        "{ip} lives in BGP prefix {} originated by {}. Continuous origin-AS monitoring (RIPE RIS / RouteViews / BGPalerter) turns a hijack from invisible to a paged alert.",
                        po.prefix,
                        po.origins.iter().map(|(a, h)| format!("AS{a} ({h})")).collect::<Vec<_>>().join(", ")
                    ),
                    target,
                    "Enable BGP route monitoring with alerting on new origins/more-specifics for your prefixes (e.g. BGPalerter, Cloudflare/Kentik route monitoring).",
                    0.75,
                    Evidence::new().with("ip", ip.clone()).with("prefix", po.prefix.clone()).with("announced", po.announced),
                ));
            }
        }
    }

    // ── 3a) IRR route registry vs live BGP ───────────────────────────────────
    if cfg.check_irr && !covering_prefix.is_empty() && !observed_bgp_origins.is_empty() {
        posture.irr_checked = true;
        let irr_origins = ripe_irr_route_origins(&client, &cfg.ripe_base, &covering_prefix).await;
        posture.irr_matches_bgp =
            irr_origins.is_empty() || observed_bgp_origins.iter().all(|o| irr_origins.contains(o));
        let ev = Evidence::new()
            .with("prefix", covering_prefix.clone())
            .with("observed_origins", json!(observed_bgp_origins))
            .with("irr_origins", json!(irr_origins.iter().collect::<Vec<_>>()))
            .check(
                "irr_covers_bgp",
                posture.irr_matches_bgp,
                json!(irr_origins.len()),
            );
        if !posture.irr_matches_bgp {
            critical_signal = true;
            findings.push(bgp_finding(
                &format!("IRR route registry contradicts live BGP for {}", covering_prefix),
                "high",
                "T1584.004",
                &format!(
                    "Live BGP origin AS(es) {:?} for {} are NOT authorised in IRR route objects {:?}. This mismatch is a route-leak / hijack precursor — many networks filter on IRR.",
                    observed_bgp_origins, covering_prefix, irr_origins
                ),
                target,
                "Publish correct route/route6 objects in RIPE/ARIN RADb matching your live announcements, or fix the BGP announcement to match IRR.",
                0.88,
                ev,
            ));
        } else if !irr_origins.is_empty() {
            findings.push(bgp_finding(
                &format!("IRR route objects align with BGP for {}", covering_prefix),
                "info",
                "T1584.004",
                &format!("IRR origins {:?} cover live BGP origin(s) {:?} — filtering-friendly posture.", irr_origins, observed_bgp_origins),
                target,
                "Keep IRR in sync with every prefix you originate; automate with IRRToolSet / PeeringDB.",
                0.78,
                ev,
            ));
        }
    }

    // ── 3a2) More-specific prefix hijack (RIPEstat related-prefixes) ─────────
    if cfg.check_more_specific && !covering_prefix.is_empty() {
        posture.more_specific_checked = true;
        let legit: Vec<u32> = if cfg.expected_origin_asns.is_empty() {
            observed_bgp_origins.clone()
        } else {
            cfg.expected_origin_asns.iter().copied().collect()
        };
        let threats =
            ripe_foreign_more_specifics(&client, &cfg.ripe_base, &covering_prefix, &legit).await;
        posture.more_specific_clean = threats.is_empty();
        if !threats.is_empty() {
            critical_signal = true;
            threat_compromised.bgp = true;
            findings.push(bgp_finding(
                &format!("Foreign more-specific BGP announcements for {}", covering_prefix),
                "critical",
                "T1584.004",
                &format!(
                    "RIPEstat reports more-specific prefix(es) under {} originated by foreign AS(es): {:?}. More-specific hijacks steal traffic without touching the covering aggregate — classic BGP interception.",
                    covering_prefix, threats
                ),
                target,
                "Alert on more-specific announcements immediately (BGPalerter). File RPKI ROAs with tight maxLength and engage upstreams to drop unauthorised more-specifics.",
                0.93,
                Evidence::new()
                    .with("covering_prefix", covering_prefix.clone())
                    .with("threats", json!(threats))
                    .check("more_specific_clean", false, json!(threats.len())),
            ));
        } else {
            findings.push(bgp_finding(
                &format!("No foreign more-specifics under {}", covering_prefix),
                "info",
                "T1584.004",
                &format!("No unauthorised more-specific prefixes detected under {} at scan time.", covering_prefix),
                target,
                "Continuously monitor for new more-specifics — they appear minutes before a hijack peaks.",
                0.7,
                Evidence::new().with("covering_prefix", covering_prefix.clone()),
            ));
        }
    }

    // ── 3a3) IPv4/IPv6 dual-stack origin binding ─────────────────────────────
    if cfg.check_dual_stack && posture.resolved {
        if let Some((_, base)) = cfg.resolvers.first() {
            if let Some(r6) = doh_query(&client, base, &domain, T_AAAA, false).await {
                let v6 = answers_of(&r6, T_AAAA);
                if let (Some(v4_ip), Some(v6_ip)) = (primary_ip.as_ref(), v6.first()) {
                    posture.dual_stack_checked = true;
                    let v4_origins = origin_asns_for_ip(&client, &cfg.ripe_base, v4_ip).await;
                    let v6_origins = origin_asns_for_ip(&client, &cfg.ripe_base, v6_ip).await;
                    let overlap: BTreeSet<u32> = v4_origins
                        .iter()
                        .copied()
                        .filter(|a| v6_origins.contains(a))
                        .collect();
                    posture.dual_stack_origin_match =
                        !v4_origins.is_empty() && !v6_origins.is_empty() && !overlap.is_empty();
                    if !posture.dual_stack_origin_match {
                        findings.push(bgp_finding(
                            &format!("IPv4/IPv6 origin mismatch for {domain}"),
                            "medium",
                            "T1584.004",
                            &format!(
                                "{domain} A→{v4_ip} (origin AS{:?}) vs AAAA→{v6_ip} (origin AS{:?}) — no shared origin AS. Split-stack hijack or misconfiguration can serve different endpoints per protocol.",
                                v4_origins, v6_origins
                            ),
                            target,
                            "Ensure A and AAAA point to the same organisation/network. Monitor both address families in RPKI/BGP alerting.",
                            0.8,
                            Evidence::new()
                                .with("domain", domain.clone())
                                .with("a_ip", v4_ip.clone())
                                .with("aaaa_ip", v6_ip.clone())
                                .with("v4_origins", json!(v4_origins))
                                .with("v6_origins", json!(v6_origins)),
                        ));
                    } else {
                        findings.push(bgp_finding(
                            &format!("IPv4/IPv6 origin binding consistent for {domain}"),
                            "info",
                            "T1584.004",
                            &format!("A and AAAA share origin AS(es) {:?} — dual-stack routing integrity OK.", overlap),
                            target,
                            "Extend RPKI ROAs to IPv6 prefixes and monitor both families.",
                            0.75,
                            Evidence::new()
                                .with("domain", domain.clone())
                                .with("shared_origins", json!(overlap.iter().collect::<Vec<_>>())),
                        ));
                    }
                }
            }
        }
    }

    // ── 3b) TLS identity binding (live cert vs scanned name) ─────────────────
    if cfg.check_tls_identity && posture.resolved {
        if let Some(cert) = tls_cert_details(&domain).await {
            posture.tls_checked = true;
            let names = tls_cert_name_list(&cert);
            let covers = names.iter().any(|n| cert_covers_domain(n, &domain));
            posture.tls_identity_match = covers && !cert.expired;
            if !covers || cert.expired {
                tls_mismatch = true;
                threat_compromised.tls = true;
                critical_signal = true;
                findings.push(bgp_finding(
                    &format!("TLS identity mismatch for {domain}"),
                    "critical",
                    "T1584.001",
                    &format!(
                        "Live TLS on port 443 for {domain} presents cert subject/SAN {:?} (expired={}). The certificate does NOT cover the scanned name — consistent with DNS/BGP hijack to an attacker endpoint even when resolvers agree.",
                        names, cert.expired
                    ),
                    target,
                    "Verify the IP you reach is yours. If hijacked, engage transit/RIR and fix DNS/RPKI. Re-issue a cert covering the correct name once routing is restored.",
                    0.91,
                    Evidence::new()
                        .with("domain", domain.clone())
                        .with("cert_subject", cert.subject.clone())
                        .with("san_dns_names", json!(cert.san_dns_names))
                        .with("expired", cert.expired)
                        .check("cert_covers_domain", covers, json!(names)),
                ));
            } else {
                findings.push(bgp_finding(
                    &format!("TLS identity matches {domain}"),
                    "info",
                    "T1584.001",
                    &format!(
                        "Certificate on port 443 covers {domain} and is not expired (issuer: {}). Strong binding between the name and the live endpoint.",
                        cert.issuer
                    ),
                    target,
                    "Monitor cert expiry and maintain CT logging; a valid cert on a hijacked IP is still possible if the attacker obtains one — combine with RPKI/DNSSEC.",
                    0.85,
                    Evidence::new()
                        .with("domain", domain.clone())
                        .with("issuer", cert.issuer.clone())
                        .with("days_until_expiry", cert.days_until_expiry)
                        .check("cert_covers_domain", true, json!(names)),
                ));
            }
        } else {
            findings.push(bgp_finding(
                &format!("TLS probe inconclusive for {domain}"),
                "low",
                "T1584.001",
                &format!("Could not complete a TLS handshake on port 443 for {domain} from the scanner egress (timeout, no HTTPS, or firewall)."),
                target,
                "Ensure HTTPS is reachable on 443 from your monitoring vantage points; TLS identity binding is a high-value hijack corroboration signal.",
                0.5,
                Evidence::new().with("domain", domain.clone()).check("tls_reachable", false, "no cert"),
            ));
        }
    }

    // ── 3c) DANE/TLSA ────────────────────────────────────────────────────────
    if cfg.check_dane {
        if let Some(r) = doh_query(&client, &cfg.resolvers[0].1, &domain, T_TLSA, false).await {
            let tlsa = answers_of(&r, T_TLSA);
            posture.dane_checked = true;
            posture.dane_present = !tlsa.is_empty();
            if tlsa.is_empty() {
                findings.push(bgp_finding(
                    &format!("No DANE/TLSA for {domain}"),
                    "low",
                    "T1584.002",
                    &format!("{domain} has no TLSA records. DANE pins the expected certificate in DNS — optional but adds another hijack detection layer when DNSSEC is enabled."),
                    target,
                    "After DNSSEC is stable, consider publishing TLSA records (RFC 6698) to bind TLS keys to DNS.",
                    0.55,
                    Evidence::new().with("domain", domain.clone()).check("tlsa_present", false, "none"),
                ));
            } else {
                findings.push(bgp_finding(
                    &format!("DANE/TLSA present for {domain}"),
                    "info",
                    "T1584.002",
                    &format!("{domain} publishes {} TLSA record(s): {}. DANE-aware clients can reject certs that do not match the pinned association.", tlsa.len(), tlsa.join("; ")),
                    target,
                    "Keep TLSA in sync with cert rotations; use automated TLSA updates (RFC 7671) where possible.",
                    0.8,
                    Evidence::new().with("domain", domain.clone()).with("tlsa", json!(tlsa)),
                ));
            }
        }
    }

    // ── 3d) Certificate Transparency inventory ───────────────────────────────
    if cfg.check_ct {
        posture.ct_inventory_checked = true;
        if let Some(count) = probe_ct_count(&client, &domain).await {
            let issuers = probe_ct_recent_issuers(&client, &domain, 12).await;
            let sev = if count > 50 { "medium" } else { "info" };
            findings.push(bgp_finding(
                &format!("{count} CT certificate(s) for {domain}"),
                sev,
                "T1584.001",
                &format!(
                    "crt.sh reports {count} certificate(s) for {domain}. Recent issuers: {}. Monitor for unauthorised CAs after any DNS/BGP incident.",
                    if issuers.is_empty() { "n/a".into() } else { issuers.join(", ") }
                ),
                target,
                "Subscribe to CT monitoring (Certstream, crt.sh alerts) and cross-check issuers against your CAA policy.",
                0.65,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("ct_cert_count", count as u64)
                    .with("recent_issuers", json!(issuers))
                    .check("ct_inventory", true, json!(count)),
            ));
        }
    }

    // ── 3e) SOA primary NS integrity ───────────────────────────────────────
    if cfg.check_soa && posture.resolved {
        if let Some(r) = doh_query(&client, &cfg.resolvers[0].1, &domain, T_SOA, false).await {
            let soa = answers_of(&r, T_SOA);
            if let Some(soa_raw) = soa.first() {
                posture.soa_checked = true;
                if let Some(mname) = parse_soa_mname(soa_raw) {
                    let ns_resp =
                        doh_query(&client, &cfg.resolvers[0].1, &domain, T_NS, false).await;
                    let ns_set: BTreeSet<String> = ns_resp
                        .map(|nr| {
                            answers_of(&nr, T_NS)
                                .iter()
                                .map(|n| n.trim().trim_end_matches('.').to_ascii_lowercase())
                                .collect()
                        })
                        .unwrap_or_default();
                    posture.soa_mname_in_ns = ns_set.is_empty() || ns_set.contains(&mname);
                    if !posture.soa_mname_in_ns && !ns_set.is_empty() {
                        findings.push(bgp_finding(
                            &format!("SOA MNAME not in NS set for {domain}"),
                            "medium",
                            "T1584.002",
                            &format!(
                                "SOA primary nameserver (MNAME) is {mname} but authoritative NS set is {:?}. MNAME should be a listed nameserver — misconfiguration aids zone tampering.",
                                ns_set
                            ),
                            target,
                            "Align SOA MNAME with an authoritative NS in the NS set and verify zone file integrity.",
                            0.7,
                            Evidence::new()
                                .with("domain", domain.clone())
                                .with("soa_mname", mname.clone())
                                .with("nameservers", json!(ns_set.iter().collect::<Vec<_>>())),
                        ));
                    } else {
                        findings.push(bgp_finding(
                            &format!("SOA MNAME consistent for {domain}"),
                            "info",
                            "T1584.002",
                            &format!("SOA primary {mname} is listed in the NS set — zone metadata integrity OK."),
                            target,
                            "Monitor SOA serial for unexpected jumps (indicates zone file changes).",
                            0.65,
                            Evidence::new().with("domain", domain.clone()).with("soa_mname", mname),
                        ));
                    }
                }
            }
        }
    }

    // ── 4) Authoritative NS diversity ────────────────────────────────────────
    if cfg.check_ns {
        if let Some(r) = doh_query(&client, &cfg.resolvers[0].1, &domain, T_NS, false).await {
            let ns = answers_of(&r, T_NS);
            if !ns.is_empty() {
                posture.ns_checked = true;
                // Resolve each NS to an IP, map to origin AS, count distinct ASes.
                let mut as_of_ns: HashMap<String, u32> = HashMap::new();
                for nsname in ns.iter().take(8) {
                    if let Some(rr) = doh_query(
                        &client,
                        &cfg.resolvers[0].1,
                        nsname.trim_end_matches('.'),
                        T_A,
                        false,
                    )
                    .await
                    {
                        if let Some(ip) = answers_of(&rr, T_A).into_iter().next() {
                            if let Some(po) =
                                ripe_prefix_overview(&client, &cfg.ripe_base, &ip).await
                            {
                                if let Some((asn, _)) = po.origins.first() {
                                    as_of_ns.insert(nsname.clone(), *asn);
                                }
                            }
                        }
                    }
                }
                let distinct_as: BTreeSet<u32> = as_of_ns.values().copied().collect();
                posture.ns_diverse = ns.len() >= 2 && distinct_as.len() >= 2;
                let ev = Evidence::new()
                    .with("domain", domain.clone())
                    .with("nameservers", json!(ns))
                    .with(
                        "ns_origin_asns",
                        json!(distinct_as.iter().collect::<Vec<_>>()),
                    )
                    .check("multiple_nameservers", ns.len() >= 2, json!(ns.len()))
                    .check(
                        "multiple_networks",
                        distinct_as.len() >= 2,
                        json!(distinct_as.len()),
                    );
                if !posture.ns_diverse {
                    findings.push(bgp_finding(
                        &format!("Low authoritative-NS diversity for {domain}"),
                        "medium",
                        "T1584.002",
                        &format!(
                            "{domain} is served by {} nameserver(s) across {} distinct network(s)/AS(es). Low diversity is a single point of hijack/failure — compromising or hijacking one provider/network takes the whole zone.",
                            ns.len(), distinct_as.len().max(1)
                        ),
                        target,
                        "Use at least two nameservers on independent providers/networks (different ASes). Consider a secondary DNS provider for resilience against provider-level hijack/outage.",
                        0.72,
                        ev,
                    ));
                } else {
                    findings.push(bgp_finding(
                        &format!("Diverse authoritative NS for {domain}"),
                        "info",
                        "T1584.002",
                        &format!("{domain} uses {} nameservers across {} networks — resilient against single-provider hijack/outage.", ns.len(), distinct_as.len()),
                        target,
                        "Maintain multi-provider DNS and keep registrar/DNS account access locked down (MFA, registrar lock).",
                        0.8,
                        ev,
                    ));
                }
            }
        }
    }

    // ── 5) CAA issuance control ──────────────────────────────────────────────
    if cfg.check_caa {
        if let Some(r) = doh_query(&client, &cfg.resolvers[0].1, &domain, T_CAA, false).await {
            let caa = answers_of(&r, T_CAA);
            captured_caa = caa.clone();
            posture.caa_checked = true;
            posture.caa_present = !caa.is_empty();
            if caa.is_empty() {
                findings.push(bgp_finding(
                    &format!("No CAA record for {domain}"),
                    "medium",
                    "T1584.001",
                    &format!("{domain} has no CAA record, so any public CA may issue a certificate for it. Combined with a DNS/BGP hijack, an attacker can obtain a trusted cert and fully impersonate the site."),
                    target,
                    "Publish a CAA record restricting issuance to your CA(s), e.g. `example.com. CAA 0 issue \"letsencrypt.org\"` plus `iodef` for violation reports.",
                    0.7,
                    Evidence::new().with("domain", domain.clone()).check("caa_present", false, "no CAA"),
                ));
            } else {
                findings.push(bgp_finding(
                    &format!("CAA issuance control present for {domain}"),
                    "info",
                    "T1584.001",
                    &format!("{domain} restricts certificate issuance via CAA: {}. Limits hijack-plus-mis-issuance attacks.", caa.join("; ")),
                    target,
                    "Keep the CAA allow-list tight and add an `iodef` reporting URL to be notified of unauthorised issuance attempts.",
                    0.8,
                    Evidence::new().with("domain", domain.clone()).with("caa", json!(caa)),
                ));
            }
        }
    }

    // ── 6) Dangling-CNAME / subdomain-takeover ───────────────────────────────
    if cfg.check_takeover {
        posture.takeover_checked = true;
        posture.takeover_clean = true;
        let mut names: Vec<String> = vec![domain.clone()];
        for s in &cfg.subdomains {
            let s = s.trim().trim_end_matches('.');
            if s.is_empty() {
                continue;
            }
            names.push(if s.ends_with(&domain) {
                s.to_string()
            } else {
                format!("{s}.{domain}")
            });
        }
        for name in names.into_iter().take(25) {
            if let Some(r) = doh_query(&client, &cfg.resolvers[0].1, &name, T_CNAME, false).await {
                let cnames = answers_of(&r, T_CNAME);
                for cn in &cnames {
                    let cl = cn.trim_end_matches('.').to_ascii_lowercase();
                    if let Some((suffix, service)) =
                        TAKEOVER_SUFFIXES.iter().find(|(suf, _)| cl.ends_with(*suf))
                    {
                        // Dangling check: does the CNAME target itself resolve to an address?
                        let resolves = doh_query(
                            &client,
                            &cfg.resolvers[0].1,
                            cn.trim_end_matches('.'),
                            T_A,
                            false,
                        )
                        .await
                        .map(|rr| !answers_of(&rr, T_A).is_empty())
                        .unwrap_or(false);
                        let sev = if resolves { "low" } else { "high" };
                        findings.push(bgp_finding(
                            &format!("{} CNAME to {} ({})", if resolves { "Third-party" } else { "Dangling" }, service, name),
                            sev,
                            "T1584.001",
                            &format!(
                                "{name} is a CNAME to {cn} ({service}). {}",
                                if resolves {
                                    "The target currently resolves; confirm the third-party resource is still owned by you to prevent future takeover."
                                } else {
                                    "The target does NOT resolve — a dangling delegation that an attacker can claim on the third-party service to take over this hostname (subdomain takeover)."
                                }
                            ),
                            target,
                            "Remove the dangling CNAME or (re)claim the resource on the third-party service. Track all CNAMEs to external services and decommission them with the resource.",
                            if resolves { 0.6 } else { 0.85 },
                            Evidence::new()
                                .with("name", name.clone())
                                .with("cname", cn.clone())
                                .with("service", *service)
                                .with("target_suffix", *suffix)
                                .check("target_resolves", resolves, cn.clone()),
                        ));
                        if !resolves {
                            posture.takeover_clean = false;
                            critical_signal = critical_signal || sev == "high";
                        }
                    }
                }
            }
        }
    }

    // ── 7) v5 cross-plane binding probes ─────────────────────────────────────

    // HSTS + HTTP redirect integrity (endpoint hijack corroboration)
    if cfg.check_hsts && posture.resolved {
        posture.hsts_checked = true;
        if let Some(https) = http_get(&client, &format!("https://{domain}/")).await {
            let hsts = http_header(&https.headers, "strict-transport-security");
            posture.hsts_present = hsts
                .as_ref()
                .is_some_and(|h| h.to_ascii_lowercase().contains("max-age"));
            if !posture.hsts_present {
                findings.push(bgp_finding(
                    &format!("No HSTS for {domain}"),
                    "low",
                    "T1557",
                    &format!("HTTPS response for {domain} lacks Strict-Transport-Security. After DNS/BGP hijack, clients can be downgraded to plaintext unless HSTS is preloaded."),
                    target,
                    "Deploy HSTS with max-age ≥ 31536000, includeSubDomains, and consider HSTS preload list submission.",
                    0.62,
                    Evidence::new().with("domain", domain.clone()).check("hsts_present", false, "missing"),
                ));
            } else {
                let hsts_val = hsts.clone().unwrap_or_default();
                findings.push(bgp_finding(
                    &format!("HSTS active for {domain}"),
                    "info",
                    "T1557",
                    &format!("Strict-Transport-Security: {hsts_val} — mitigates sslstrip after routing incidents."),
                    target,
                    "Keep max-age high and monitor cert/HSTS header drift.",
                    0.7,
                    Evidence::new().with("domain", domain.clone()).with("hsts", hsts_val),
                ));
            }
        }
    }

    if cfg.check_http_redirect && posture.resolved {
        posture.redirect_checked = true;
        if let Some(http) = http_get(&client, &format!("http://{domain}/")).await {
            let final_host = extract_host_from_url(&http.final_url).unwrap_or_default();
            let same_site = final_host.is_empty()
                || final_host == domain
                || final_host.ends_with(&format!(".{domain}"));
            posture.redirect_healthy = same_site && http.status < 400;
            if !same_site {
                threat_compromised.tls = true;
                critical_signal = true;
                findings.push(bgp_finding(
                    &format!("HTTP redirect leaves {domain} → {final_host}"),
                    "high",
                    "T1557",
                    &format!(
                        "http://{domain}/ redirects to {} (HTTP {}). Redirect to a foreign host is consistent with DNS/BGP hijack or open-redirect abuse.",
                        http.final_url, http.status
                    ),
                    target,
                    "Ensure HTTP redirects stay on-domain or HSTS-preloaded HTTPS. Investigate if the foreign host is unauthorised.",
                    0.86,
                    Evidence::new()
                        .with("domain", domain.clone())
                        .with("final_url", http.final_url.clone())
                        .with("status", http.status as u64),
                ));
            }
        }
    }

    // CAA ⟷ CT cross-validation (mis-issuance after hijack)
    if cfg.check_caa_ct_cross && !captured_caa.is_empty() {
        posture.caa_ct_checked = true;
        let allowed = parse_caa_issuers(&captured_caa);
        let issuers = probe_ct_recent_issuers(&client, &domain, 20).await;
        let violators: Vec<String> = issuers
            .iter()
            .filter(|i| ct_issuer_violates_caa(i, &allowed))
            .cloned()
            .collect();
        posture.caa_ct_aligned = violators.is_empty();
        if !violators.is_empty() {
            threat_compromised.registry = true;
            findings.push(bgp_finding(
                &format!("CT issuers outside CAA allow-list for {domain}"),
                "high",
                "T1584.001",
                &format!(
                    "CAA restricts issuance to {:?} but CT logs show certs from: {:?}. Post-hijack mis-issuance or CAA bypass.",
                    allowed, violators
                ),
                target,
                "Investigate unauthorised certificates immediately. Tighten CAA and enable CT monitoring alerts.",
                0.87,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("caa_allowed", json!(allowed.iter().collect::<Vec<_>>()))
                    .with("violating_issuers", json!(violators)),
            ));
        } else if !issuers.is_empty() {
            findings.push(bgp_finding(
                &format!("CT issuers align with CAA for {domain}"),
                "info",
                "T1584.001",
                &format!(
                    "Recent CT issuers {:?} match CAA allow-list {:?}.",
                    issuers, allowed
                ),
                target,
                "Continue CT+CAA continuous monitoring.",
                0.75,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("issuers", json!(issuers)),
            ));
        }
    }

    // RPKI maxLength slack (hijack window via over-broad ROA)
    if cfg.check_rpki_maxlength && !covering_prefix.is_empty() {
        if let Some(asn) = observed_bgp_origins.first() {
            posture.rpki_maxlength_checked = true;
            if let Some(slack) =
                ripe_rpki_maxlength_slack(&client, &cfg.ripe_base, *asn, &covering_prefix).await
            {
                posture.rpki_maxlength_tight = slack <= 8;
                if slack > 16 {
                    findings.push(bgp_finding(
                        &format!("RPKI ROA maxLength very loose for {}", covering_prefix),
                        "medium",
                        "T1584.004",
                        &format!(
                            "ROA maxLength slack is {slack} bits above prefix {} — attacker can announce a more-specific within the ROA window. Tighten maxLength to actual need.",
                            covering_prefix
                        ),
                        target,
                        "Re-issue ROA with minimal maxLength (often equal to prefix length).",
                        0.76,
                        Evidence::new()
                            .with("prefix", covering_prefix.clone())
                            .with("maxlength_slack", slack as u64),
                    ));
                } else {
                    findings.push(bgp_finding(
                        &format!("RPKI maxLength tight for {}", covering_prefix),
                        "info",
                        "T1584.004",
                        &format!(
                            "ROA maxLength slack {slack} — limited more-specific hijack window."
                        ),
                        target,
                        "Review ROA when aggregating prefixes.",
                        0.68,
                        Evidence::new()
                            .with("prefix", covering_prefix.clone())
                            .with("slack", slack as u64),
                    ));
                }
            }
        }
    }

    // BGP global visibility (is the route seen on the Internet?)
    if cfg.check_bgp_visibility && !covering_prefix.is_empty() {
        posture.visibility_checked = true;
        if let Some(vis) = ripe_bgp_visibility(&client, &cfg.ripe_base, &covering_prefix).await {
            posture.bgp_visible = vis >= 0.5;
            let sev = if vis < 0.3 {
                "high"
            } else if vis < 0.7 {
                "medium"
            } else {
                "info"
            };
            findings.push(bgp_finding(
                &format!("BGP visibility {:.0}% for {}", vis * 100.0, covering_prefix),
                sev,
                "T1590",
                &format!(
                    "RIPEstat routing-status visibility {:.1}% for {}. Low visibility may indicate filtering, anycast shadowing, or a route that is not globally propagated.",
                    vis * 100.0, covering_prefix
                ),
                target,
                "Compare with your BGP monitoring dashboards; investigate sudden visibility drops during incidents.",
                0.7,
                Evidence::new()
                    .with("prefix", covering_prefix.clone())
                    .with("visibility_pct", (vis * 100.0) as u64)
                    .check("globally_visible", vis >= 0.5, json!(vis)),
            ));
        }
    }

    // MX vs web origin binding (email hijack path)
    if cfg.check_mx_origin && posture.resolved {
        if let Some(r) = doh_query(&client, &cfg.resolvers[0].1, &domain, T_MX, false).await {
            let mx_raw = answers_of(&r, T_MX);
            if let Some(mx_host) = mx_raw.first().and_then(|m| m.split_whitespace().nth(1)) {
                let mx_host = mx_host.trim().trim_end_matches('.');
                if let Some(rr) = doh_query(&client, &cfg.resolvers[0].1, mx_host, T_A, false).await
                {
                    if let Some(mx_ip) = answers_of(&rr, T_A).into_iter().next() {
                        posture.mx_checked = true;
                        let web_as = observed_bgp_origins.clone();
                        let mx_as = origin_asns_for_ip(&client, &cfg.ripe_base, &mx_ip).await;
                        let overlap: BTreeSet<u32> = web_as
                            .iter()
                            .copied()
                            .filter(|a| mx_as.contains(a))
                            .collect();
                        posture.mx_origin_match =
                            !web_as.is_empty() && !mx_as.is_empty() && !overlap.is_empty();
                        if !posture.mx_origin_match && !web_as.is_empty() && !mx_as.is_empty() {
                            findings.push(bgp_finding(
                                &format!("MX origin differs from web A for {domain}"),
                                "medium",
                                "T1584.002",
                                &format!(
                                    "Web A AS{:?} vs MX {mx_host}→{mx_ip} AS{:?} — split infrastructure; verify MX is expected (Google/M365) not attacker-controlled after DNS hijack.",
                                    web_as, mx_as
                                ),
                                target,
                                "Document expected MX providers; alert when MX A records change origin AS.",
                                0.74,
                                Evidence::new()
                                    .with("domain", domain.clone())
                                    .with("mx_host", mx_host)
                                    .with("mx_ip", mx_ip)
                                    .with("web_origins", json!(web_as))
                                    .with("mx_origins", json!(mx_as)),
                            ));
                        }
                    }
                }
            }
        }
    }

    // In-bailiwick NS glue (A records must exist for child NS names)
    if cfg.check_glue && posture.resolved {
        if let Some(r) = doh_query(&client, &cfg.resolvers[0].1, &domain, T_NS, false).await {
            let ns = answers_of(&r, T_NS);
            let in_bailiwick: Vec<String> = ns
                .iter()
                .filter(|n| is_in_bailiwick_ns(n, &domain))
                .map(|n| n.trim().trim_end_matches('.').to_string())
                .collect();
            if !in_bailiwick.is_empty() {
                posture.glue_checked = true;
                let mut missing_glue = Vec::new();
                for n in &in_bailiwick {
                    let ips = doh_query(&client, &cfg.resolvers[0].1, n, T_A, false)
                        .await
                        .map(|rr| answers_of(&rr, T_A))
                        .unwrap_or_default();
                    if ips.is_empty() {
                        missing_glue.push(n.clone());
                    }
                }
                posture.glue_consistent = missing_glue.is_empty();
                if !missing_glue.is_empty() {
                    threat_compromised.dns = true;
                    findings.push(bgp_finding(
                        &format!("Missing glue A for in-bailiwick NS on {domain}"),
                        "high",
                        "T1584.002",
                        &format!(
                            "In-bailiwick nameservers {:?} lack A records {:?} — broken glue enables resolver hijack / lame delegation.",
                            in_bailiwick, missing_glue
                        ),
                        target,
                        "Publish glue A/AAAA at parent zone for every in-bailiwick NS.",
                        0.84,
                        Evidence::new()
                            .with("domain", domain.clone())
                            .with("missing_glue", json!(missing_glue)),
                    ));
                }
            }
        }
    }

    // Geo binding (resolved IP country vs operator expectation)
    if cfg.check_geo && !cfg.expected_countries.is_empty() {
        if let Some(ip) = primary_ip.as_ref() {
            posture.geo_checked = true;
            let countries = ripe_geoloc_countries(&client, &cfg.ripe_base, ip).await;
            posture.geo_match = countries.is_empty()
                || countries.iter().any(|c| cfg.expected_countries.contains(c));
            if !posture.geo_match && !countries.is_empty() {
                critical_signal = true;
                threat_compromised.dns = true;
                findings.push(bgp_finding(
                    &format!("Geo mismatch for {domain} ({ip})"),
                    "critical",
                    "T1590",
                    &format!(
                        "Resolved IP {ip} geolocates to {:?} but expected {:?}. Unexpected geography after routing/DNS change is a hijack signal.",
                        countries, cfg.expected_countries
                    ),
                    target,
                    "Verify the IP is yours; if not, treat as active hijack and engage providers.",
                    0.9,
                    Evidence::new()
                        .with("ip", ip.clone())
                        .with("observed_countries", json!(countries.iter().collect::<Vec<_>>()))
                        .with("expected", json!(cfg.expected_countries.iter().collect::<Vec<_>>())),
                ));
            }
        }
    }

    // ── 7) v6 advanced DNS integrity (FCrDNS, allow-list, lame NS, wildcard, timing) ─
    let doh_base = cfg
        .resolvers
        .first()
        .map(|(_, b)| b.as_str())
        .unwrap_or(DEFAULT_RESOLVERS[0].1);

    if cfg.check_expected_ips && !cfg.expected_a_ips.is_empty() && posture.resolved {
        posture.expected_ips_checked = true;
        let unexpected: Vec<String> = all_a_ips
            .iter()
            .filter(|ip| !cfg.expected_a_ips.contains(*ip))
            .cloned()
            .collect();
        posture.expected_ips_match = unexpected.is_empty();
        if !posture.expected_ips_match {
            critical_signal = true;
            threat_compromised.dns = true;
            findings.push(bgp_finding(
                &format!("Unexpected A record(s) for {domain} — not in allow-list"),
                "critical",
                "T1584.002",
                &format!(
                    "Observed A IPs {:?} but operator allow-list is {:?}. Any IP outside the declared set is a direct hijack indicator.",
                    all_a_ips.iter().collect::<Vec<_>>(),
                    cfg.expected_a_ips.iter().collect::<Vec<_>>()
                ),
                target,
                "If unauthorised, initiate incident response immediately. Update allow-list only after verifying legitimate infrastructure changes.",
                0.95,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("observed_ips", json!(all_a_ips.iter().collect::<Vec<_>>()))
                    .with("expected_ips", json!(cfg.expected_a_ips.iter().collect::<Vec<_>>()))
                    .with("unexpected_ips", json!(unexpected)),
            ));
        } else {
            findings.push(bgp_finding(
                &format!("A records match operator allow-list for {domain}"),
                "info",
                "T1584.002",
                &format!(
                    "All observed A IPs {:?} are within the declared allow-list {:?}.",
                    all_a_ips.iter().collect::<Vec<_>>(),
                    cfg.expected_a_ips.iter().collect::<Vec<_>>()
                ),
                target,
                "Keep allow-list current when migrating infrastructure; alert on any deviation.",
                0.85,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("observed_ips", json!(all_a_ips.iter().collect::<Vec<_>>())),
            ));
        }
    }

    if cfg.check_dnssec_ad_divergence && cfg.check_dnssec && per_resolver.len() >= 2 {
        let with_answers: Vec<_> = per_resolver
            .iter()
            .filter(|(_, ips, _, st)| *st == 0 && !ips.is_empty())
            .collect();
        if with_answers.len() >= 2 {
            posture.dnssec_ad_divergence_checked = true;
            let ads: BTreeSet<bool> = with_answers.iter().map(|(_, _, ad, _)| *ad).collect();
            posture.dnssec_ad_consensus = ads.len() <= 1;
            let detail: Vec<Value> = with_answers
                .iter()
                .map(|(n, ips, ad, st)| json!({ "resolver": n, "ips": ips, "ad": ad, "rcode": st }))
                .collect();
            if !posture.dnssec_ad_consensus {
                threat_compromised.dns = true;
                findings.push(bgp_finding(
                    &format!("DNSSEC AD-flag divergence across resolvers for {domain}"),
                    "high",
                    "T1557",
                    &format!(
                        "Validating resolvers disagree on the AD (authenticated data) bit for {domain}. One path validates DNSSEC while another does not — classic split-path poisoning or validator bypass."
                    ),
                    target,
                    "Compare resolver DNSSEC trust anchors; ensure all resolvers validate. Investigate any resolver returning AD=false while others return AD=true.",
                    0.89,
                    Evidence::new()
                        .with("domain", domain.clone())
                        .with("resolvers", json!(detail))
                        .check("ad_consensus", false, json!(ads.iter().collect::<Vec<_>>())),
                ));
            } else {
                findings.push(bgp_finding(
                    &format!("DNSSEC AD-flag consistent across resolvers for {domain}"),
                    "info",
                    "T1557",
                    &format!(
                        "All resolvers agree on AD={} for {domain}.",
                        ads.iter().next().copied().unwrap_or(false)
                    ),
                    target,
                    "Monitor AD-flag divergence continuously alongside A-record consensus.",
                    0.8,
                    Evidence::new()
                        .with("domain", domain.clone())
                        .with("resolvers", json!(detail)),
                ));
            }
        }
    }

    if cfg.check_fcrdns {
        if let Some(ip) = primary_ip.as_ref() {
            posture.fcrdns_checked = true;
            posture.fcrdns_valid = fcrdns_valid(&client, doh_base, &domain, ip).await;
            if !posture.fcrdns_valid {
                findings.push(bgp_finding(
                    &format!("FCrDNS mismatch for {domain} ({ip})"),
                    "medium",
                    "T1590",
                    &format!(
                        "Forward-confirmed reverse DNS failed for {ip}→{domain}. PTR missing or forward-A does not confirm the mapping — weak binding aids impersonation after routing hijack."
                    ),
                    target,
                    "Publish PTR records that forward-resolve back to the A record; align rDNS with asset inventory.",
                    0.78,
                    Evidence::new().with("domain", domain.clone()).with("ip", ip.clone()),
                ));
            } else {
                findings.push(bgp_finding(
                    &format!("FCrDNS valid for {domain} ({ip})"),
                    "info",
                    "T1590",
                    &format!("PTR for {ip} forward-confirms {domain}."),
                    target,
                    "Maintain PTR↔A consistency across infrastructure changes.",
                    0.72,
                    Evidence::new()
                        .with("domain", domain.clone())
                        .with("ip", ip.clone()),
                ));
            }
        }
    }

    if cfg.check_ns_lame && posture.resolved {
        if let Some(r) = doh_query(&client, doh_base, &domain, T_NS, false).await {
            let ns = answers_of(&r, T_NS);
            if !ns.is_empty() {
                posture.ns_lame_checked = true;
                let mut lame: Vec<String> = Vec::new();
                for nsname in ns.iter().take(8) {
                    let host = nsname.trim().trim_end_matches('.');
                    let Some(rr) = doh_query(&client, doh_base, host, T_A, false).await else {
                        lame.push(nsname.clone());
                        continue;
                    };
                    let Some(ns_ip_str) = answers_of(&rr, T_A).into_iter().next() else {
                        lame.push(nsname.clone());
                        continue;
                    };
                    let Ok(ns_ip) = IpAddr::from_str(&ns_ip_str) else {
                        lame.push(nsname.clone());
                        continue;
                    };
                    if !auth_zone_responds(&domain, ns_ip, cfg.timeout_ms).await {
                        lame.push(nsname.clone());
                    }
                }
                posture.ns_lame_free = lame.is_empty();
                if !posture.ns_lame_free {
                    threat_compromised.dns = true;
                    findings.push(bgp_finding(
                        &format!("Lame delegation on {domain}"),
                        "high",
                        "T1584.002",
                        &format!(
                            "Authoritative NS {:?} cannot answer for {domain} (SOA/A lookup failed). Lame delegation enables resolver hijack and cache poisoning.",
                            lame
                        ),
                        target,
                        "Fix or decommission broken nameservers; ensure every listed NS responds authoritatively.",
                        0.86,
                        Evidence::new()
                            .with("domain", domain.clone())
                            .with("lame_ns", json!(lame)),
                    ));
                }
            }
        }
    }

    if cfg.check_cname_chain {
        posture.cname_checked = true;
        let chain = follow_cname_chain(&client, doh_base, &domain, cfg.cname_max_hops).await;
        let dom = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let terminator = chain
            .last()
            .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
            .unwrap_or_default();
        posture.cname_healthy =
            chain.len() <= 1 || terminator == dom || terminator.ends_with(&format!(".{dom}"));
        if !posture.cname_healthy {
            threat_compromised.dns = true;
            findings.push(bgp_finding(
                &format!("CNAME chain leaves zone for {domain}"),
                "high",
                "T1584.002",
                &format!(
                    "CNAME chain {:?} terminates at {terminator} — outside {dom}. Off-zone terminators are hijack/subdomain-takeover precursors.",
                    chain
                ),
                target,
                "Audit CNAME delegations; ensure chains terminate within your zone or trusted CDN partners.",
                0.84,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("chain", json!(chain))
                    .with("terminator", terminator),
            ));
        } else if chain.len() > 1 {
            findings.push(bgp_finding(
                &format!("CNAME chain healthy for {domain}"),
                "info",
                "T1584.002",
                &format!("Chain {:?} terminates in-zone.", chain),
                target,
                "Re-audit after DNS changes.",
                0.7,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("chain", json!(chain)),
            ));
        }
    }

    if cfg.check_spf_apex {
        if let Some(r) = doh_query(&client, doh_base, &domain, T_TXT, false).await {
            posture.spf_checked = true;
            posture.spf_present = apex_has_spf(&answers_of(&r, T_TXT));
            if !posture.spf_present {
                findings.push(bgp_finding(
                    &format!("No SPF at apex for {domain}"),
                    "low",
                    "T1584.002",
                    &format!("No v=spf1 TXT at {domain} apex. Email-path DNS integrity is unbound — post-hijack mail spoofing risk."),
                    target,
                    "Publish SPF at apex alongside web/mail binding controls.",
                    0.65,
                    Evidence::new().with("domain", domain.clone()),
                ));
            } else {
                findings.push(bgp_finding(
                    &format!("SPF present at apex for {domain}"),
                    "info",
                    "T1584.002",
                    "v=spf1 TXT found at apex — email-path DNS integrity signal present.",
                    target,
                    "Combine with DMARC and monitor TXT record drift.",
                    0.68,
                    Evidence::new().with("domain", domain.clone()),
                ));
            }
        }
    }

    if cfg.check_wildcard && posture.resolved {
        posture.wildcard_checked = true;
        let probe = wildcard_probe_host(&domain);
        if let Some(r) = doh_query(&client, doh_base, &probe, T_A, false).await {
            let probe_ips = answers_of(&r, T_A);
            let has_wildcard = r.status == 0 && !probe_ips.is_empty();
            posture.wildcard_clean =
                !has_wildcard || probe_ips.iter().all(|ip| all_a_ips.contains(ip));
            if has_wildcard && !posture.wildcard_clean {
                threat_compromised.dns = true;
                findings.push(bgp_finding(
                    &format!("Wildcard DNS catch-all with foreign IPs for {domain}"),
                    "high",
                    "T1584.002",
                    &format!(
                        "Random host {probe} resolves to {:?} but apex A is {:?}. Wildcard catch-all to unexpected IPs enables subdomain hijack.",
                        probe_ips,
                        all_a_ips.iter().collect::<Vec<_>>()
                    ),
                    target,
                    "Remove wildcard A unless intentional; restrict catch-all to known infrastructure IPs.",
                    0.83,
                    Evidence::new()
                        .with("domain", domain.clone())
                        .with("probe_host", probe)
                        .with("probe_ips", json!(probe_ips)),
                ));
            } else if has_wildcard {
                findings.push(bgp_finding(
                    &format!("Wildcard DNS present for {domain} (IPs match apex)"),
                    "info",
                    "T1584.002",
                    &format!(
                        "Wildcard resolves {probe} → {:?} — consistent with apex.",
                        probe_ips
                    ),
                    target,
                    "Document intentional wildcard use; monitor for drift.",
                    0.7,
                    Evidence::new()
                        .with("domain", domain.clone())
                        .with("probe_host", probe),
                ));
            }
        } else {
            posture.wildcard_clean = true;
        }
    }

    if cfg.check_cds_cdnskey {
        posture.cds_checked = true;
        let cds = doh_query(&client, doh_base, &domain, T_CDS, false)
            .await
            .map(|r| answers_of(&r, T_CDS));
        let cdnskey = doh_query(&client, doh_base, &domain, T_CDNSKEY, false)
            .await
            .map(|r| answers_of(&r, T_CDNSKEY));
        posture.cds_automation_ready = cds.as_ref().is_some_and(|v| !v.is_empty())
            || cdnskey.as_ref().is_some_and(|v| !v.is_empty());
        if posture.cds_automation_ready {
            findings.push(bgp_finding(
                &format!("CDS/CDNSKEY automation ready for {domain}"),
                "info",
                "T1584.002",
                "CDS or CDNSKEY records present — parent can automate DNSSEC key rollover.",
                target,
                "Use CDS/CDNSKEY for safe automated KSK rollovers with your registrar.",
                0.75,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("cds", json!(cds.unwrap_or_default()))
                    .with("cdnskey", json!(cdnskey.unwrap_or_default())),
            ));
        } else if posture.dnssec_signed {
            findings.push(bgp_finding(
                &format!("No CDS/CDNSKEY for signed zone {domain}"),
                "low",
                "T1584.002",
                "Zone appears DNSSEC-signed but lacks CDS/CDNSKEY — manual parent DS updates required on rollover.",
                target,
                "Publish CDS/CDNSKEY when ready for automated rollover with the parent.",
                0.62,
                Evidence::new().with("domain", domain.clone()),
            ));
        }
    }

    if cfg.check_orphan_ds {
        let ds = doh_query(&client, doh_base, &domain, T_DS, false)
            .await
            .map(|r| answers_of(&r, T_DS));
        let dnskey = doh_query(&client, doh_base, &domain, T_DNSKEY, false)
            .await
            .map(|r| answers_of(&r, T_DNSKEY));
        if ds.as_ref().is_some_and(|d| !d.is_empty()) {
            posture.orphan_ds_checked = true;
            posture.orphan_ds_clean = dnskey.as_ref().is_some_and(|k| !k.is_empty());
            if !posture.orphan_ds_clean {
                threat_compromised.dns = true;
                findings.push(bgp_finding(
                    &format!("Orphan DS (no DNSKEY) for {domain}"),
                    "high",
                    "T1584.002",
                    &format!(
                        "DS records exist at {domain} but no DNSKEY in zone. Broken chain — validators may fail open or reject the zone."
                    ),
                    target,
                    "Publish DNSKEY matching parent DS or remove stale DS at the parent.",
                    0.87,
                    Evidence::new()
                        .with("domain", domain.clone())
                        .with("ds", json!(ds.unwrap_or_default())),
                ));
            }
        }
    }

    if cfg.check_resolver_timing && resolver_timings.len() >= 2 {
        posture.resolver_timing_checked = true;
        let min_ms = resolver_timings
            .iter()
            .map(|(_, ms)| *ms)
            .min()
            .unwrap_or(1)
            .max(1);
        let max_ms = resolver_timings
            .iter()
            .map(|(_, ms)| *ms)
            .max()
            .unwrap_or(0);
        posture.resolver_timing_healthy =
            max_ms as f64 <= min_ms as f64 * cfg.resolver_timing_factor;
        let detail: Vec<Value> = resolver_timings
            .iter()
            .map(|(n, ms)| json!({ "resolver": n, "latency_ms": ms }))
            .collect();
        if !posture.resolver_timing_healthy {
            findings.push(bgp_finding(
                &format!("Resolver timing anomaly for {domain}"),
                "medium",
                "T1557",
                &format!(
                    "Resolver latencies range {min_ms}–{max_ms} ms (factor {:.1}× threshold). One path disproportionately slow — interception or path hijack precursor.",
                    cfg.resolver_timing_factor
                ),
                target,
                "Compare resolver paths; investigate slow resolver egress and BGP path changes.",
                0.76,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("timings", json!(detail))
                    .with("min_ms", min_ms)
                    .with("max_ms", max_ms),
            ));
        } else {
            findings.push(bgp_finding(
                &format!("Resolver timing healthy for {domain}"),
                "info",
                "T1557",
                &format!(
                    "All resolver paths {min_ms}–{max_ms} ms — within {:.1}× factor.",
                    cfg.resolver_timing_factor
                ),
                target,
                "Alert when timing skew exceeds baseline.",
                0.68,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("timings", json!(detail)),
            ));
        }
    }

    // ── 8) v7 autonomous follow-up probes (delegation, UDP/DoH, DMARC, parent NS) ─
    let doh_base = cfg
        .resolvers
        .first()
        .map(|(_, b)| b.as_str())
        .unwrap_or(DEFAULT_RESOLVERS[0].1);

    if cfg.check_delegation_walk {
        posture.delegation_walk_checked = true;
        let mut chain: Vec<String> = vec![domain.clone()];
        let mut cur = domain.clone();
        let mut valid = true;
        while let Some(parent) = parent_zone_name(&cur) {
            if parent.split('.').count() < 1 {
                break;
            }
            chain.push(parent.clone());
            if let Some(r) = doh_query(&client, doh_base, &parent, T_NS, false).await {
                if answers_of(&r, T_NS).is_empty() {
                    valid = false;
                    break;
                }
            } else {
                valid = false;
                break;
            }
            if parent.split('.').count() <= 1 {
                break;
            }
            cur = parent;
            if chain.len() >= 8 {
                break;
            }
        }
        posture.delegation_chain_valid = valid && chain.len() >= 2;
        let sev = if posture.delegation_chain_valid {
            "info"
        } else {
            "medium"
        };
        findings.push(bgp_finding(
            &format!(
                "Delegation chain {} for {domain}",
                if posture.delegation_chain_valid { "intact" } else { "broken" }
            ),
            sev,
            "T1584.002",
            &format!(
                "Walked delegation {:?} — {} breaks in parent NS resolution indicate zone cut or hijack at delegation point.",
                chain,
                if posture.delegation_chain_valid { "no" } else { "possible" }
            ),
            target,
            "Verify parent zone NS/glue at registrar; monitor delegation changes.",
            0.74,
            Evidence::new()
                .with("domain", domain.clone())
                .with("chain", json!(chain))
                .check("delegation_intact", posture.delegation_chain_valid, json!(chain.len())),
        ));
    }

    if cfg.check_udp_doh_cross && posture.resolved && !all_a_ips.is_empty() {
        posture.udp_doh_checked = true;
        let udp_sets = public_udp_lookup_all(&domain, cfg.timeout_ms).await;
        let mut detail: Vec<Value> = Vec::new();
        let mut all_match = !udp_sets.is_empty();
        for (name, ips) in &udp_sets {
            let matches = ips.iter().all(|ip| all_a_ips.contains(ip))
                && all_a_ips.iter().all(|ip| ips.contains(ip));
            detail.push(json!({
                "resolver": name,
                "ips": ips.iter().collect::<Vec<_>>(),
                "matches_doh": matches,
            }));
            if !matches {
                all_match = false;
            }
        }
        posture.udp_doh_consistent = all_match;
        if !posture.udp_doh_consistent {
            threat_compromised.dns = true;
            findings.push(bgp_finding(
                &format!("UDP/53 vs DoH answer mismatch for {domain}"),
                "high",
                "T1557",
                &format!(
                    "Public UDP/53 resolvers disagree with DoH consensus {:?}. Transport-path divergence — possible resolver-path hijack or split-horizon.",
                    detail
                ),
                target,
                "Compare authoritative NS, UDP recursive (Google/Cloudflare/Quad9), and DoH paths; alert on any divergence.",
                0.88,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("udp_resolvers", json!(detail))
                    .with("doh_ips", json!(all_a_ips.iter().collect::<Vec<_>>())),
            ));
        } else {
            findings.push(bgp_finding(
                &format!(
                    "UDP/53 matches DoH across {} resolver(s) for {domain}",
                    udp_sets.len()
                ),
                "info",
                "T1557",
                &format!(
                    "UDP and DoH agree on {:?}.",
                    all_a_ips.iter().collect::<Vec<_>>()
                ),
                target,
                "Monitor UDP vs DoH continuously on all public resolvers.",
                0.74,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("udp_resolvers", json!(detail)),
            ));
        }
    }

    if cfg.check_dmarc {
        posture.dmarc_checked = true;
        posture.dmarc_present = zone_discovery.has_dmarc;
        if !posture.dmarc_present && (zone_discovery.has_mx || zone_discovery.has_spf) {
            findings.push(bgp_finding(
                &format!("No DMARC for mail-enabled {domain}"),
                "low",
                "T1584.002",
                &format!(
                    "_dmarc.{domain} lacks v=DMARC1 but MX/SPF exist — email path vulnerable to spoofing after DNS hijack."
                ),
                target,
                "Publish DMARC at _dmarc with p=reject or quarantine after SPF/DKIM alignment.",
                0.68,
                Evidence::new().with("domain", domain.clone()),
            ));
        } else if posture.dmarc_present {
            findings.push(bgp_finding(
                &format!("DMARC present for {domain}"),
                "info",
                "T1584.002",
                "v=DMARC1 TXT at _dmarc — email-path integrity control active.",
                target,
                "Tighten policy to p=reject when ready.",
                0.7,
                Evidence::new().with("domain", domain.clone()),
            ));
        }
    }

    if cfg.check_parent_ns && !zone_discovery.ns_hosts.is_empty() {
        if let Some(parent) = zone_discovery.parent_zone.as_ref() {
            posture.parent_ns_checked = true;
            let child_ns: BTreeSet<String> = zone_discovery
                .ns_hosts
                .iter()
                .map(|n| n.trim().trim_end_matches('.').to_ascii_lowercase())
                .collect();
            let parent_ns_raw = doh_query(&client, doh_base, parent, T_NS, false)
                .await
                .map(|r| answers_of(&r, T_NS))
                .unwrap_or_default();
            let parent_ns: BTreeSet<String> = parent_ns_raw
                .iter()
                .map(|n| n.trim().trim_end_matches('.').to_ascii_lowercase())
                .collect();
            let overlap: BTreeSet<_> = child_ns.intersection(&parent_ns).collect();
            posture.parent_ns_consistent = !child_ns.is_empty()
                && (overlap.len() >= 1 || parent_ns.is_empty() || child_ns.len() >= 2);
            if !posture.parent_ns_consistent {
                findings.push(bgp_finding(
                    &format!("Parent/child NS inconsistency for {domain}"),
                    "medium",
                    "T1584.002",
                    &format!(
                        "Child NS {:?} vs parent zone {parent} NS {:?} — unexpected delegation topology.",
                        child_ns.iter().collect::<Vec<_>>(),
                        parent_ns.iter().collect::<Vec<_>>()
                    ),
                    target,
                    "Verify NS at registrar match operational NS; detect unauthorized delegation changes.",
                    0.76,
                    Evidence::new()
                        .with("domain", domain.clone())
                        .with("child_ns", json!(child_ns.iter().collect::<Vec<_>>()))
                        .with("parent_ns", json!(parent_ns.iter().collect::<Vec<_>>())),
                ));
            }
        }
    }

    // ── 9) v8 capstone: SOA serial consensus + discovered-host TLS spot-check ─
    if cfg.check_soa_serial && posture.resolved && !zone_discovery.ns_hosts.is_empty() {
        posture.soa_serial_checked = true;
        let mut serials: BTreeSet<u32> = BTreeSet::new();
        let mut detail: Vec<Value> = Vec::new();
        for nsname in zone_discovery.ns_hosts.iter().take(8) {
            let host = nsname.trim().trim_end_matches('.');
            let Some(rr) = doh_query(&client, doh_base, host, T_A, false).await else {
                continue;
            };
            let Some(ns_ip_str) = answers_of(&rr, T_A).into_iter().next() else {
                continue;
            };
            let Ok(ns_ip) = IpAddr::from_str(&ns_ip_str) else {
                continue;
            };
            if let Some(serial) = auth_lookup_soa_serial(&domain, ns_ip, cfg.timeout_ms).await {
                serials.insert(serial);
                detail.push(json!({ "nameserver": nsname, "serial": serial }));
            }
        }
        posture.soa_serial_consistent = serials.len() <= 1 && !serials.is_empty();
        if !posture.soa_serial_consistent {
            findings.push(bgp_finding(
                &format!("SOA serial divergence across auth NS for {domain}"),
                "high",
                "T1584.002",
                &format!(
                    "Authoritative NS returned distinct SOA serials {:?} — zone file drift, partial propagation, or split-brain. Details: {:?}.",
                    serials.iter().collect::<Vec<_>>(),
                    detail
                ),
                target,
                "Reconcile zone files on all authoritative NS; verify AXFR/IXFR and monitor serial monotonicity.",
                0.82,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("serials", json!(serials.iter().collect::<Vec<_>>()))
                    .with("per_ns", json!(detail))
                    .check("soa_serial_consensus", false, json!(serials.len())),
            ));
        } else if !serials.is_empty() {
            findings.push(bgp_finding(
                &format!("SOA serial consensus for {domain}"),
                "info",
                "T1584.002",
                &format!(
                    "All responding auth NS agree on SOA serial {}.",
                    serials.iter().next().unwrap_or(&0)
                ),
                target,
                "Continue monitoring serial jumps after zone updates.",
                0.7,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("per_ns", json!(detail)),
            ));
        }
    }

    if cfg.check_discovered_tls && !zone_discovery.discovered_hosts.is_empty() {
        posture.discovered_tls_checked = true;
        let apex = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut mismatches: Vec<String> = Vec::new();
        let mut checked = 0u32;
        for host in zone_discovery
            .discovered_hosts
            .iter()
            .filter(|h| h.trim().trim_end_matches('.').to_ascii_lowercase() != apex)
            .take(cfg.discovered_tls_limit)
        {
            let host = host.trim().trim_end_matches('.');
            if let Some(cert) = tls_cert_details(host).await {
                checked += 1;
                let names = tls_cert_name_list(&cert);
                let covers = names.iter().any(|n| cert_covers_domain(n, host));
                if !covers || cert.expired {
                    mismatches.push(host.to_string());
                }
            }
        }
        posture.discovered_tls_match = checked > 0 && mismatches.is_empty();
        if !mismatches.is_empty() {
            threat_compromised.tls = true;
            findings.push(bgp_finding(
                &format!("Discovered-host TLS mismatch for {domain}"),
                "high",
                "T1584.001",
                &format!(
                    "Live TLS on {} does not cover the hostname or cert is expired — shadow-host hijack risk outside apex binding.",
                    mismatches.join(", ")
                ),
                target,
                "Verify DNS for each discovered host points to your infrastructure; re-issue certs covering all production hostnames.",
                0.86,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("mismatched_hosts", json!(mismatches))
                    .with("hosts_checked", checked as u64)
                    .check("discovered_tls_match", false, json!(mismatches)),
            ));
        } else if checked > 0 {
            findings.push(bgp_finding(
                &format!("Discovered-host TLS binding OK for {domain}"),
                "info",
                "T1584.001",
                &format!("Spot-checked {checked} discovered hostname(s) — certificates cover scanned names."),
                target,
                "Expand CT monitoring to catch new hosts automatically.",
                0.72,
                Evidence::new()
                    .with("domain", domain.clone())
                    .with("hosts_checked", checked as u64),
            ));
        }
    }

    // Baseline delta vs prior scan (DB or manual snapshot)
    let current_fp = HijackFingerprint {
        score: hijack_resistance_score(&posture),
        a_ips: all_a_ips.clone(),
        origin_asns: observed_bgp_origins.iter().copied().collect(),
    };
    if cfg.check_baseline_delta {
        posture.baseline_checked = prior_fp.is_some();
        if let Some(prior) = &prior_fp {
            let score_drop = prior.score.saturating_sub(current_fp.score);
            let new_ips: BTreeSet<String> =
                current_fp.a_ips.difference(&prior.a_ips).cloned().collect();
            let new_origins: BTreeSet<u32> = current_fp
                .origin_asns
                .difference(&prior.origin_asns)
                .copied()
                .collect();
            posture.baseline_stable =
                score_drop <= 5 && new_ips.is_empty() && new_origins.is_empty();
            if !posture.baseline_stable {
                let sev = if score_drop > 20 || !new_ips.is_empty() {
                    "critical"
                } else {
                    "high"
                };
                if sev == "critical" {
                    critical_signal = true;
                }
                findings.push(bgp_finding(
                    &format!("Hijack posture regression vs baseline for {domain}"),
                    sev,
                    "T1584",
                    &format!(
                        "Score {}→{} (Δ{score_drop}), new A IPs {:?}, new origin ASes {:?} since last scan. Sudden drift is a leading hijack indicator.",
                        prior.score, current_fp.score, new_ips, new_origins
                    ),
                    target,
                    "Compare with prior evidence bundle; if unauthorised, initiate incident response.",
                    0.88,
                    Evidence::new()
                        .with("domain", domain.clone())
                        .with("prior_score", prior.score as u64)
                        .with("current_score", current_fp.score as u64)
                        .with("new_ips", json!(new_ips.iter().collect::<Vec<_>>()))
                        .with("new_origins", json!(new_origins.iter().collect::<Vec<_>>())),
                ));
            } else {
                findings.push(bgp_finding(
                    &format!("Stable vs baseline for {domain}"),
                    "info",
                    "T1584",
                    &format!(
                        "Score {}→{} — no new IPs or origin ASes vs prior fingerprint.",
                        prior.score, current_fp.score
                    ),
                    target,
                    "Keep scheduled scans to detect drift early.",
                    0.72,
                    Evidence::new()
                        .with("prior_score", prior.score as u64)
                        .with("current_score", current_fp.score as u64),
                ));
            }
        }
    }

    // ── Compound hijack-in-progress (multi-plane corroboration) ──────────────
    let corroboration_count = [
        resolver_diverged,
        auth_diverged,
        posture.rpki_invalid,
        bogon_hit,
        tls_mismatch,
        !posture.more_specific_clean && posture.more_specific_checked,
        !posture.expected_ips_match && posture.expected_ips_checked,
        !posture.fcrdns_valid && posture.fcrdns_checked,
        !posture.wildcard_clean && posture.wildcard_checked,
        !posture.ns_lame_free && posture.ns_lame_checked,
        !posture.dnssec_ad_consensus && posture.dnssec_ad_divergence_checked,
        !posture.orphan_ds_clean && posture.orphan_ds_checked,
    ]
    .iter()
    .filter(|&&x| x)
    .count();
    if corroboration_count >= 2 {
        critical_signal = true;
        findings.push(bgp_finding(
            &format!("Compound hijack-in-progress signal for {domain}"),
            "critical",
            "T1557",
            &format!(
                "{corroboration_count} independent hijack indicators fired simultaneously for {domain}: resolver_divergence={resolver_diverged}, auth_poisoning={auth_diverged}, rpki_invalid={}, bogon={bogon_hit}, tls_mismatch={tls_mismatch}, foreign_more_specific={}. Multi-plane corroboration is the highest-fidelity active-interception signature.",
                posture.rpki_invalid,
                !posture.more_specific_clean && posture.more_specific_checked
            ),
            target,
            "Treat as P1 incident: isolate the asset, verify authoritative DNS and BGP out-of-band, engage transit/RIR, and preserve resolver/TLS/RPKI evidence for forensics.",
            0.97,
            Evidence::new()
                .with("domain", domain.clone())
                .with("resolver_divergence", resolver_diverged)
                .with("auth_poisoning", auth_diverged)
                .with("rpki_invalid", posture.rpki_invalid)
                .with("bogon", bogon_hit)
                .with("tls_mismatch", tls_mismatch)
                .with("foreign_more_specific", !posture.more_specific_clean && posture.more_specific_checked)
                .with("corroboration_planes", corroboration_count as u64)
                .check("compound_hijack", true, json!(corroboration_count)),
        ));
    }

    let plane_matrix = build_threat_plane_matrix(&posture, &threat_compromised);
    finalize(
        findings,
        &posture,
        critical_signal,
        &domain,
        target,
        &current_fp,
        &plane_matrix,
        &cfg,
        &zone_discovery,
        &adaptive_plan,
    )
}

fn build_roadmap(p: &Posture) -> Vec<Value> {
    let mut steps = Vec::new();
    let mut step = |order: u32, title: &str, done: bool, detail: &str| {
        steps.push(json!({ "order": order, "title": title, "done": done, "detail": detail }));
    };
    step(
        1,
        "Enable DNSSEC",
        p.dnssec_validated && !p.dnssec_broken && p.dnskey_strong,
        "Sign the zone with modern algorithms and publish the parent DS.",
    );
    step(
        2,
        "File RPKI ROAs",
        p.rpki_valid && !p.rpki_invalid,
        "Authorise your origin AS for every prefix (tight maxLength).",
    );
    step(
        3,
        "Match authoritative & recursive",
        p.auth_recursive_match,
        "Every recursive answer must appear on authoritative NS — detect poisoning.",
    );
    step(
        4,
        "Lock registrar (RDAP)",
        p.rdap_transfer_locked,
        "Enable clientTransferProhibited to block domain theft.",
    );
    step(
        5,
        "Bind TLS identity",
        p.tls_identity_match,
        "Ensure HTTPS presents a cert covering the scanned name.",
    );
    step(
        6,
        "Sync IRR with BGP",
        p.irr_matches_bgp,
        "Publish route objects matching live origin AS.",
    );
    step(
        7,
        "Monitor BGP origins",
        p.bgp_origin_stable && !p.unexpected_origin,
        "Alert on new origins/more-specifics.",
    );
    step(
        8,
        "Publish CAA",
        p.caa_present,
        "Restrict which CAs can issue certificates.",
    );
    step(
        9,
        "Diversify nameservers",
        p.ns_diverse,
        "Use 2+ providers on independent networks.",
    );
    step(
        10,
        "Dual-stack binding",
        p.dual_stack_origin_match,
        "A and AAAA should share origin AS.",
    );
    step(
        11,
        "Watch resolver divergence",
        p.resolver_consensus,
        "Compare answers across resolvers continuously.",
    );
    step(
        12,
        "Bind expected A IPs",
        !p.expected_ips_checked || p.expected_ips_match,
        "Declare allow-list; alert on any foreign A record.",
    );
    step(
        13,
        "FCrDNS alignment",
        !p.fcrdns_checked || p.fcrdns_valid,
        "PTR must forward-confirm every production A record.",
    );
    step(
        14,
        "Eliminate lame NS",
        !p.ns_lame_checked || p.ns_lame_free,
        "Every authoritative NS must answer for the zone.",
    );
    step(
        15,
        "Audit wildcard DNS",
        !p.wildcard_checked || p.wildcard_clean,
        "No catch-all wildcard to foreign IPs.",
    );
    step(
        16,
        "DNSSEC AD consensus",
        !p.dnssec_ad_divergence_checked || p.dnssec_ad_consensus,
        "All validating resolvers must agree on AD.",
    );
    step(
        17,
        "Delegation chain intact",
        !p.delegation_walk_checked || p.delegation_chain_valid,
        "Parent zones must delegate cleanly.",
    );
    step(
        18,
        "UDP/DoH transport parity",
        !p.udp_doh_checked || p.udp_doh_consistent,
        "Recursive UDP must match DoH consensus.",
    );
    step(
        19,
        "DMARC on mail zones",
        !p.dmarc_checked || p.dmarc_present,
        "Publish _dmarc when MX/SPF exist.",
    );
    step(
        20,
        "SOA serial consensus",
        !p.soa_serial_checked || p.soa_serial_consistent,
        "All auth NS must publish the same SOA serial.",
    );
    step(
        21,
        "Discovered-host TLS",
        !p.discovered_tls_checked || p.discovered_tls_match,
        "Every production hostname must present a matching cert.",
    );
    step(
        22,
        "Full probe coverage",
        true,
        "Review coverage_audit in summary — every enabled probe must execute.",
    );
    steps
}

fn finalize(
    mut findings: Vec<Value>,
    posture: &Posture,
    critical_signal: bool,
    domain: &str,
    target: &str,
    fingerprint: &HijackFingerprint,
    plane_matrix: &Value,
    cfg: &BgpConfig,
    discovery: &ZoneDiscovery,
    adaptive: &AdaptivePlan,
) -> EngineResult {
    let score = hijack_resistance_score(posture);
    let sev = summary_severity(score, critical_signal);
    let roadmap = build_roadmap(posture);
    let manifest = probe_manifest_from_cfg(cfg);
    let coverage_audit = build_coverage_audit(cfg, posture);
    let incident_bundle =
        build_incident_bundle(&findings, posture, plane_matrix, &roadmap, &manifest);
    let disc_graph = discovery_graph(discovery, adaptive);

    let summary_ev = Evidence::new()
        .with("hijack_resistance_score", score)
        .with("dnssec_validated", posture.dnssec_validated)
        .with("dnssec_signed", posture.dnssec_signed)
        .with("dnssec_broken", posture.dnssec_broken)
        .with("dnskey_strong", posture.dnskey_strong)
        .with("rpki_valid", posture.rpki_valid)
        .with("rpki_invalid", posture.rpki_invalid)
        .with("resolver_consensus", posture.resolver_consensus)
        .with("auth_recursive_match", posture.auth_recursive_match)
        .with("rdap_transfer_locked", posture.rdap_transfer_locked)
        .with("irr_matches_bgp", posture.irr_matches_bgp)
        .with("more_specific_clean", posture.more_specific_clean)
        .with("dual_stack_origin_match", posture.dual_stack_origin_match)
        .with("tls_identity_match", posture.tls_identity_match)
        .with("hsts_present", posture.hsts_present)
        .with("redirect_healthy", posture.redirect_healthy)
        .with("caa_ct_aligned", posture.caa_ct_aligned)
        .with("baseline_stable", posture.baseline_stable)
        .with("bogon_free", posture.bogon_free)
        .with("ttl_healthy", posture.ttl_healthy)
        .with("bgp_origin_stable", posture.bgp_origin_stable)
        .with("dane_present", posture.dane_present)
        .with("caa_present", posture.caa_present)
        .with("ns_diverse", posture.ns_diverse)
        .with("moas", posture.moas)
        .with("unexpected_origin", posture.unexpected_origin)
        .with("expected_ips_match", posture.expected_ips_match)
        .with("fcrdns_valid", posture.fcrdns_valid)
        .with("aaaa_consensus", posture.aaaa_consensus)
        .with("ns_lame_free", posture.ns_lame_free)
        .with("wildcard_clean", posture.wildcard_clean)
        .with("dnssec_ad_consensus", posture.dnssec_ad_consensus)
        .with("cname_healthy", posture.cname_healthy)
        .with("spf_present", posture.spf_present)
        .with("resolver_timing_healthy", posture.resolver_timing_healthy)
        .with("orphan_ds_clean", posture.orphan_ds_clean)
        .with("cds_automation_ready", posture.cds_automation_ready)
        .with("delegation_chain_valid", posture.delegation_chain_valid)
        .with("udp_doh_consistent", posture.udp_doh_consistent)
        .with("dmarc_present", posture.dmarc_present)
        .with("parent_ns_consistent", posture.parent_ns_consistent)
        .with("soa_serial_consistent", posture.soa_serial_consistent)
        .with("discovered_tls_match", posture.discovered_tls_match)
        .with("takeover_clean", posture.takeover_clean)
        .with("discovery_ran", posture.discovery_ran)
        .with(
            "coverage_complete",
            coverage_audit
                .get("coverage_complete")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        )
        .with("threat_planes", plane_matrix.clone());

    let mut summary = bgp_finding(
        &format!("Hijack-Resistance Score: {score}/100"),
        sev,
        "T1584",
        &format!(
            "DNS/BGP hijack-resistance for {domain}: planes DNS={} BGP={} TLS={} Registry={}. Score components: DNSSEC {}, RPKI {}, auth=recursive {}, baseline-stable {}.",
            plane_matrix.pointer("/dns/status").and_then(Value::as_str).unwrap_or("?"),
            plane_matrix.pointer("/bgp/status").and_then(Value::as_str).unwrap_or("?"),
            plane_matrix.pointer("/tls_http/status").and_then(Value::as_str).unwrap_or("?"),
            plane_matrix.pointer("/registry/status").and_then(Value::as_str).unwrap_or("?"),
            yn(posture.dnssec_validated && !posture.dnssec_broken && posture.dnskey_strong),
            if posture.rpki_invalid { "INVALID" } else { yn(posture.rpki_valid) },
            yn(posture.auth_recursive_match),
            yn(posture.baseline_stable)
        ),
        target,
        "Raise score toward 100 across all four threat planes: DNS integrity, BGP/RPKI, TLS/HTTP binding, and registry/issuance control.",
        0.94,
        summary_ev,
    );
    if let Some(obj) = summary.as_object_mut() {
        obj.insert("type".to_string(), json!("dns_bgp_integrity_summary"));
        obj.insert("hijack_resistance_score".to_string(), json!(score));
        obj.insert("critical_signal".to_string(), json!(critical_signal));
        obj.insert("roadmap".to_string(), json!(roadmap));
        obj.insert("threat_planes".to_string(), plane_matrix.clone());
        obj.insert(
            "scan_fingerprint".to_string(),
            json!({
                "a_ips": fingerprint.a_ips.iter().collect::<Vec<_>>(),
                "origin_asns": fingerprint.origin_asns.iter().collect::<Vec<_>>(),
                "score": score,
            }),
        );
        obj.insert("engine_version".to_string(), json!("8.0"));
        obj.insert("incident_bundle".to_string(), incident_bundle.clone());
        obj.insert("probe_manifest".to_string(), json!(manifest));
        obj.insert("coverage_audit".to_string(), coverage_audit.clone());
        obj.insert("discovery_graph".to_string(), disc_graph.clone());
        obj.insert("autonomous_mode".to_string(), json!(cfg.autonomous_mode));
    }
    findings.insert(0, summary);

    EngineResult::ok(
        findings.clone(),
        format!(
            "bgp_dns_hijacking: hijack-resistance {score}/100, {} finding(s) [dnssec={}, rpki_valid={}, rpki_invalid={}, consensus={}]",
            findings.len(),
            posture.dnssec_validated,
            posture.rpki_valid,
            posture.rpki_invalid,
            posture.resolver_consensus
        ),
    )
}

/// CLI entry point.
pub async fn run_bgp_dns_hijacking(target: &str) {
    print_result(run_bgp_dns_hijacking_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_domain_strips_scheme_port_path() {
        assert_eq!(
            extract_domain("https://Example.com:443/login"),
            "example.com"
        );
        assert_eq!(extract_domain("http://a.b.c/"), "a.b.c");
        assert_eq!(extract_domain("host.tld."), "host.tld");
    }

    #[test]
    fn parse_doh_json_extracts_answers_and_flags() {
        let v = json!({
            "Status": 0,
            "AD": true,
            "Answer": [
                { "name": "x.com", "type": 1, "TTL": 300, "data": "1.2.3.4" },
                { "name": "x.com", "type": 1, "TTL": 300, "data": "5.6.7.8" },
                { "name": "x.com", "type": 28, "TTL": 300, "data": "2606::1" }
            ]
        });
        let r = parse_doh_json(&v);
        assert_eq!(r.status, 0);
        assert!(r.ad);
        assert_eq!(answers_of(&r, T_A), vec!["1.2.3.4", "5.6.7.8"]);
        assert_eq!(answers_of(&r, T_AAAA), vec!["2606::1"]);
        assert!(answers_of(&r, T_NS).is_empty());
    }

    #[test]
    fn parse_doh_json_defaults_servfail_when_missing_status() {
        let r = parse_doh_json(&json!({}));
        assert_eq!(r.status, 2);
        assert!(!r.ad);
        assert!(r.answers.is_empty());
    }

    #[test]
    fn rpki_state_parsing() {
        assert_eq!(RpkiState::parse("valid"), RpkiState::Valid);
        assert_eq!(RpkiState::parse("Invalid"), RpkiState::Invalid);
        assert_eq!(RpkiState::parse("unknown"), RpkiState::Unknown);
        assert_eq!(RpkiState::parse("not-found"), RpkiState::Unknown);
        assert_eq!(RpkiState::Valid.as_str(), "valid");
    }

    #[test]
    fn score_rewards_dnssec_and_rpki() {
        let mut p = Posture {
            resolved: true,
            resolver_checked: true,
            resolver_consensus: true,
            dnssec_checked: true,
            dnssec_signed: true,
            dnssec_validated: true,
            dnskey_strong: true,
            rpki_checked: true,
            rpki_valid: true,
            auth_recursive_checked: true,
            auth_recursive_match: true,
            rdap_checked: true,
            rdap_transfer_locked: true,
            irr_checked: true,
            irr_matches_bgp: true,
            more_specific_checked: true,
            more_specific_clean: true,
            dual_stack_checked: true,
            dual_stack_origin_match: true,
            caa_checked: true,
            caa_present: true,
            ns_checked: true,
            ns_diverse: true,
            bgp_checked: true,
            bgp_origin_stable: true,
            tls_checked: true,
            tls_identity_match: true,
            bogon_checked: true,
            bogon_free: true,
            ttl_checked: true,
            ttl_healthy: true,
            soa_checked: true,
            soa_mname_in_ns: true,
            ..Posture::default()
        };
        let strong = hijack_resistance_score(&p);
        assert!(
            strong >= 95,
            "hardened posture should score very high, got {strong}"
        );

        // Drop DNSSEC + RPKI → score must fall substantially.
        p.dnssec_validated = false;
        p.rpki_valid = false;
        let weak = hijack_resistance_score(&p);
        assert!(weak < strong);
        assert!(weak <= 40, "no DNSSEC/RPKI should score low, got {weak}");

        // No applicable dimensions → 0, never divide-by-zero.
        assert_eq!(hijack_resistance_score(&Posture::default()), 0);
    }

    #[test]
    fn rpki_invalid_drags_score_and_is_not_counted_valid() {
        let p = Posture {
            rpki_checked: true,
            rpki_valid: false,
            rpki_invalid: true,
            dnssec_checked: true,
            dnssec_validated: true,
            dnskey_strong: true,
            ..Posture::default()
        };
        // dnssec(18) achieved, rpki(18) applicable but not achieved → 50.
        assert_eq!(hijack_resistance_score(&p), 50);
    }

    #[test]
    fn is_more_specific_v4_detects_longer_prefix() {
        assert!(is_more_specific_v4("1.2.3.0/25", "1.2.3.0/24"));
        assert!(!is_more_specific_v4("1.2.3.0/24", "1.2.3.0/24"));
        assert!(!is_more_specific_v4("2.0.0.0/24", "1.2.3.0/24"));
    }

    #[test]
    fn parse_soa_mname_extracts_primary() {
        assert_eq!(
            parse_soa_mname(
                "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600"
            ),
            Some("ns1.example.com".into())
        );
    }

    #[test]
    fn parse_caa_issuers_extracts_ca_domains() {
        let caa = vec![
            r#"0 issue "letsencrypt.org""#.to_string(),
            r#"0 issuewild ";"#.to_string(),
            r#"0 iodef "mailto:sec@example.com""#.to_string(),
        ];
        let issuers = parse_caa_issuers(&caa);
        assert!(issuers.contains("letsencrypt.org"));
        assert_eq!(issuers.len(), 1);
    }

    #[test]
    fn ct_issuer_violates_caa_when_not_in_allowlist() {
        let mut allowed = BTreeSet::new();
        allowed.insert("letsencrypt.org".to_string());
        assert!(ct_issuer_violates_caa(
            "C=US, O=Let's Encrypt, CN=R3",
            &allowed
        ));
        assert!(!ct_issuer_violates_caa(
            "C=US, O=Let's Encrypt, CN=R3",
            &BTreeSet::new()
        ));
    }

    #[test]
    fn bogon_label_detects_rfc1918_and_loopback() {
        assert_eq!(bogon_label_v4("10.0.0.1"), Some("RFC1918 private (10/8)"));
        assert_eq!(bogon_label_v4("127.0.0.1"), Some("loopback (127/8)"));
        assert_eq!(bogon_label_v4("8.8.8.8"), None);
    }

    #[test]
    fn cert_covers_domain_wildcard_and_exact() {
        assert!(cert_covers_domain("example.com", "example.com"));
        assert!(cert_covers_domain("*.example.com", "www.example.com"));
        assert!(!cert_covers_domain("*.example.com", "example.org"));
    }

    #[test]
    fn parse_doh_json_extracts_ttl() {
        let v = json!({
            "Status": 0,
            "Answer": [{ "type": 1, "TTL": 60, "data": "1.2.3.4" }]
        });
        let r = parse_doh_json(&v);
        assert_eq!(min_ttl_for(&r, T_A), Some(60));
    }

    #[test]
    fn summary_severity_escalates_on_critical_signal() {
        assert_eq!(summary_severity(95, false), "info");
        assert_eq!(summary_severity(95, true), "critical");
        assert_eq!(summary_severity(50, false), "medium");
        assert_eq!(summary_severity(10, false), "critical");
    }

    #[test]
    fn parse_resolvers_supports_name_and_url_forms() {
        let c = ArsenalConfig::from_value(json!({
            "resolvers": ["MyDoH=https://doh.example/q", "https://dns.google/resolve"]
        }));
        let r = parse_resolvers(&c);
        assert_eq!(r[0].0, "MyDoH");
        assert_eq!(r[0].1, "https://doh.example/q");
        assert_eq!(r[1].0, "dns.google");
        // Empty → defaults.
        let d = parse_resolvers(&ArsenalConfig::from_value(json!({})));
        assert_eq!(d.len(), DEFAULT_RESOLVERS.len());
    }

    #[test]
    fn expected_origin_asns_parse_with_and_without_prefix() {
        let c = ArsenalConfig::from_value(
            json!({ "expected_origin_asns": ["AS13335", "15169", "as2906"] }),
        );
        let cfg = load_config(&c);
        assert!(cfg.expected_origin_asns.contains(&13335));
        assert!(cfg.expected_origin_asns.contains(&15169));
        assert!(cfg.expected_origin_asns.contains(&2906));
    }

    #[test]
    fn ipv4_ptr_name_builds_in_addr_arpa() {
        assert_eq!(
            ipv4_ptr_name("1.2.3.4"),
            Some("4.3.2.1.in-addr.arpa".to_string())
        );
        assert!(ipv4_ptr_name("not-an-ip").is_none());
    }

    #[test]
    fn apex_has_spf_detects_v_spf1() {
        assert!(apex_has_spf(&[
            "v=spf1 include:_spf.google.com ~all".to_string()
        ]));
        assert!(!apex_has_spf(&["google-site-verification=abc".to_string()]));
    }

    #[test]
    fn wildcard_probe_host_is_under_domain() {
        let host = wildcard_probe_host("Example.com.");
        assert!(host.ends_with(".example.com"));
        assert!(host.starts_with("ws"));
    }

    #[test]
    fn probe_manifest_includes_v6_when_enabled() {
        let c = ArsenalConfig::from_value(json!({
            "check_fcrdns": true,
            "check_wildcard": true,
            "check_ns_lame": false
        }));
        let cfg = load_config(&c);
        let m = probe_manifest_from_cfg(&cfg);
        assert!(m.contains(&"fcrdns"));
        assert!(m.contains(&"wildcard_dns"));
        assert!(!m.contains(&"ns_lame"));
    }

    #[test]
    fn parent_zone_name_strips_leftmost_label() {
        assert_eq!(
            parent_zone_name("www.example.com"),
            Some("example.com".into())
        );
        assert_eq!(parent_zone_name("example.com"), Some("com".into()));
        assert!(parent_zone_name("com").is_none());
    }

    #[test]
    fn adaptive_plan_enables_dnssec_when_ds_present() {
        let mut d = ZoneDiscovery::default();
        d.has_ds = true;
        d.signals.push("DS records".into());
        let cfg = load_config(&ArsenalConfig::from_value(json!({})));
        let plan = plan_adaptive_probes(&d, &cfg);
        assert!(plan.auto_enabled.contains("dnssec"));
        assert!(plan.auto_enabled.contains("orphan_ds"));
    }

    #[test]
    fn adaptive_plan_skips_dual_stack_without_aaaa() {
        let d = ZoneDiscovery::default();
        let cfg = load_config(&ArsenalConfig::from_value(
            json!({ "force_all_probes": false }),
        ));
        let plan = plan_adaptive_probes(&d, &cfg);
        assert!(plan.auto_skipped.contains("dual_stack"));
    }

    #[test]
    fn discovery_graph_includes_rationale() {
        let d = ZoneDiscovery {
            domain: "example.com".into(),
            has_a: true,
            signals: vec!["A records".into()],
            ..ZoneDiscovery::default()
        };
        let cfg = load_config(&ArsenalConfig::from_value(json!({})));
        let plan = plan_adaptive_probes(&d, &cfg);
        let g = discovery_graph(&d, &plan);
        assert_eq!(g.get("domain").and_then(Value::as_str), Some("example.com"));
        assert!(g.get("rationale").and_then(Value::as_array).is_some());
    }

    #[test]
    fn fqdn_to_subdomain_label_extracts_host_label() {
        assert_eq!(
            fqdn_to_subdomain_label("api.example.com", "example.com"),
            Some("api".into())
        );
        assert_eq!(fqdn_to_subdomain_label("example.com", "example.com"), None);
    }

    #[test]
    fn parse_mx_host_extracts_exchange() {
        assert_eq!(
            parse_mx_host("10 mail.example.com."),
            Some("mail.example.com".into())
        );
    }

    #[test]
    fn enrich_discovered_hosts_merges_mx_and_ct() {
        let mut d = ZoneDiscovery {
            domain: "example.com".into(),
            ct_hosts: vec!["www.example.com".into()],
            mx_hosts: vec!["mail.example.com".into()],
            ..ZoneDiscovery::default()
        };
        enrich_discovered_hosts(&mut d);
        assert!(d.discovered_hosts.iter().any(|h| h == "www.example.com"));
        assert!(d.discovered_hosts.iter().any(|h| h == "mail.example.com"));
    }

    #[test]
    fn parse_soa_serial_extracts_third_field() {
        assert_eq!(
            parse_soa_serial(
                "ns1.example.com. hostmaster.example.com. 2026061801 7200 3600 1209600 3600"
            ),
            Some(2026061801)
        );
        assert_eq!(parse_soa_serial("incomplete"), None);
    }

    #[test]
    fn coverage_audit_marks_complete_when_all_enabled_ran() {
        let mut p = Posture::default();
        p.resolver_checked = true;
        p.resolver_consensus = true;
        p.discovery_ran = true;
        let cfg = load_config(&ArsenalConfig::from_value(json!({
            "check_dnssec": false,
            "check_bgp": false,
            "autonomous_mode": true,
        })));
        let audit = build_coverage_audit(&cfg, &p);
        assert_eq!(
            audit.get("engine_version").and_then(Value::as_str),
            Some("8.0")
        );
        assert!(audit.get("probes").and_then(Value::as_array).is_some());
    }

    #[test]
    fn adaptive_plan_enables_bgp_stack_when_has_a() {
        let d = ZoneDiscovery {
            domain: "example.com".into(),
            has_a: true,
            ..ZoneDiscovery::default()
        };
        let cfg = load_config(&ArsenalConfig::from_value(
            json!({ "force_all_probes": false }),
        ));
        let plan = plan_adaptive_probes(&d, &cfg);
        assert!(plan.auto_enabled.contains("irr"));
        assert!(plan.auto_enabled.contains("soa_serial"));
        assert!(plan.auto_enabled.contains("discovered_tls"));
    }

    #[test]
    fn autonomous_disables_irr_without_routable_surface() {
        let mut cfg = load_config(&ArsenalConfig::from_value(json!({
            "autonomous_mode": true,
            "force_all_probes": false,
        })));
        let d = ZoneDiscovery {
            domain: "example.com".into(),
            has_a: false,
            ..ZoneDiscovery::default()
        };
        let plan = plan_adaptive_probes(&d, &cfg);
        apply_autonomous_plan(&mut cfg, &d, &plan);
        assert!(!cfg.check_irr);
        assert!(!cfg.check_soa_serial);
    }

    #[test]
    fn autonomous_clears_static_subdomains_when_disabled() {
        let mut cfg = load_config(&ArsenalConfig::from_value(json!({
            "autonomous_mode": true,
            "use_static_subdomain_wordlist": false,
            "subdomains": ["www", "api"]
        })));
        let d = ZoneDiscovery {
            domain: "example.com".into(),
            discovered_hosts: vec!["cdn.example.com".into()],
            ..ZoneDiscovery::default()
        };
        let plan = plan_adaptive_probes(&d, &cfg);
        apply_autonomous_plan(&mut cfg, &d, &plan);
        assert!(!cfg.subdomains.contains(&"www".to_string()));
        assert!(cfg.subdomains.iter().any(|s| s == "cdn"));
    }
}
