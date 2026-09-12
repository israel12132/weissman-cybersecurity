//! **Adversary Gap Mirror** — what a criminal operator can learn about an authorized
//! target from *legal clearnet defender feeds*, fused with safe in-scope exposure probes.
//!
//! Live-only. Never Tor, never marketplaces, never credential dumps, never exploit PoCs.
//! Empty feeds → informational “queried, zero hits” evidence — never invented victims.
//!
//! Public sources (no paid IntelX required):
//! - ransomware.live v2 victim search (PRO when `RANSOMWARE_LIVE_API_KEY` is set)
//! - RansomLook leak-blog *posts catalog* (`GET /api/posts` only — never `/api/search`)
//! - abuse.ch ThreatFox (`search_ioc` with free Auth-Key, else recent domain export)
//! - abuse.ch URLhaus (host API with Auth-Key, else public hostfile)
//! - Have I Been Pwned public breach *catalog* (`GET /breaches?Domain=`, no key)
//! - urlscan.io public search (`page.apexDomain:`, optional `URLSCAN_API_KEY`)
//!
//! Exposure fusion (authorized RoE only): TCP connect of common remote-access ports and
//! HTTP product tokens (VPN/OWA/Citrix). Underground USD bands are cited from *public*
//! industry reporting and emitted only when live evidence exists.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, extract_host, finding, http_client, http_get, http_get_with_headers,
    http_get_with_headers_max, http_post_bytes_with_headers, http_post_json_with_headers, tcp_scan,
};
use crate::engine_result::EngineResult;
use serde_json::{json, Value};

pub const ENGINE_ID: &str = "adversary_gap_mirror";
const MITRE: &str = "T1597";
const UA: &str = "WeissmanCybersecurity/1.0 (adversary-gap-mirror; authorized-assessment)";
/// RansomLook `/api/posts` is ~110 KiB; default probe cap is 64 KiB.
const INTEL_BODY_MAX: usize = 262_144;

/// Remote-access ports initial-access brokers historically list (public reporting).
pub const IAB_PORTS: &[u16] = &[
    22, 3389, 445, 5985, 5986, 443, 8443, 10443, 4443, 9443, 5900,
];

const VPN_TOKENS: &[&str] = &[
    "citrix",
    "netscaler",
    "globalprotect",
    "global protect",
    "fortigate",
    "fortinet",
    "pulse secure",
    "anyconnect",
    "sonicwall",
    "rdweb",
    "rd gateway",
    "outlook web",
    "owa",
    "remote desktop",
];

/// Second-level suffixes common for Israeli + other multi-part ccTLDs.
const MULTI_PART_SUFFIXES: &[&str] = &[
    "co.il", "org.il", "ac.il", "gov.il", "net.il", "muni.il", "k12.il", "co.uk", "org.uk",
    "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "com.br",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RansomHit {
    pub victim: String,
    pub group: String,
    pub website: String,
    pub attack_date: String,
    pub infostealer_employees: i64,
    pub infostealer_users: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RansomLookHit {
    pub title: String,
    pub group: String,
    pub discovered: String,
    pub site: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlscanHit {
    pub id: String,
    pub page_domain: String,
    pub task_url: String,
    pub total: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocHit {
    pub ioc: String,
    pub threat_type: String,
    pub malware: String,
    pub confidence: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreachCatalogHit {
    pub name: String,
    pub domain: String,
    pub breach_date: String,
    pub pwn_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IabQuote {
    pub label: &'static str,
    pub usd_low: u32,
    pub usd_high: u32,
    pub citation: &'static str,
    pub next_engines: &'static [&'static str],
}

fn env_nonempty(keys: &[&str]) -> String {
    for k in keys {
        if let Ok(v) = std::env::var(k) {
            let t = v.trim().to_string();
            if !t.is_empty() {
                return t;
            }
        }
    }
    String::new()
}

pub(crate) fn abusech_auth_key() -> String {
    env_nonempty(&[
        "ABUSECH_AUTH_KEY",
        "ABUSECH_API_KEY",
        "THREATFOX_AUTH_KEY",
        "URLHAUS_AUTH_KEY",
    ])
}

fn ransomware_live_api_key() -> String {
    env_nonempty(&["RANSOMWARE_LIVE_API_KEY", "RANSOMWARE_LIVE_PRO_KEY"])
}

fn urlscan_api_key() -> String {
    env_nonempty(&["URLSCAN_API_KEY", "URLSCAN_APIKEY"])
}

fn pbool(params: &Value, key: &str, default: bool) -> bool {
    params
        .get(key)
        .and_then(|v| {
            v.as_bool()
                .or_else(|| v.as_str().map(|s| s == "true" || s == "1"))
        })
        .unwrap_or(default)
}

/// Registrable apex, including `example.co.il`.
#[must_use]
pub fn registrable_apex(host: &str) -> String {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return h;
    }
    for suf in MULTI_PART_SUFFIXES {
        if h == *suf {
            return h;
        }
        let dotted = format!(".{suf}");
        if let Some(rest) = h.strip_suffix(&dotted) {
            let label = rest.rsplit('.').next().unwrap_or(rest);
            if !label.is_empty() {
                return format!("{label}.{suf}");
            }
        }
    }
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        h
    }
}

fn strip_authority(s: &str) -> &str {
    let s = s.rsplit('@').next().unwrap_or(s);
    s.split(':').next().unwrap_or(s)
}

fn host_matches_needle(host: &str, needle: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let needle = needle
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() || needle.is_empty() {
        return false;
    }
    let host = strip_authority(&host);
    let needle = strip_authority(&needle);
    let apex = registrable_apex(host);
    let needle_apex = registrable_apex(needle);
    needle == host
        || needle == apex
        || needle_apex == apex
        || needle.ends_with(&format!(".{apex}"))
        || host.ends_with(&format!(".{needle}"))
}

const GENERIC_VICTIM_STEMS: &[&str] = &[
    "bank", "shop", "mail", "news", "corp", "test", "info", "cloud", "host", "data", "home", "www",
    "online", "group", "inc", "ltd", "the",
];

fn victim_mentions_org(victim: &str, host: &str) -> bool {
    if host_matches_needle(host, victim) {
        return true;
    }
    let v = victim.to_ascii_lowercase();
    let apex = registrable_apex(host);
    let stem = apex.split('.').next().unwrap_or(&apex);
    if stem.len() < 4 || GENERIC_VICTIM_STEMS.contains(&stem) {
        return false;
    }
    v.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == stem)
}

fn enrich(engine: &str, mut f: Value, evidence: Value) -> Value {
    if let Some(o) = f.as_object_mut() {
        o.insert("evidence".into(), evidence);
        o.insert("source".into(), json!(engine));
        o.insert("engine".into(), json!(engine));
    }
    f
}

/// Parse ransomware.live JSON (array or `{ "victims": [...] }` / `{ "data": [...] }`).
#[must_use]
pub fn parse_ransomware_live(body: &str, host: &str) -> Vec<RansomHit> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let rows = v
        .as_array()
        .or_else(|| v.get("victims").and_then(Value::as_array))
        .or_else(|| v.get("data").and_then(Value::as_array))
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for row in rows {
        let victim = row
            .get("victim")
            .or_else(|| row.get("victimname"))
            .or_else(|| row.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let website = row
            .get("website")
            .or_else(|| row.get("domain"))
            .or_else(|| row.get("url"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !host_matches_needle(host, &website) && !victim_mentions_org(&victim, host) {
            continue;
        }
        let (infostealer_employees, infostealer_users) = match row.get("infostealer") {
            Some(Value::Object(o)) => (
                o.get("employees").and_then(Value::as_i64).unwrap_or(0),
                o.get("users").and_then(Value::as_i64).unwrap_or(0),
            ),
            _ => (0, 0),
        };
        out.push(RansomHit {
            victim,
            group: row
                .get("group")
                .or_else(|| row.get("group_name"))
                .or_else(|| row.get("gang"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            website,
            attack_date: row
                .get("attackdate")
                .or_else(|| row.get("attack_date"))
                .or_else(|| row.get("discovered"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            infostealer_employees,
            infostealer_users,
        });
        if out.len() >= 20 {
            break;
        }
    }
    out
}

#[must_use]
pub fn parse_threatfox(body: &str) -> Vec<IocHit> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let status = v.get("query_status").and_then(Value::as_str).unwrap_or("");
    if status != "ok" && status != "no_result" && !status.is_empty() && status != "ok" {
        // still try to parse data if present
    }
    let rows = v
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for row in rows {
        let ioc = row
            .get("ioc")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if ioc.is_empty() {
            continue;
        }
        out.push(IocHit {
            ioc,
            threat_type: row
                .get("threat_type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            malware: row
                .get("malware")
                .or_else(|| row.get("malware_printable"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            confidence: row
                .get("confidence_level")
                .and_then(Value::as_i64)
                .unwrap_or(0),
        });
        if out.len() >= 20 {
            break;
        }
    }
    out
}

#[must_use]
pub fn parse_urlhaus_host(body: &str) -> usize {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return 0;
    };
    if v.get("query_status").and_then(Value::as_str) == Some("no_results") {
        return 0;
    }
    v.get("urls")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .or_else(|| {
            v.get("url_count")
                .and_then(Value::as_u64)
                .map(|n| n as usize)
        })
        .unwrap_or(0)
}

/// Parse ThreatFox *export* JSON (`{ "id": [ { ioc_value, ... } ] }`) filtered to host.
#[must_use]
pub fn parse_threatfox_export(body: &str, host: &str) -> Vec<IocHit> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let Some(map) = v.as_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for arr in map.values() {
        let Some(rows) = arr.as_array() else {
            continue;
        };
        for row in rows {
            let ioc = row
                .get("ioc_value")
                .or_else(|| row.get("ioc"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if ioc.is_empty() || !host_matches_needle(host, &ioc) {
                continue;
            }
            out.push(IocHit {
                ioc,
                threat_type: row
                    .get("threat_type")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                malware: row
                    .get("malware_printable")
                    .or_else(|| row.get("malware"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                confidence: row
                    .get("confidence_level")
                    .and_then(Value::as_i64)
                    .unwrap_or(50),
            });
            if out.len() >= 20 {
                return out;
            }
        }
    }
    out
}

/// Count hosts in the public URLhaus hostfile that match the target.
#[must_use]
pub fn parse_urlhaus_hostfile(body: &str, host: &str) -> usize {
    let mut n = 0usize;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name = line.split_whitespace().nth(1).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        if host_matches_needle(host, name) {
            n += 1;
            if n >= 20 {
                break;
            }
        }
    }
    n
}

#[must_use]
pub fn parse_hibp_breaches(body: &str, host: &str) -> Vec<BreachCatalogHit> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let rows = v.as_array().cloned().unwrap_or_default();
    let mut out = Vec::new();
    for row in rows {
        let domain = row
            .get("Domain")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if domain.is_empty() || !host_matches_needle(host, &domain) {
            continue;
        }
        out.push(BreachCatalogHit {
            name: row
                .get("Name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            domain,
            breach_date: row
                .get("BreachDate")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            pwn_count: row.get("PwnCount").and_then(Value::as_i64).unwrap_or(0),
        });
        if out.len() >= 20 {
            break;
        }
    }
    out
}

/// v2 returns HTTP 404 JSON `{ "error": "No victims found for keyword '…'." }` when the
/// keyword has zero rows — that is a live zero-hit, not a feed outage.
#[must_use]
pub fn ransomware_live_no_victims(status: u16, body: &str) -> bool {
    if status != 404 {
        return false;
    }
    let lower = body.to_ascii_lowercase();
    lower.contains("no victims found") || lower.contains("\"error\"")
}

fn is_onion_or_magnet(s: &str) -> bool {
    let s = s.trim().to_ascii_lowercase();
    s.contains(".onion") || s.starts_with("magnet:") || s.starts_with("urn:")
}

/// Parse RansomLook **posts only**. Never read `leaks` / `records` (those can carry
/// credential-column dumps from `GET /api/search`). Never copy `magnet`.
#[must_use]
pub fn parse_ransomlook_posts(body: &str, host: &str) -> Vec<RansomLookHit> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let rows = v
        .get("posts")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| {
            v.as_array().and_then(|a| {
                if a.first()
                    .map(|x| x.get("post_title").is_some())
                    .unwrap_or(false)
                {
                    Some(a.clone())
                } else {
                    None
                }
            })
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    for row in rows {
        let title = row
            .get("post_title")
            .or_else(|| row.get("title"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let link = row
            .get("link")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let site = if is_onion_or_magnet(&link) {
            String::new()
        } else {
            link
        };
        if !host_matches_needle(host, &site) && !victim_mentions_org(&title, host) {
            continue;
        }
        out.push(RansomLookHit {
            title,
            group: row
                .get("group_name")
                .or_else(|| row.get("group"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            discovered: row
                .get("discovered")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            site,
        });
        if out.len() >= 20 {
            break;
        }
    }
    out
}

/// urlscan.io search hits whose scanned page matches the authorized apex.
#[must_use]
pub fn parse_urlscan_search(body: &str, host: &str) -> (i64, Vec<UrlscanHit>) {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return (0, Vec::new());
    };
    let total = v.get("total").and_then(Value::as_i64).unwrap_or(0);
    let rows = v
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for row in rows {
        let page_domain = row
            .pointer("/page/domain")
            .or_else(|| row.pointer("/page/apexDomain"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let apex_page = row
            .pointer("/page/apexDomain")
            .or_else(|| row.pointer("/task/apexDomain"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if !host_matches_needle(host, &page_domain) && !host_matches_needle(host, apex_page) {
            continue;
        }
        out.push(UrlscanHit {
            id: row
                .get("_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            page_domain,
            task_url: row
                .pointer("/task/url")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            total,
        });
        if out.len() >= 10 {
            break;
        }
    }
    (total, out)
}

/// Spamhaus DBL `abused_legit_*` = a legitimate site being abused for malware.
#[must_use]
pub fn parse_urlhaus_abused_legit(body: &str) -> Option<String> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return None;
    };
    let dbl = v
        .pointer("/blacklists/spamhaus_dbl")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if dbl.is_empty() || dbl.eq_ignore_ascii_case("not listed") {
        return None;
    }
    if dbl.to_ascii_lowercase().contains("abused_legit") {
        Some(dbl.to_string())
    } else {
        None
    }
}

/// Public published IAB price bands — only attach when live evidence exists.
#[must_use]
pub fn iab_quote_for_ports(open: &[u16], http_tokens: &[String]) -> Option<IabQuote> {
    let tokens_blob = http_tokens.join(" ").to_ascii_lowercase();
    let vpn = VPN_TOKENS.iter().any(|t| tokens_blob.contains(t));
    if open.contains(&3389) {
        return Some(IabQuote {
            label: "Exposed RDP (TCP 3389)",
            usd_low: 500,
            usd_high: 3_000,
            citation: "Public access-broker reporting (Coveware / Group-IB 2023–2025 ranges). Not a live market quote.",
            next_engines: &["password_spray", "smb_netbios", "leak_hunter"],
        });
    }
    if vpn {
        return Some(IabQuote {
            label: "Corporate VPN / remote-access appliance banner",
            usd_low: 2_000,
            usd_high: 10_000,
            citation: "Public access-broker reporting for VPN/Citrix/Pulse listings. Not a live market quote.",
            next_engines: &["leak_hunter", "password_spray", "jwt_attack"],
        });
    }
    if open.contains(&22) && open.contains(&445) {
        return Some(IabQuote {
            label: "SSH + SMB simultaneously reachable",
            usd_low: 1_000,
            usd_high: 8_000,
            citation:
                "Public IAB listings for mixed remote-admin surfaces. Not a live market quote.",
            next_engines: &["smb_netbios", "password_spray", "leak_hunter"],
        });
    }
    None
}

fn finding_ev(
    engine: &str,
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    evidence: Value,
) -> Value {
    enrich(
        engine,
        finding(engine, title, severity, MITRE, description, target),
        evidence,
    )
}

fn push_ransom_live_hits(
    findings: &mut Vec<Value>,
    engine_id: &str,
    target: &str,
    apex: &str,
    url: &str,
    status: u16,
    hits: &[RansomHit],
) {
    for hit in hits {
        let mut desc = format!(
            "Clearnet ransomware.live listed victim='{}' website='{}' date='{}'. Treat as confirmed extortion-intel, not a simulated hit. Next authorized engines: leak_hunter, password_spray, incident-response playbooks.",
            hit.victim, hit.website, hit.attack_date
        );
        if hit.infostealer_employees > 0 || hit.infostealer_users > 0 {
            desc.push_str(&format!(
                " Aggregator infostealer *counts* only: employees={} users={} (no dump contents).",
                hit.infostealer_employees, hit.infostealer_users
            ));
        }
        findings.push(finding_ev(
            engine_id,
            &format!(
                "Ransomware leak-site listing for {} (group {})",
                if hit.victim.is_empty() {
                    apex
                } else {
                    &hit.victim
                },
                if hit.group.is_empty() {
                    "unknown"
                } else {
                    &hit.group
                }
            ),
            "high",
            &desc,
            target,
            json!({
                "source": "ransomware.live",
                "url": url,
                "http_status": status,
                "victim": hit.victim,
                "group": hit.group,
                "website": hit.website,
                "attack_date": hit.attack_date,
                "infostealer_employees": hit.infostealer_employees,
                "infostealer_users": hit.infostealer_users,
            }),
        ));
    }
    if hits.is_empty() {
        findings.push(finding_ev(
            engine_id,
            &format!("ransomware.live queried — no victim listing for {apex}"),
            "info",
            &format!(
                "Live GET {url} returned HTTP {status} with zero victim rows matching '{apex}'."
            ),
            target,
            json!({"source":"ransomware.live","url":url,"http_status":status,"matches":0}),
        ));
    }
}

/// Collect clearnet intel findings for any engine id (darkweb_intel reuses this).
pub async fn collect_clearnet_intel(engine_id: &str, target: &str) -> Vec<Value> {
    let host = extract_host(target);
    if host.is_empty() {
        return Vec::new();
    }
    let apex = registrable_apex(&host);
    let client = http_client().await;
    let mut findings = Vec::new();
    let headers = [("User-Agent", UA), ("Accept", "application/json")];

    // ransomware.live — v2 only (v1 302s to marketing HTML). PRO when a key is set.
    // Search apex, then org-stem on zero-hit so domain-less listings can still match
    // after exact-host / victim-token filters (never keyword-only findings).
    let rl_key = ransomware_live_api_key();
    let stem = apex.split('.').next().unwrap_or(&apex).to_string();
    let mut rl_keywords: Vec<String> = vec![apex.clone()];
    if stem.len() >= 4 && stem != apex && !GENERIC_VICTIM_STEMS.contains(&stem.as_str()) {
        rl_keywords.push(stem);
    }
    let mut rl_queried = false;
    let mut rl_status = 0u16;
    let mut rl_ok = false;
    let mut rl_had_hits = false;
    for kw in &rl_keywords {
        if rl_had_hits {
            break;
        }
        let (url, hdrs): (String, Vec<(&str, &str)>) = if !rl_key.is_empty() {
            (
                format!(
                    "https://api-pro.ransomware.live/victims/search?q={}",
                    urlencoding::encode(kw)
                ),
                vec![
                    ("User-Agent", UA),
                    ("Accept", "application/json"),
                    ("X-API-KEY", rl_key.as_str()),
                ],
            )
        } else {
            (
                format!(
                    "https://api.ransomware.live/v2/searchvictims/{}",
                    urlencoding::encode(kw)
                ),
                headers.to_vec(),
            )
        };
        if let Some(p) = http_get_with_headers(&client, &url, &hdrs).await {
            rl_queried = true;
            rl_status = p.status;
            if p.status == 200 {
                rl_ok = true;
                let hits = parse_ransomware_live(&p.body, &host);
                if !hits.is_empty() {
                    rl_had_hits = true;
                    push_ransom_live_hits(
                        &mut findings,
                        engine_id,
                        target,
                        &apex,
                        &url,
                        p.status,
                        &hits,
                    );
                }
            } else if ransomware_live_no_victims(p.status, &p.body) {
                rl_ok = true;
            } else if !rl_key.is_empty() && (p.status == 401 || p.status == 403) {
                // Bad PRO key — fall through to public v2 on the next loop iteration
                // by clearing the key after this attempt on apex.
                findings.push(finding_ev(
                    engine_id,
                    "ransomware.live PRO key rejected — falling back to public v2",
                    "info",
                    &format!(
                        "Live GET {url} returned HTTP {}. Check RANSOMWARE_LIVE_API_KEY.",
                        p.status
                    ),
                    target,
                    json!({"source":"ransomware.live","url":url,"http_status":p.status,"auth":"pro"}),
                ));
                break;
            }
        }
    }
    if !rl_key.is_empty() && !rl_ok && !rl_had_hits {
        // PRO failed; public v2 apex search.
        let url = format!(
            "https://api.ransomware.live/v2/searchvictims/{}",
            urlencoding::encode(&apex)
        );
        if let Some(p) = http_get_with_headers(&client, &url, &headers).await {
            rl_queried = true;
            rl_status = p.status;
            if p.status == 200 || ransomware_live_no_victims(p.status, &p.body) {
                rl_ok = true;
                let hits = if p.status == 200 {
                    parse_ransomware_live(&p.body, &host)
                } else {
                    Vec::new()
                };
                if !hits.is_empty() {
                    rl_had_hits = true;
                    push_ransom_live_hits(
                        &mut findings,
                        engine_id,
                        target,
                        &apex,
                        &url,
                        p.status,
                        &hits,
                    );
                }
            }
        }
    }
    if rl_ok && !rl_had_hits {
        let already_zero = findings.iter().any(|f| {
            f.get("title")
                .and_then(Value::as_str)
                .map(|t| t.contains("no victim listing"))
                .unwrap_or(false)
        });
        if !already_zero {
            findings.push(finding_ev(
                engine_id,
                &format!("ransomware.live queried — no victim listing for {apex}"),
                "info",
                &format!(
                    "Live ransomware.live search for '{apex}' returned zero matching victim rows."
                ),
                target,
                json!({"source":"ransomware.live","http_status": rl_status,"matches":0}),
            ));
        }
    }
    if !rl_queried {
        findings.push(finding_ev(
            engine_id,
            "ransomware.live unreachable this run",
            "info",
            "No HTTP response from api.ransomware.live. Finding is a live probe failure, not a hidden listing.",
            target,
            json!({"source":"ransomware.live","http_status": rl_status, "reachable": false}),
        ));
    } else if !rl_ok {
        findings.push(finding_ev(
            engine_id,
            "ransomware.live returned a non-success status",
            "info",
            &format!(
                "Live ransomware.live search for '{apex}' returned HTTP {rl_status} (no 200 body to parse)."
            ),
            target,
            json!({"source":"ransomware.live","http_status": rl_status}),
        ));
    }

    // ThreatFox — Auth-Key search when configured; otherwise recent public domain export.
    let key = abusech_auth_key();
    let tf_api = "https://threatfox-api.abuse.ch/api/v1/";
    let tf_export = "https://threatfox.abuse.ch/export/json/domains/recent/";
    if !key.is_empty() {
        let tf_body = json!({"query": "search_ioc", "search_term": apex, "exact_match": true});
        if let Some(p) =
            http_post_json_with_headers(&client, tf_api, &tf_body, &[("Auth-Key", key.as_str())])
                .await
        {
            let hits = parse_threatfox(&p.body);
            if p.status == 200 && !hits.is_empty() {
                for hit in &hits {
                    let sev = if hit.confidence >= 75 {
                        "high"
                    } else {
                        "medium"
                    };
                    findings.push(finding_ev(
                        engine_id,
                        &format!("ThreatFox IOC {} ({})", hit.ioc, hit.malware),
                        sev,
                        &format!(
                            "abuse.ch ThreatFox search_ioc returned ioc='{}' type='{}' malware='{}' confidence={}. Next authorized engines: threat_intel_fusion, leak_hunter.",
                            hit.ioc, hit.threat_type, hit.malware, hit.confidence
                        ),
                        target,
                        json!({
                            "source": "threatfox",
                            "url": tf_api,
                            "http_status": p.status,
                            "ioc": hit.ioc,
                            "threat_type": hit.threat_type,
                            "malware": hit.malware,
                            "confidence": hit.confidence,
                            "auth": "auth_key",
                        }),
                    ));
                }
            } else if p.status == 200 {
                findings.push(finding_ev(
                    engine_id,
                    &format!("ThreatFox queried — no IOC for {apex}"),
                    "info",
                    &format!("Live POST {tf_api} search_ioc for '{apex}' returned HTTP {} with zero IOCs.", p.status),
                    target,
                    json!({"source":"threatfox","url":tf_api,"http_status":p.status,"matches":0,"auth":"auth_key"}),
                ));
            } else {
                findings.push(finding_ev(
                    engine_id,
                    "ThreatFox Auth-Key search returned a non-success status",
                    "info",
                    &format!("Live POST {tf_api} search_ioc for '{apex}' returned HTTP {}. Check ABUSECH_AUTH_KEY (free at auth.abuse.ch).", p.status),
                    target,
                    json!({"source":"threatfox","url":tf_api,"http_status":p.status,"auth":"auth_key"}),
                ));
            }
        } else {
            findings.push(finding_ev(
                engine_id,
                "ThreatFox unreachable this run",
                "info",
                "No HTTP response from threatfox-api.abuse.ch. Finding is a live probe failure, not a hidden IOC.",
                target,
                json!({"source":"threatfox","url":tf_api,"reachable":false}),
            ));
        }
    } else if let Some(p) = http_get_with_headers(&client, tf_export, &headers).await {
        if p.status == 200 {
            let hits = parse_threatfox_export(&p.body, &host);
            if hits.is_empty() {
                findings.push(finding_ev(
                    engine_id,
                    &format!("ThreatFox recent-domain export — no IOC for {apex}"),
                    "info",
                    &format!(
                        "Live GET {tf_export} (no Auth-Key) listed recent domains; none matched '{apex}'. Set ABUSECH_AUTH_KEY for targeted search_ioc."
                    ),
                    target,
                    json!({"source":"threatfox","url":tf_export,"http_status":p.status,"matches":0,"auth":"export"}),
                ));
            } else {
                for hit in &hits {
                    let sev = if hit.confidence >= 75 {
                        "high"
                    } else {
                        "medium"
                    };
                    findings.push(finding_ev(
                        engine_id,
                        &format!("ThreatFox recent export IOC {} ({})", hit.ioc, hit.malware),
                        sev,
                        &format!(
                            "abuse.ch ThreatFox recent domain export listed ioc='{}' type='{}' malware='{}'. Next authorized engines: threat_intel_fusion, leak_hunter.",
                            hit.ioc, hit.threat_type, hit.malware
                        ),
                        target,
                        json!({
                            "source": "threatfox",
                            "url": tf_export,
                            "http_status": p.status,
                            "ioc": hit.ioc,
                            "threat_type": hit.threat_type,
                            "malware": hit.malware,
                            "confidence": hit.confidence,
                            "auth": "export",
                        }),
                    ));
                }
            }
        } else {
            findings.push(finding_ev(
                engine_id,
                "ThreatFox recent-domain export returned a non-success status",
                "info",
                &format!("Live GET {tf_export} returned HTTP {}.", p.status),
                target,
                json!({"source":"threatfox","url":tf_export,"http_status":p.status}),
            ));
        }
    } else {
        findings.push(finding_ev(
            engine_id,
            "ThreatFox unreachable this run",
            "info",
            "No HTTP response from threatfox.abuse.ch export. Finding is a live probe failure, not a hidden IOC.",
            target,
            json!({"source":"threatfox","url":tf_export,"reachable":false}),
        ));
    }

    // URLhaus — Auth-Key host API when configured; otherwise public hostfile (~10KB).
    let uh_api = "https://urlhaus-api.abuse.ch/v1/host/";
    let uh_export = "https://urlhaus.abuse.ch/downloads/hostfile/";
    if !key.is_empty() {
        let form = format!("host={}", urlencoding::encode(&apex));
        if let Some(p) = http_post_bytes_with_headers(
            &client,
            uh_api,
            form.as_bytes(),
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Auth-Key", key.as_str()),
            ],
        )
        .await
        {
            let n = parse_urlhaus_host(&p.body);
            let abused = parse_urlhaus_abused_legit(&p.body);
            if p.status == 200 && n > 0 {
                findings.push(finding_ev(
                    engine_id,
                    &format!("URLhaus lists {n} malicious URL(s) on {apex}"),
                    "high",
                    &format!(
                        "abuse.ch URLhaus host query for '{apex}' returned {n} URL rows (HTTP {}). Next authorized engines: threat_intel_fusion, asm.",
                        p.status
                    ),
                    target,
                    json!({"source":"urlhaus","url":uh_api,"http_status":p.status,"url_count":n,"auth":"auth_key"}),
                ));
            } else if p.status == 200 {
                findings.push(finding_ev(
                    engine_id,
                    &format!("URLhaus queried — no host rows for {apex}"),
                    "info",
                    &format!("Live URLhaus host query for '{apex}' returned HTTP {} with zero URLs.", p.status),
                    target,
                    json!({"source":"urlhaus","url":uh_api,"http_status":p.status,"url_count":0,"auth":"auth_key"}),
                ));
            } else {
                findings.push(finding_ev(
                    engine_id,
                    "URLhaus Auth-Key host query returned a non-success status",
                    "info",
                    &format!("Live URLhaus host query for '{apex}' returned HTTP {}. Check ABUSECH_AUTH_KEY.", p.status),
                    target,
                    json!({"source":"urlhaus","url":uh_api,"http_status":p.status,"auth":"auth_key"}),
                ));
            }
            if p.status == 200 {
                if let Some(dbl) = abused {
                    findings.push(finding_ev(
                        engine_id,
                        &format!("URLhaus Spamhaus DBL: {apex} is {dbl}"),
                        "high",
                        &format!(
                            "abuse.ch URLhaus reports Spamhaus DBL '{dbl}' for '{apex}' (abused legitimate site). Next authorized engines: threat_intel_fusion, asm."
                        ),
                        target,
                        json!({"source":"urlhaus","url":uh_api,"http_status":p.status,"spamhaus_dbl":dbl,"auth":"auth_key"}),
                    ));
                }
            }
        } else {
            findings.push(finding_ev(
                engine_id,
                "URLhaus unreachable this run",
                "info",
                "No HTTP response from urlhaus-api.abuse.ch. Finding is a live probe failure, not a hidden listing.",
                target,
                json!({"source":"urlhaus","url":uh_api,"reachable":false}),
            ));
        }
    } else if let Some(p) = http_get_with_headers(&client, uh_export, &headers).await {
        if p.status == 200 {
            let n = parse_urlhaus_hostfile(&p.body, &host);
            if n > 0 {
                findings.push(finding_ev(
                    engine_id,
                    &format!("URLhaus hostfile lists {n} malicious host(s) for {apex}"),
                    "high",
                    &format!(
                        "Live GET {uh_export} (no Auth-Key) matched {n} hostfile row(s) for '{apex}'. Set ABUSECH_AUTH_KEY for full URL rows."
                    ),
                    target,
                    json!({"source":"urlhaus","url":uh_export,"http_status":p.status,"url_count":n,"auth":"hostfile"}),
                ));
            } else {
                findings.push(finding_ev(
                    engine_id,
                    &format!("URLhaus hostfile queried — no host rows for {apex}"),
                    "info",
                    &format!("Live GET {uh_export} listed current malware hosts; none matched '{apex}'."),
                    target,
                    json!({"source":"urlhaus","url":uh_export,"http_status":p.status,"url_count":0,"auth":"hostfile"}),
                ));
            }
        } else {
            findings.push(finding_ev(
                engine_id,
                "URLhaus hostfile returned a non-success status",
                "info",
                &format!("Live GET {uh_export} returned HTTP {}.", p.status),
                target,
                json!({"source":"urlhaus","url":uh_export,"http_status":p.status}),
            ));
        }
    } else {
        findings.push(finding_ev(
            engine_id,
            "URLhaus unreachable this run",
            "info",
            "No HTTP response from urlhaus.abuse.ch hostfile. Finding is a live probe failure, not a hidden listing.",
            target,
            json!({"source":"urlhaus","url":uh_export,"reachable":false}),
        ));
    }

    // HIBP public catalog filtered by Domain (no API key). Named-incident only — not employee exposure.
    let hibp_url = format!(
        "https://haveibeenpwned.com/api/v3/breaches?Domain={}",
        urlencoding::encode(&apex)
    );
    if let Some(p) = http_get_with_headers(&client, &hibp_url, &headers).await {
        if p.status == 200 {
            let hits = parse_hibp_breaches(&p.body, &host);
            if hits.is_empty() {
                findings.push(finding_ev(
                    engine_id,
                    &format!("HIBP catalog queried — no Domain={apex} breach"),
                    "info",
                    &format!(
                        "Live GET {hibp_url} (no API key) listed public breaches; none had Domain matching '{apex}'."
                    ),
                    target,
                    json!({"source":"hibp_breaches","url":hibp_url,"http_status":p.status,"matches":0,"attribution":"Have I Been Pwned"}),
                ));
            } else {
                for hit in &hits {
                    findings.push(finding_ev(
                        engine_id,
                        &format!(
                            "HIBP catalog: {} breached {} ({} accounts)",
                            hit.name, hit.domain, hit.pwn_count
                        ),
                        "medium",
                        &format!(
                            "Have I Been Pwned public catalog lists breach '{}' Domain='{}' date='{}' PwnCount={}. This is catalog metadata, not a dump. Next authorized engines: leak_hunter, password_spray.",
                            hit.name, hit.domain, hit.breach_date, hit.pwn_count
                        ),
                        target,
                        json!({
                            "source": "hibp_breaches",
                            "url": hibp_url,
                            "http_status": p.status,
                            "name": hit.name,
                            "domain": hit.domain,
                            "breach_date": hit.breach_date,
                            "pwn_count": hit.pwn_count,
                            "attribution": "Have I Been Pwned",
                        }),
                    ));
                }
            }
        } else {
            findings.push(finding_ev(
                engine_id,
                "HIBP catalog returned a non-success status",
                "info",
                &format!("Live GET {hibp_url} returned HTTP {}.", p.status),
                target,
                json!({"source":"hibp_breaches","url":hibp_url,"http_status":p.status}),
            ));
        }
    } else {
        findings.push(finding_ev(
            engine_id,
            "HIBP catalog unreachable this run",
            "info",
            "No HTTP response from haveibeenpwned.com/api/v3/breaches. Finding is a live probe failure, not a hidden breach.",
            target,
            json!({"source":"hibp_breaches","url":hibp_url,"reachable":false}),
        ));
    }

    // RansomLook leak-blog posts catalog. Do not call /api/search — that JSON can include
    // `leaks.records` with password columns. Ignore magnet/onion links; match titles + clearnet sites.
    let rlk_url = "https://www.ransomlook.io/api/posts";
    if let Some(p) = http_get_with_headers_max(&client, rlk_url, &headers, INTEL_BODY_MAX).await {
        if p.status == 200 {
            let hits = parse_ransomlook_posts(&p.body, &host);
            if hits.is_empty() {
                findings.push(finding_ev(
                    engine_id,
                    &format!("RansomLook posts catalog queried — no listing for {apex}"),
                    "info",
                    &format!(
                        "Live GET {rlk_url} returned HTTP {} with zero post_title/site rows matching '{apex}'. Magnets and leak records are not fetched.",
                        p.status
                    ),
                    target,
                    json!({"source":"ransomlook","url":rlk_url,"http_status":p.status,"matches":0}),
                ));
            } else {
                for hit in &hits {
                    findings.push(finding_ev(
                        engine_id,
                        &format!(
                            "RansomLook leak-site listing for {} (group {})",
                            if hit.title.is_empty() { &apex } else { &hit.title },
                            if hit.group.is_empty() { "unknown" } else { &hit.group }
                        ),
                        "high",
                        &format!(
                            "Clearnet RansomLook posts catalog listed post_title='{}' group='{}' discovered='{}'. Magnet/onion locations are not retrieved. Next authorized engines: leak_hunter, password_spray.",
                            hit.title, hit.group, hit.discovered
                        ),
                        target,
                        json!({
                            "source": "ransomlook",
                            "url": rlk_url,
                            "http_status": p.status,
                            "post_title": hit.title,
                            "group": hit.group,
                            "discovered": hit.discovered,
                            "site": hit.site,
                        }),
                    ));
                }
            }
        } else {
            findings.push(finding_ev(
                engine_id,
                "RansomLook posts catalog returned a non-success status",
                "info",
                &format!("Live GET {rlk_url} returned HTTP {}.", p.status),
                target,
                json!({"source":"ransomlook","url":rlk_url,"http_status":p.status}),
            ));
        }
    } else {
        findings.push(finding_ev(
            engine_id,
            "RansomLook unreachable this run",
            "info",
            "No HTTP response from www.ransomlook.io/api/posts. Finding is a live probe failure, not a hidden listing.",
            target,
            json!({"source":"ransomlook","url":rlk_url,"reachable":false}),
        ));
    }

    // urlscan.io — page.apexDomain only (bare `domain:` matches any contacted host = false positives).
    // Malicious-verdict filter requires URLSCAN_API_KEY. Unauthenticated = public scan inventory (info).
    let us_key = urlscan_api_key();
    let us_q_mal = format!("page.apexDomain:{apex} AND verdicts.overall.malicious:true");
    let us_q_pub = format!("page.apexDomain:{apex}");
    let mut us_query = if us_key.is_empty() {
        us_q_pub.clone()
    } else {
        us_q_mal.clone()
    };
    let mut us_url = format!(
        "https://urlscan.io/api/v1/search/?q={}&size=10",
        urlencoding::encode(&us_query)
    );
    let us_hdrs: Vec<(&str, &str)> = if us_key.is_empty() {
        headers.to_vec()
    } else {
        vec![
            ("User-Agent", UA),
            ("Accept", "application/json"),
            ("API-Key", us_key.as_str()),
        ]
    };
    let mut us_probe = http_get_with_headers(&client, &us_url, &us_hdrs).await;
    if !us_key.is_empty() {
        if let Some(p) = &us_probe {
            if p.status == 403 || p.status == 401 {
                us_query = us_q_pub.clone();
                us_url = format!(
                    "https://urlscan.io/api/v1/search/?q={}&size=10",
                    urlencoding::encode(&us_query)
                );
                us_probe = http_get_with_headers(&client, &us_url, &headers).await;
            }
        }
    }
    if let Some(p) = us_probe {
        if p.status == 200 {
            let (total, hits) = parse_urlscan_search(&p.body, &host);
            let malicious = us_query.contains("malicious");
            if malicious && !hits.is_empty() {
                for hit in &hits {
                    let permalink = if hit.id.is_empty() {
                        us_url.clone()
                    } else {
                        format!("https://urlscan.io/result/{}/", hit.id)
                    };
                    findings.push(finding_ev(
                        engine_id,
                        &format!("urlscan.io malicious verdict for {}", hit.page_domain),
                        "medium",
                        &format!(
                            "urlscan.io search listed a malicious verdict for scanned host '{}'. Permalink {}. Next authorized engines: typosquatting_monitor, leak_hunter.",
                            hit.page_domain, permalink
                        ),
                        target,
                        json!({
                            "source": "urlscan",
                            "url": us_url,
                            "http_status": p.status,
                            "page_domain": hit.page_domain,
                            "task_url": hit.task_url,
                            "permalink": permalink,
                            "verdict": "malicious",
                            "attribution": "urlscan.io",
                        }),
                    ));
                }
            } else {
                findings.push(finding_ev(
                    engine_id,
                    &format!("urlscan.io queried — {total} public scan(s) of {apex}"),
                    "info",
                    &format!(
                        "Live GET urlscan.io search q='{us_query}' returned HTTP {} total={total} matching page.apexDomain '{apex}'. Unauthenticated search cannot filter malicious verdicts.",
                        p.status
                    ),
                    target,
                    json!({
                        "source": "urlscan",
                        "url": us_url,
                        "http_status": p.status,
                        "total": total,
                        "matches": hits.len(),
                        "query": us_query,
                        "attribution": "urlscan.io",
                    }),
                ));
            }
        } else {
            findings.push(finding_ev(
                engine_id,
                "urlscan.io search returned a non-success status",
                "info",
                &format!("Live GET {us_url} returned HTTP {}.", p.status),
                target,
                json!({"source":"urlscan","url":us_url,"http_status":p.status}),
            ));
        }
    } else {
        findings.push(finding_ev(
            engine_id,
            "urlscan.io unreachable this run",
            "info",
            "No HTTP response from urlscan.io/api/v1/search. Finding is a live probe failure, not a hidden scan.",
            target,
            json!({"source":"urlscan","url":us_url,"reachable":false}),
        ));
    }

    findings
}

async fn probe_iab_surface(
    target: &str,
    include_ports: bool,
    include_http: bool,
) -> (Vec<u16>, Vec<String>) {
    let host = extract_host(target);
    let mut open = Vec::new();
    let mut tokens = Vec::new();
    if include_ports {
        open = tcp_scan(&host, IAB_PORTS, 8).await;
    }
    if include_http {
        let client = http_client().await;
        for url in [
            format!("https://{host}/"),
            format!("https://{host}/vpn/index.html"),
            format!("https://{host}/remote/login"),
            format!("https://{host}/owa/"),
            format!("https://{host}/RDWeb/"),
            format!("https://{host}/global-protect/login.esp"),
            format!("https://{host}/dana-na/"),
        ] {
            if let Some(p) = http_get(&client, &url).await {
                let blob = format!("{} {}", p.headers_blob(), p.body).to_ascii_lowercase();
                for tok in VPN_TOKENS {
                    if blob.contains(tok) {
                        tokens.push((*tok).to_string());
                    }
                }
            }
        }
        tokens.sort();
        tokens.dedup();
    }
    (open, tokens)
}

pub async fn run_adversary_gap_mirror_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let include_ports = pbool(&ctx.job_params, "include_ports", true);
    let include_http = pbool(&ctx.job_params, "include_http", true);

    let mut findings = collect_clearnet_intel(ENGINE_ID, target).await;
    let (open, tokens) = probe_iab_surface(target, include_ports, include_http).await;

    if !open.is_empty() {
        findings.push(finding_ev(
            ENGINE_ID,
            &format!("IAB-interesting ports open: {:?}", open),
            if open.contains(&3389) || open.contains(&445) {
                "high"
            } else {
                "medium"
            },
            &format!(
                "Authorized TCP connect to {} observed open ports {:?}. These are the remote-access classes initial-access brokers advertise. Next authorized engines: {:?}.",
                extract_host(target),
                open,
                ["password_spray", "smb_netbios", "leak_hunter"]
            ),
            target,
            json!({"open_ports": open, "probe": "tcp_connect", "ports_scanned": IAB_PORTS}),
        ));
    } else if include_ports {
        findings.push(finding_ev(
            ENGINE_ID,
            "IAB port set closed or filtered",
            "info",
            &format!(
                "Authorized TCP connect of {:?} on {} produced zero accepts.",
                IAB_PORTS,
                extract_host(target)
            ),
            target,
            json!({"open_ports": open, "ports_scanned": IAB_PORTS}),
        ));
    }

    if !tokens.is_empty() {
        findings.push(finding_ev(
            ENGINE_ID,
            &format!("Remote-access product tokens: {}", tokens.join(", ")),
            "medium",
            &format!(
                "Authorized HTTPS GETs on {} observed product tokens {:?}. Next authorized engines: leak_hunter, password_spray, jwt_attack.",
                extract_host(target),
                tokens
            ),
            target,
            json!({"http_tokens": tokens, "probe": "https_get"}),
        ));
    }

    if let Some(q) = iab_quote_for_ports(&open, &tokens) {
        findings.push(finding_ev(
            ENGINE_ID,
            &format!(
                "Published IAB economics (not a live market quote): {} (public band USD {}–{})",
                q.label, q.usd_low, q.usd_high
            ),
            "high",
            &format!(
                "{} — public published IAB band USD {}–{}. {}. Next authorized Weissman engines: {}.",
                q.label,
                q.usd_low,
                q.usd_high,
                q.citation,
                q.next_engines.join(", ")
            ),
            target,
            json!({
                "label": q.label,
                "usd_low": q.usd_low,
                "usd_high": q.usd_high,
                "citation": q.citation,
                "next_engines": q.next_engines,
                "open_ports": open,
                "http_tokens": tokens,
                "not_a_live_market_quote": true,
            }),
        ));
    }

    if findings.is_empty() {
        empty_ok(ENGINE_ID, target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!(
                "adversary_gap_mirror: {n} finding(s) for {}",
                extract_host(target)
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apex_handles_co_il() {
        assert_eq!(registrable_apex("www.bank.co.il"), "bank.co.il");
        assert_eq!(registrable_apex("api.shop.example.com"), "example.com");
        assert_eq!(registrable_apex("EXAMPLE.COM."), "example.com");
    }

    #[test]
    fn host_match_subdomain_and_apex() {
        assert!(host_matches_needle("www.acme.com", "acme.com"));
        assert!(host_matches_needle(
            "acme.com",
            "https://www.acme.com/login"
        ));
        assert!(!host_matches_needle("acme.com", "notacme.com"));
        assert!(!host_matches_needle("bank.co.il", "mybank.co.il"));
        assert!(!victim_mentions_org("Notacme Corp", "acme.com"));
        assert!(victim_mentions_org("Acme Ltd", "www.acme.com"));
        assert!(!victim_mentions_org("National Bank", "bank.co.il"));
    }

    #[test]
    fn ransomware_live_filters_unrelated() {
        let body = r#"[{"victim":"Other Corp","group":"lockbit","website":"other.example","attackdate":"2024-01-01"},{"victim":"Acme Ltd","group":"play","website":"acme.com","attackdate":"2025-02-02"}]"#;
        let hits = parse_ransomware_live(body, "www.acme.com");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].group, "play");
    }

    #[test]
    fn threatfox_parses_ok_payload() {
        let body = r#"{"query_status":"ok","data":[{"ioc":"acme.com","threat_type":"botnet_cc","malware":"cobaltstrike","confidence_level":90}]}"#;
        let hits = parse_threatfox(body);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].confidence, 90);
    }

    #[test]
    fn urlhaus_zero_on_no_results() {
        assert_eq!(parse_urlhaus_host(r#"{"query_status":"no_results"}"#), 0);
        assert_eq!(
            parse_urlhaus_host(r#"{"query_status":"ok","urls":[{},{}]}"#),
            2
        );
    }

    #[test]
    fn threatfox_export_filters_host() {
        let body = r#"{"1":[{"ioc_value":"www.acme.com","ioc_type":"domain","threat_type":"botnet_cc","malware_printable":"Cobalt Strike","confidence_level":80}],"2":[{"ioc_value":"evil.example","ioc_type":"domain","threat_type":"payload_delivery","malware":"x"}]}"#;
        let hits = parse_threatfox_export(body, "mail.acme.com");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ioc, "www.acme.com");
    }

    #[test]
    fn urlhaus_hostfile_matches_and_ignores_unrelated() {
        let body = "# comment\n127.0.0.1\twww.acme.com\n127.0.0.1\tnotacme.com\n";
        assert_eq!(parse_urlhaus_hostfile(body, "acme.com"), 1);
        assert_eq!(parse_urlhaus_hostfile(body, "other.org"), 0);
    }

    #[test]
    fn hibp_matches_domain_only() {
        let body = r#"[{"Name":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","PwnCount":1},{"Name":"Acme","Domain":"acme.com","BreachDate":"2024-01-01","PwnCount":12}]"#;
        let hits = parse_hibp_breaches(body, "mail.acme.com");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "Acme");
    }

    #[test]
    fn iab_quote_requires_live_ports() {
        assert!(iab_quote_for_ports(&[], &[]).is_none());
        let q = iab_quote_for_ports(&[3389], &[]).expect("rdp");
        assert_eq!(q.usd_low, 500);
        assert!(q.next_engines.contains(&"password_spray"));
    }

    #[test]
    fn iab_quote_vpn_tokens() {
        let q = iab_quote_for_ports(&[443], &["citrix".into()]).expect("vpn");
        assert_eq!(q.usd_high, 10_000);
    }

    #[test]
    fn ransomware_live_404_is_zero_not_outage() {
        assert!(ransomware_live_no_victims(
            404,
            r#"{"error": "No victims found for keyword 'adobe.com'."}"#
        ));
        assert!(!ransomware_live_no_victims(200, "[]"));
        assert!(!ransomware_live_no_victims(500, "oops"));
    }

    #[test]
    fn ransomware_live_infostealer_counts_only() {
        let body = r#"[{"victim":"Acme Ltd","group":"play","website":"acme.com","attackdate":"2025-02-02","infostealer":{"employees":1,"users":4}}]"#;
        let hits = parse_ransomware_live(body, "www.acme.com");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].infostealer_users, 4);
        assert_eq!(hits[0].infostealer_employees, 1);
    }

    #[test]
    fn ransomlook_matches_title_and_ignores_leaks_and_magnet() {
        let body = r#"{"posts":[{"post_title":"Acme Ltd","group_name":"lockbit","discovered":"2026-01-01","magnet":"magnet:?xt=urn:btih:deadbeef","link":"http://abc.onion/post"}],"leaks":[{"name":"acme.com","columns":["password","email"],"records":[["secret","a@acme.com"]]}]}"#;
        let hits = parse_ransomlook_posts(body, "acme.com");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].group, "lockbit");
        assert!(hits[0].site.is_empty());
        assert!(!hits[0].title.to_ascii_lowercase().contains("magnet"));
        assert!(!hits[0].group.contains("password"));
    }

    #[test]
    fn ransomlook_ignores_unrelated_and_search_leaks_only() {
        let body = r#"{"posts":[],"leaks":[{"name":"acme.com","columns":["password"],"records":"REDACTED"}]}"#;
        assert!(parse_ransomlook_posts(body, "acme.com").is_empty());
    }

    #[test]
    fn urlscan_filters_to_apex() {
        let body = r#"{"total":3,"results":[{"_id":"aaa","task":{"url":"https://www.acme.com/","apexDomain":"acme.com"},"page":{"domain":"www.acme.com","apexDomain":"acme.com"}},{"_id":"bbb","task":{"url":"https://evil.example/","apexDomain":"example"},"page":{"domain":"evil.example","apexDomain":"example"}}]}"#;
        let (total, hits) = parse_urlscan_search(body, "mail.acme.com");
        assert_eq!(total, 3);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "aaa");
    }

    #[test]
    fn urlhaus_abused_legit_flag() {
        assert_eq!(
            parse_urlhaus_abused_legit(
                r#"{"query_status":"ok","blacklists":{"spamhaus_dbl":"abused_legit_malware","surbl":"not listed"}}"#
            )
            .as_deref(),
            Some("abused_legit_malware")
        );
        assert!(
            parse_urlhaus_abused_legit(r#"{"blacklists":{"spamhaus_dbl":"not listed"}}"#).is_none()
        );
    }
}
