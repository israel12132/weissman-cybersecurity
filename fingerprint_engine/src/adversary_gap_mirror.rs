//! **Adversary Gap Mirror** — what a criminal operator can learn about an authorized
//! target from *legal clearnet defender feeds*, fused with safe in-scope exposure probes.
//!
//! Live-only. Never Tor, never marketplaces, never credential dumps, never exploit PoCs.
//! Empty feeds → informational “queried, zero hits” evidence — never invented victims.
//!
//! Public sources (no paid IntelX required):
//! - ransomware.live victim search (ransomware leak-site *names* published on clearnet)
//! - abuse.ch ThreatFox IOC search
//! - abuse.ch URLhaus host query
//! - Have I Been Pwned public breach *catalog* (`GET /breaches`, no key)
//!
//! Exposure fusion (authorized RoE only): TCP connect of common remote-access ports and
//! HTTP product tokens (VPN/OWA/Citrix). Underground USD bands are cited from *public*
//! industry reporting and emitted only when live evidence exists.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, extract_host, finding, http_client, http_get, http_get_with_headers,
    http_post_bytes_with_headers, http_post_json, tcp_scan,
};
use crate::engine_result::EngineResult;
use serde_json::{json, Value};

pub const ENGINE_ID: &str = "adversary_gap_mirror";
const MITRE: &str = "T1597";
const UA: &str = "WeissmanCybersecurity/1.0 (adversary-gap-mirror; authorized-assessment)";

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

    // ransomware.live — try v2 then v1 keyword search.
    let rl_urls = [
        format!(
            "https://api.ransomware.live/v2/searchvictims/{}",
            urlencoding::encode(&apex)
        ),
        format!(
            "https://api.ransomware.live/v1/search?q={}",
            urlencoding::encode(&apex)
        ),
    ];
    let mut rl_queried = false;
    let mut rl_status = 0u16;
    let mut rl_ok = false;
    for url in &rl_urls {
        if let Some(p) = http_get_with_headers(&client, url, &headers).await {
            rl_queried = true;
            rl_status = p.status;
            if p.status == 200 {
                rl_ok = true;
                let hits = parse_ransomware_live(&p.body, &host);
                for hit in &hits {
                    findings.push(finding_ev(
                        engine_id,
                        &format!(
                            "Ransomware leak-site listing for {} (group {})",
                            if hit.victim.is_empty() { &apex } else { &hit.victim },
                            if hit.group.is_empty() { "unknown" } else { &hit.group }
                        ),
                        "high",
                        &format!(
                            "Clearnet ransomware.live listed victim='{}' website='{}' date='{}'. Treat as confirmed extortion-intel, not a simulated hit. Next authorized engines: leak_hunter, password_spray, incident-response playbooks.",
                            hit.victim, hit.website, hit.attack_date
                        ),
                        target,
                        json!({
                            "source": "ransomware.live",
                            "url": url,
                            "http_status": p.status,
                            "victim": hit.victim,
                            "group": hit.group,
                            "website": hit.website,
                            "attack_date": hit.attack_date,
                        }),
                    ));
                }
                if hits.is_empty() {
                    findings.push(finding_ev(
                        engine_id,
                        &format!("ransomware.live queried — no victim listing for {apex}"),
                        "info",
                        &format!(
                            "Live GET {} returned HTTP {} with zero victim rows matching '{}'.",
                            url, p.status, apex
                        ),
                        target,
                        json!({"source":"ransomware.live","url":url,"http_status":p.status,"matches":0}),
                    ));
                }
                break;
            }
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

    // ThreatFox
    let tf_url = "https://threatfox-api.abuse.ch/api/v1/";
    let tf_body = json!({"query": "search_ioc", "search_term": apex});
    if let Some(p) = http_post_json(&client, tf_url, &tf_body).await {
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
                        "abuse.ch ThreatFox returned ioc='{}' type='{}' malware='{}' confidence={}. Next authorized engines: threat_intel_fusion, leak_hunter.",
                        hit.ioc, hit.threat_type, hit.malware, hit.confidence
                    ),
                    target,
                    json!({
                        "source": "threatfox",
                        "url": tf_url,
                        "http_status": p.status,
                        "ioc": hit.ioc,
                        "threat_type": hit.threat_type,
                        "malware": hit.malware,
                        "confidence": hit.confidence,
                    }),
                ));
            }
        } else if p.status == 200 {
            findings.push(finding_ev(
                engine_id,
                &format!("ThreatFox queried — no IOC for {apex}"),
                "info",
                &format!(
                    "Live POST {tf_url} search_ioc for '{apex}' returned HTTP {} with zero IOCs.",
                    p.status
                ),
                target,
                json!({"source":"threatfox","url":tf_url,"http_status":p.status,"matches":0}),
            ));
        } else {
            findings.push(finding_ev(
                engine_id,
                "ThreatFox returned a non-success status",
                "info",
                &format!(
                    "Live POST {tf_url} search_ioc for '{apex}' returned HTTP {}.",
                    p.status
                ),
                target,
                json!({"source":"threatfox","url":tf_url,"http_status":p.status}),
            ));
        }
    } else {
        findings.push(finding_ev(
            engine_id,
            "ThreatFox unreachable this run",
            "info",
            "No HTTP response from threatfox-api.abuse.ch. Finding is a live probe failure, not a hidden IOC.",
            target,
            json!({"source":"threatfox","url":tf_url,"reachable":false}),
        ));
    }

    // URLhaus host
    let uh_url = "https://urlhaus-api.abuse.ch/v1/host/";
    let form = format!("host={}", urlencoding::encode(&apex));
    if let Some(p) = http_post_bytes_with_headers(
        &client,
        uh_url,
        form.as_bytes(),
        &[("Content-Type", "application/x-www-form-urlencoded")],
    )
    .await
    {
        let n = parse_urlhaus_host(&p.body);
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
                json!({"source":"urlhaus","url":uh_url,"http_status":p.status,"url_count":n}),
            ));
        } else if p.status == 200 {
            findings.push(finding_ev(
                engine_id,
                &format!("URLhaus queried — no host rows for {apex}"),
                "info",
                &format!(
                    "Live URLhaus host query for '{apex}' returned HTTP {} with zero URLs.",
                    p.status
                ),
                target,
                json!({"source":"urlhaus","url":uh_url,"http_status":p.status,"url_count":0}),
            ));
        } else {
            findings.push(finding_ev(
                engine_id,
                "URLhaus returned a non-success status",
                "info",
                &format!(
                    "Live URLhaus host query for '{apex}' returned HTTP {}.",
                    p.status
                ),
                target,
                json!({"source":"urlhaus","url":uh_url,"http_status":p.status}),
            ));
        }
    } else {
        findings.push(finding_ev(
            engine_id,
            "URLhaus unreachable this run",
            "info",
            "No HTTP response from urlhaus-api.abuse.ch. Finding is a live probe failure, not a hidden listing.",
            target,
            json!({"source":"urlhaus","url":uh_url,"reachable":false}),
        ));
    }

    // HIBP public catalog (no API key).
    let hibp_url = "https://haveibeenpwned.com/api/v3/breaches";
    if let Some(p) = http_get_with_headers(&client, hibp_url, &headers).await {
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
                    json!({"source":"hibp_breaches","url":hibp_url,"http_status":p.status,"matches":0}),
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
}
