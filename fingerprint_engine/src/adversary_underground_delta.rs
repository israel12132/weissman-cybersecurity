//! **Adversary Underground Delta** — first-mover for *criminal-index* OSINT.
//!
//! Criminals check public leak indexes, ransomware leak-site trackers, and
//! malware IoC feeds before they ever touch Tor. This engine queries those
//! **public, legal** APIs against an authorized apex, snapshots the hits, and
//! emits only what is **new since the last run**. New high/critical hits can
//! enqueue `leak_hunter` on the same FQDN.
//!
//! Sources (no Tor, no marketplace scraping):
//! - Have I Been Pwned domain-breach catalog (optional `HIBP_API_KEY`)
//! - ransomware.live victim search (exact registrable domain only)
//! - abuse.ch ThreatFox IoC search
//! - abuse.ch URLhaus hostinfo
//! - urlscan.io malicious verdicts
//! IntelX remains in `darkweb_intel` when `INTELX_API_KEY` is set (paid index).
//!
//! Live-only: source timeouts are reported as health failures, never as a
//! clean bill of health. Substring matches in ransomware.live descriptions are
//! discarded (they are a known false-positive class).

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, extract_host, finding, http_client, http_get, http_get_with_headers,
    http_post_bytes_with_headers, http_post_json_with_headers,
};
use crate::engine_result::EngineResult;
use crate::first_mover_surface_delta::in_authorized_scope;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub const ENGINE_ID: &str = "adversary_underground_delta";
const MITRE: &str = "T1597";
pub const FOLLOW_ON_ENGINES: &[&str] = &["leak_hunter"];
const SNAPSHOT_KEEP: i64 = 20;
const CACHE_TTL: Duration = Duration::from_secs(90);
const MAX_HITS: usize = 80;

const UNDERGROUND_SOURCES: &[&str] = &[
    ENGINE_ID,
    "darkweb_intel",
    "dark_web_monitor",
    "leak_hunter",
    "typosquatting_monitor",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceHit {
    pub source: String,
    pub fingerprint: String,
    pub title: String,
    pub severity: String,
    pub evidence: String,
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UndergroundSnapshot {
    pub apex: String,
    pub hits: Vec<SourceHit>,
    #[serde(default)]
    pub health: Vec<SourceHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceHealth {
    pub id: String,
    pub ok: bool,
    pub http_status: u16,
    pub message: String,
    pub hit_count: usize,
}

#[derive(Debug, Clone)]
struct CachedOsint {
    at: Instant,
    hits: Vec<SourceHit>,
    health: Vec<SourceHealth>,
}

fn cache() -> &'static DashMap<String, CachedOsint> {
    static C: OnceLock<DashMap<String, CachedOsint>> = OnceLock::new();
    C.get_or_init(DashMap::new)
}

#[must_use]
pub fn registrable_apex(host: &str) -> String {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    h.strip_prefix("www.").unwrap_or(&h).to_string()
}

#[must_use]
pub fn hit_fingerprint(source: &str, title: &str, url: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source.trim().to_ascii_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(title.trim().to_ascii_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(url.trim().to_ascii_lowercase().as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Exact apex or subdomain — never a free-text description match.
#[must_use]
pub fn domain_hit_in_scope(apex: &str, candidate: &str) -> bool {
    let apex = registrable_apex(apex);
    let cand = registrable_apex(candidate);
    if apex.is_empty() || cand.is_empty() || !apex.contains('.') {
        return false;
    }
    in_authorized_scope(&apex, &cand) || in_authorized_scope(&cand, &apex)
}

/// Host extracted from a URL / host:port / host/path IoC — never a substring of the path.
#[must_use]
pub fn ioc_matches_apex(apex: &str, ioc: &str) -> bool {
    let apex = registrable_apex(apex);
    let ioc = ioc.trim();
    if apex.is_empty() || ioc.is_empty() {
        return false;
    }
    let host = if ioc.contains("://") {
        extract_host(ioc)
    } else {
        let no_path = ioc.split('/').next().unwrap_or(ioc);
        extract_host(&format!("https://{no_path}"))
    };
    if host.is_empty() {
        return false;
    }
    domain_hit_in_scope(&apex, &host)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn live_finding(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    proof: &str,
    source_url: &str,
    http_status: u16,
    confidence: f64,
) -> Value {
    let mut f = finding(engine_id, title, severity, mitre, description, target);
    if let Some(obj) = f.as_object_mut() {
        obj.insert("confidence".into(), json!(confidence));
        obj.insert(
            "evidence".into(),
            json!({
                "proof": proof,
                "source_url": source_url,
                "http_status": http_status,
            }),
        );
        if !source_url.is_empty() {
            obj.insert("evidence_url".into(), json!(source_url));
        }
    }
    f
}

fn health_info_finding(engine_id: &str, target: &str, health: &[SourceHealth]) -> Value {
    let ok = health.iter().filter(|h| h.ok).count();
    let failed: Vec<&str> = health
        .iter()
        .filter(|h| !h.ok)
        .map(|h| h.id.as_str())
        .collect();
    let proof = health
        .iter()
        .map(|h| {
            format!(
                "{} http={} ok={} hits={} ({})",
                h.id, h.http_status, h.ok, h.hit_count, h.message
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    live_finding(
        engine_id,
        &format!(
            "Underground OSINT source health: {ok}/{} reachable",
            health.len()
        ),
        if failed.is_empty() { "info" } else { "low" },
        MITRE,
        &format!(
            "Queried public criminal-index APIs for '{}'. Reachable: {ok}. Failed: {}.",
            extract_host(target),
            if failed.is_empty() {
                "none".to_string()
            } else {
                failed.join(", ")
            }
        ),
        target,
        &proof,
        "",
        0,
        0.9,
    )
}

/// HIBP `/breaches?domain=` returns an array of breach objects.
#[must_use]
pub fn parse_hibp_breaches(body: &str, apex: &str) -> Vec<SourceHit> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    let apex = registrable_apex(apex);
    let mut out = Vec::new();
    for b in arr.iter().take(MAX_HITS) {
        let domain = b
            .get("Domain")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if domain.is_empty() || !domain_hit_in_scope(&apex, &domain) {
            continue;
        }
        let name = b.get("Name").and_then(Value::as_str).unwrap_or("breach");
        let title_name = b.get("Title").and_then(Value::as_str).unwrap_or(name);
        let pwn = b.get("PwnCount").and_then(Value::as_i64).unwrap_or(0);
        let date = b.get("BreachDate").and_then(Value::as_str).unwrap_or("");
        let stealer = b
            .get("IsStealerLog")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let verified = b
            .get("IsVerified")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !verified {
            continue;
        }
        let severity = if stealer { "critical" } else { "high" };
        let url = format!("https://haveibeenpwned.com/PwnedWebsites#{name}");
        let title = format!("HIBP verified breach '{title_name}' for {apex}");
        let evidence = format!(
            "HIBP domain catalog: Name={name} Domain={} BreachDate={date} PwnCount={pwn} IsStealerLog={stealer}",
            domain
        );
        out.push(SourceHit {
            source: "hibp".into(),
            fingerprint: hit_fingerprint("hibp", &title, &url),
            title,
            severity: severity.into(),
            evidence,
            url,
        });
    }
    out
}

/// ransomware.live search is keyword-wide. Only keep exact in-scope domains.
#[must_use]
pub fn parse_ransomware_live_victims(body: &str, apex: &str) -> Vec<SourceHit> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let arr: &[Value] = if let Some(a) = v.as_array() {
        a
    } else if let Some(a) = v.get("victims").and_then(Value::as_array) {
        a
    } else {
        return Vec::new();
    };
    let apex = registrable_apex(apex);
    let mut out = Vec::new();
    for row in arr.iter().take(MAX_HITS * 4) {
        let domain = row
            .get("domain")
            .or_else(|| row.get("website"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let domain = domain
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_start_matches("www.")
            .trim_end_matches('/');
        if domain.is_empty() || !domain_hit_in_scope(&apex, domain) {
            continue;
        }
        let group = row
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let victim = row.get("victim").and_then(Value::as_str).unwrap_or(domain);
        let permalink = row.get("url").and_then(Value::as_str).unwrap_or("");
        let discovered = row.get("discovered").and_then(Value::as_str).unwrap_or("");
        let title = format!("Ransomware leak-site listing: {victim} ({group})");
        let evidence = format!(
            "ransomware.live exact-domain match domain={domain} group={group} discovered={discovered} permalink={permalink}"
        );
        out.push(SourceHit {
            source: "ransomware_live".into(),
            fingerprint: hit_fingerprint("ransomware_live", &title, permalink),
            title,
            severity: "critical".into(),
            evidence,
            url: permalink.to_string(),
        });
    }
    out
}

#[must_use]
pub fn parse_threatfox(body: &str, apex: &str) -> Vec<SourceHit> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let status = v.get("query_status").and_then(Value::as_str).unwrap_or("");
    if status.eq_ignore_ascii_case("no_result") {
        return Vec::new();
    }
    let Some(arr) = v.get("data").and_then(Value::as_array) else {
        return Vec::new();
    };
    let apex = registrable_apex(apex);
    let mut out = Vec::new();
    for row in arr.iter().take(MAX_HITS) {
        let ioc = row.get("ioc").and_then(Value::as_str).unwrap_or("");
        if !ioc_matches_apex(&apex, ioc) {
            continue;
        }
        let malware = row
            .get("malware_printable")
            .or_else(|| row.get("malware"))
            .and_then(Value::as_str)
            .unwrap_or("ioc");
        let threat = row.get("threat_type").and_then(Value::as_str).unwrap_or("");
        let title = format!("ThreatFox IoC for {apex}: {malware}");
        let evidence = format!("ThreatFox ioc={ioc} threat_type={threat} malware={malware}");
        out.push(SourceHit {
            source: "threatfox".into(),
            fingerprint: hit_fingerprint("threatfox", &title, ioc),
            title,
            severity: "high".into(),
            evidence,
            url: "https://threatfox.abuse.ch".into(),
        });
    }
    out
}

#[must_use]
pub fn parse_urlhaus_hostinfo(body: &str, apex: &str) -> Vec<SourceHit> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let listed = v
        .get("query_status")
        .and_then(Value::as_str)
        .map(|s| s.eq_ignore_ascii_case("ok"))
        .unwrap_or(false);
    let urls = v.get("urls").and_then(Value::as_array);
    let n = urls.map(|a| a.len()).unwrap_or(0);
    if !listed || n == 0 {
        return Vec::new();
    }
    let title = format!("URLhaus lists {n} malware URL(s) on {apex}");
    let sample = urls
        .and_then(|a| a.first())
        .and_then(|u| u.get("url").and_then(Value::as_str))
        .unwrap_or("");
    vec![SourceHit {
        source: "urlhaus".into(),
        fingerprint: hit_fingerprint("urlhaus", &title, sample),
        title,
        severity: "high".into(),
        evidence: format!("URLhaus hostinfo query_status=ok url_count={n} sample={sample}"),
        url: format!("https://urlhaus.abuse.ch/host/{apex}/"),
    }]
}

#[must_use]
pub fn parse_urlscan_malicious(body: &str, apex: &str) -> Vec<SourceHit> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let Some(results) = v.get("results").and_then(Value::as_array) else {
        return Vec::new();
    };
    let apex = registrable_apex(apex);
    let mut n = 0u32;
    let mut sample = String::new();
    for row in results {
        let malicious = row
            .pointer("/verdicts/overall/malicious")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || row
                .pointer("/verdicts/urlscan/malicious")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        if !malicious {
            continue;
        }
        let page = row
            .pointer("/page/domain")
            .or_else(|| row.pointer("/task/domain"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if page.is_empty() || !domain_hit_in_scope(&apex, page) {
            continue;
        }
        n += 1;
        if sample.is_empty() {
            sample = row
                .pointer("/task/url")
                .and_then(Value::as_str)
                .unwrap_or(ioc_or_empty(row))
                .to_string();
        }
    }
    if n == 0 {
        return Vec::new();
    }
    let title = format!("urlscan.io marked {n} result(s) malicious for {apex}");
    vec![SourceHit {
        source: "urlscan".into(),
        fingerprint: hit_fingerprint("urlscan", &title, &sample),
        title,
        severity: "high".into(),
        evidence: format!("urlscan search domain={apex} malicious_count={n} sample={sample}"),
        url: format!("https://urlscan.io/search/#domain:{apex}"),
    }]
}

/// Hudson Rock Cavalier OSINT — **counts only**. Never copy emails, cookies, or passwords.
#[must_use]
pub fn parse_hudson_rock_osint(body: &str, apex: &str) -> Vec<SourceHit> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let employees = json_count(
        &v,
        &[
            "total_corporate_services",
            "compromised_employees",
            "employees",
        ],
    );
    let users = json_count(
        &v,
        &[
            "total_user_services",
            "compromised_users",
            "users",
            "clients",
        ],
    );
    let stealer_n = json_count(&v, &["stealers", "total"]);
    let total = employees.max(users).max(stealer_n);
    if total <= 0 {
        return Vec::new();
    }
    let apex = registrable_apex(apex);
    let title = format!("Hudson Rock OSINT: infostealer-index counts for {apex}");
    let evidence = format!(
        "hudsonrock cavalier counts-only employees_or_corp={employees} users_or_clients={users} stealers_or_total={stealer_n} (identities not stored)"
    );
    vec![SourceHit {
        source: "hudson_rock".into(),
        fingerprint: hit_fingerprint("hudson_rock", &title, ""),
        title,
        severity: "high".into(),
        evidence,
        url: format!("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={apex}"),
    }]
}

fn json_count(v: &Value, keys: &[&str]) -> i64 {
    for k in keys {
        if let Some(n) = v.get(*k).and_then(Value::as_i64) {
            if n > 0 {
                return n;
            }
        }
        if let Some(n) = v.get(*k).and_then(Value::as_u64) {
            if n > 0 {
                return n as i64;
            }
        }
        if let Some(a) = v.get(*k).and_then(Value::as_array) {
            if !a.is_empty() {
                return a.len() as i64;
            }
        }
        if let Some(n) = v.pointer(&format!("/data/{k}")).and_then(Value::as_i64) {
            if n > 0 {
                return n;
            }
        }
        if let Some(a) = v.pointer(&format!("/data/{k}")).and_then(Value::as_array) {
            if !a.is_empty() {
                return a.len() as i64;
            }
        }
    }
    0
}

fn ioc_or_empty(row: &Value) -> &str {
    row.get("ioc").and_then(Value::as_str).unwrap_or("")
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

struct ProbeOutcome {
    health: SourceHealth,
    hits: Vec<SourceHit>,
}

fn abusech_auth_key() -> String {
    std::env::var("ABUSECH_AUTH_KEY")
        .or_else(|_| std::env::var("THREATFOX_API_KEY"))
        .or_else(|_| std::env::var("URLHAUS_AUTH_KEY"))
        .unwrap_or_default()
}

fn outcome(id: &str, status: u16, ok: bool, message: &str, hits: Vec<SourceHit>) -> ProbeOutcome {
    ProbeOutcome {
        health: SourceHealth {
            id: id.into(),
            ok,
            http_status: status,
            message: message.into(),
            hit_count: hits.len(),
        },
        hits,
    }
}

async fn probe_hibp(client: &reqwest::Client, apex: &str) -> ProbeOutcome {
    let url = format!(
        "https://haveibeenpwned.com/api/v3/breaches?domain={}",
        urlencoding::encode(apex)
    );
    let key = std::env::var("HIBP_API_KEY")
        .or_else(|_| std::env::var("WEISSMAN_HIBP_API_KEY"))
        .unwrap_or_default();
    let mut headers: Vec<(&str, &str)> = vec![(
        "user-agent",
        "Weissman-Cybersecurity/adversary-underground-delta (authorized-assessment)",
    )];
    if !key.is_empty() {
        headers.push(("hibp-api-key", key.as_str()));
    }
    match http_get_with_headers(client, &url, &headers).await {
        Some(p) if p.status == 200 => {
            let hits = parse_hibp_breaches(&p.body, apex);
            outcome("hibp", p.status, true, "ok", hits)
        }
        Some(p) => outcome(
            "hibp",
            p.status,
            false,
            &format!("HIBP HTTP {}", p.status),
            vec![],
        ),
        None => outcome("hibp", 0, false, "HIBP unreachable", vec![]),
    }
}

async fn probe_ransomware_live(client: &reqwest::Client, apex: &str) -> ProbeOutcome {
    let pro_owned = std::env::var("WEISSMAN_RANSOMWARE_LIVE_API_KEY").unwrap_or_default();
    let url = if pro_owned.is_empty() {
        format!(
            "https://api.ransomware.live/v2/searchvictims/{}",
            urlencoding::encode(apex)
        )
    } else {
        format!(
            "https://api-pro.ransomware.live/victims/search?q={}",
            urlencoding::encode(apex)
        )
    };
    let result = if pro_owned.is_empty() {
        http_get(client, &url).await
    } else {
        http_get_with_headers(client, &url, &[("x-api-key", pro_owned.as_str())]).await
    };
    match result {
        Some(p) if p.status == 200 => {
            let hits = parse_ransomware_live_victims(&p.body, apex);
            outcome("ransomware_live", p.status, true, "ok", hits)
        }
        Some(p) if p.status == 404 => {
            outcome("ransomware_live", p.status, true, "no victims", vec![])
        }
        Some(p) => outcome(
            "ransomware_live",
            p.status,
            false,
            &format!("ransomware.live HTTP {}", p.status),
            vec![],
        ),
        None => outcome(
            "ransomware_live",
            0,
            false,
            "ransomware.live unreachable",
            vec![],
        ),
    }
}

async fn probe_threatfox(client: &reqwest::Client, apex: &str) -> ProbeOutcome {
    let url = "https://threatfox-api.abuse.ch/api/v1/";
    let payload = json!({ "query": "search_ioc", "search_term": apex });
    let key = abusech_auth_key();
    let headers: Vec<(&str, &str)> = if key.is_empty() {
        vec![]
    } else {
        vec![("auth-key", key.as_str())]
    };
    match http_post_json_with_headers(client, url, &payload, &headers).await {
        Some(p) if p.status == 200 => {
            let hits = parse_threatfox(&p.body, apex);
            outcome("threatfox", p.status, true, "ok", hits)
        }
        Some(p) => outcome(
            "threatfox",
            p.status,
            false,
            &format!("ThreatFox HTTP {}", p.status),
            vec![],
        ),
        None => outcome("threatfox", 0, false, "ThreatFox unreachable", vec![]),
    }
}

async fn probe_urlhaus(client: &reqwest::Client, apex: &str) -> ProbeOutcome {
    // Official Auth-Key-optional host lookup (form POST). The HTML /api/v1/hostinfo
    // path is not a JSON contract and must not be treated as a live source.
    let url = "https://urlhaus-api.abuse.ch/v1/host/";
    let form = format!("host={}", urlencoding::encode(apex));
    let key = abusech_auth_key();
    let mut headers: Vec<(&str, &str)> =
        vec![("content-type", "application/x-www-form-urlencoded")];
    if !key.is_empty() {
        headers.push(("auth-key", key.as_str()));
    }
    match http_post_bytes_with_headers(client, url, form.as_bytes(), &headers).await {
        Some(p) if p.status == 200 => {
            let hits = parse_urlhaus_hostinfo(&p.body, apex);
            outcome("urlhaus", p.status, true, "ok", hits)
        }
        Some(p) => outcome(
            "urlhaus",
            p.status,
            false,
            &format!("URLhaus HTTP {}", p.status),
            vec![],
        ),
        None => outcome("urlhaus", 0, false, "URLhaus unreachable", vec![]),
    }
}

async fn probe_urlscan(client: &reqwest::Client, apex: &str) -> ProbeOutcome {
    let q = format!("page.domain:\"{apex}\"");
    let url = format!(
        "https://urlscan.io/api/v1/search/?q={}",
        urlencoding::encode(&q)
    );
    let key = std::env::var("URLSCAN_API_KEY").unwrap_or_default();
    let headers: Vec<(&str, &str)> = if key.is_empty() {
        vec![]
    } else {
        vec![("api-key", key.as_str())]
    };
    match http_get_with_headers(client, &url, &headers).await {
        Some(p) if p.status == 200 => {
            let hits = parse_urlscan_malicious(&p.body, apex);
            outcome("urlscan", p.status, true, "ok", hits)
        }
        Some(p) => outcome(
            "urlscan",
            p.status,
            false,
            &format!("urlscan HTTP {}", p.status),
            vec![],
        ),
        None => outcome("urlscan", 0, false, "urlscan unreachable", vec![]),
    }
}

async fn probe_hudson_rock(client: &reqwest::Client, apex: &str) -> ProbeOutcome {
    let url = format!(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={}",
        urlencoding::encode(apex)
    );
    match http_get_with_headers(
        client,
        &url,
        &[(
            "user-agent",
            "Weissman-Cybersecurity/adversary-underground-delta (authorized-assessment)",
        )],
    )
    .await
    {
        Some(p) if p.status == 200 => {
            let hits = parse_hudson_rock_osint(&p.body, apex);
            outcome("hudson_rock", p.status, true, "ok", hits)
        }
        Some(p) => outcome(
            "hudson_rock",
            p.status,
            false,
            &format!("Hudson Rock HTTP {}", p.status),
            vec![],
        ),
        None => outcome("hudson_rock", 0, false, "Hudson Rock unreachable", vec![]),
    }
}

/// Shared public OSINT collection (cached ~90s per apex).
pub async fn collect_public_osint(apex: &str) -> (Vec<SourceHit>, Vec<SourceHealth>) {
    let apex = registrable_apex(apex);
    if apex.is_empty() {
        return (Vec::new(), Vec::new());
    }
    if let Some(hit) = cache().get(&apex) {
        if hit.at.elapsed() < CACHE_TTL {
            return (hit.hits.clone(), hit.health.clone());
        }
    }
    let client = http_client().await;
    let (hibp, ransom, fox, haus, scan, hudson) = tokio::join!(
        probe_hibp(&client, &apex),
        probe_ransomware_live(&client, &apex),
        probe_threatfox(&client, &apex),
        probe_urlhaus(&client, &apex),
        probe_urlscan(&client, &apex),
        probe_hudson_rock(&client, &apex),
    );
    let mut hits = Vec::new();
    let mut health = Vec::new();
    for p in [hibp, ransom, fox, haus, scan, hudson] {
        hits.extend(p.hits);
        health.push(p.health);
    }
    hits.truncate(MAX_HITS);
    let reachable = health.iter().filter(|h| h.ok).count();
    if reachable > 0 {
        cache().insert(
            apex.clone(),
            CachedOsint {
                at: Instant::now(),
                hits: hits.clone(),
                health: health.clone(),
            },
        );
    }
    (hits, health)
}

fn findings_from_hits(engine_id: &str, target: &str, hits: &[SourceHit]) -> Vec<Value> {
    hits.iter()
        .map(|h| {
            live_finding(
                engine_id,
                &h.title,
                &h.severity,
                MITRE,
                &h.evidence,
                target,
                &h.evidence,
                &h.url,
                200,
                0.96,
            )
        })
        .collect()
}

/// Used by `darkweb_intel` / `dark_web_monitor` so they are live without IntelX.
pub async fn run_public_osint_result(engine_id: &str, target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let apex = registrable_apex(&extract_host(target));
    if apex.is_empty() {
        return EngineResult::error("could not extract host from target");
    }
    let (hits, health) = collect_public_osint(&apex).await;
    let reachable = health.iter().filter(|h| h.ok).count();
    if reachable == 0 {
        return EngineResult::error(format!(
            "{engine_id}: all public OSINT sources unreachable for {apex}"
        ));
    }
    let mut findings = findings_from_hits(engine_id, target, &hits);
    findings.insert(0, health_info_finding(engine_id, target, &health));
    EngineResult::ok(
        findings,
        format!("{engine_id}: {} hits, {reachable} sources ok", hits.len()),
    )
}

fn diff_hits(previous: &[SourceHit], current: &[SourceHit]) -> (Vec<SourceHit>, Vec<SourceHit>) {
    let prev: std::collections::BTreeSet<&str> =
        previous.iter().map(|h| h.fingerprint.as_str()).collect();
    let cur: std::collections::BTreeSet<&str> =
        current.iter().map(|h| h.fingerprint.as_str()).collect();
    let added: Vec<SourceHit> = current
        .iter()
        .filter(|h| !prev.contains(h.fingerprint.as_str()))
        .cloned()
        .collect();
    let removed: Vec<SourceHit> = previous
        .iter()
        .filter(|h| !cur.contains(h.fingerprint.as_str()))
        .cloned()
        .collect();
    (added, removed)
}

async fn load_previous_snapshot(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    apex: &str,
) -> Result<Option<UndergroundSnapshot>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let row = sqlx::query(
        r#"SELECT snapshot_json FROM underground_snapshots
           WHERE tenant_id = $1 AND client_id = $2
             AND snapshot_json->>'apex' = $3
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(apex)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(row.and_then(|r| {
        let v: Value = r.try_get("snapshot_json").ok()?;
        serde_json::from_value(v).ok()
    }))
}

async fn persist_snapshot(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    snap: &UndergroundSnapshot,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let json = serde_json::to_value(snap).map_err(|e| e.to_string())?;
    sqlx::query(
        r#"INSERT INTO underground_snapshots (tenant_id, client_id, snapshot_json, hit_count)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(json)
    .bind(snap.hits.len() as i32)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    sqlx::query(
        r#"WITH ranked AS (
             SELECT id, row_number() OVER (ORDER BY created_at DESC) AS rn
               FROM underground_snapshots
              WHERE tenant_id = $1 AND client_id = $2
                AND snapshot_json->>'apex' = $4
           )
           DELETE FROM underground_snapshots
            WHERE tenant_id = $1 AND client_id = $2
              AND snapshot_json->>'apex' = $4
              AND id IN (SELECT id FROM ranked WHERE rn > $3)"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(SNAPSHOT_KEEP)
    .bind(&snap.apex)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn enqueue_leak_hunter(ctx: &EngineRunContext, apex: &str, added: &[SourceHit]) {
    if !pbool(&ctx.job_params, "chain_leak_hunter", true) {
        return;
    }
    if !added
        .iter()
        .any(|h| h.severity == "critical" || h.severity == "high")
    {
        return;
    }
    let (Some(pool), Some(tid), Some(cid)) = (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id)
    else {
        return;
    };
    for eng in FOLLOW_ON_ENGINES {
        let payload = json!({
            "engine": *eng,
            "target": format!("https://{apex}"),
            "client_id": cid,
            "trigger": ENGINE_ID,
            "parent_fqdn": apex,
        });
        if let Err(e) =
            crate::async_jobs::enqueue(pool.as_ref(), tid, "command_center_engine", payload, None)
                .await
        {
            tracing::warn!(target: ENGINE_ID, error = %e, "follow-on enqueue failed");
        }
    }
}

pub async fn run_adversary_underground_delta_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let apex = registrable_apex(&extract_host(target));
    if apex.is_empty() {
        return EngineResult::error("could not extract host from target");
    }

    let previous = match (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id) {
        (Some(pool), Some(tid), Some(cid)) => {
            match load_previous_snapshot(pool, tid, cid, &apex).await {
                Ok(p) => p,
                Err(e) => {
                    return EngineResult::error(format!("underground snapshot read failed: {e}"));
                }
            }
        }
        _ => None,
    };

    let (hits, health) = collect_public_osint(&apex).await;
    let reachable = health.iter().filter(|h| h.ok).count();
    if reachable == 0 {
        return EngineResult::error(format!(
            "{ENGINE_ID}: all public OSINT sources unreachable for {apex}"
        ));
    }

    let current = UndergroundSnapshot {
        apex: apex.clone(),
        hits: hits.clone(),
        health: health.clone(),
    };

    if let (Some(pool), Some(tid), Some(cid)) =
        (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id)
    {
        if let Err(e) = persist_snapshot(pool, tid, cid, &current).await {
            return EngineResult::error(format!("underground snapshot persist failed: {e}"));
        }
    }

    let (added, _removed) = match &previous {
        Some(prev) => diff_hits(&prev.hits, &current.hits),
        None => (hits.clone(), Vec::new()),
    };
    let baseline = previous.is_none();

    let emit = if baseline { &hits } else { &added };
    if !baseline {
        enqueue_leak_hunter(ctx, &apex, &added).await;
    }

    let mut findings = findings_from_hits(ENGINE_ID, target, emit);
    findings.insert(0, health_info_finding(ENGINE_ID, target, &health));
    if baseline {
        findings.push(live_finding(
            ENGINE_ID,
            &format!(
                "Underground baseline established for {apex} ({} hits)",
                hits.len()
            ),
            "info",
            MITRE,
            "First run stored a criminal-index snapshot. Subsequent runs emit only new hits.",
            target,
            &format!("baseline_hits={}", hits.len()),
            "",
            200,
            0.9,
        ));
    } else if added.is_empty() {
        findings.push(live_finding(
            ENGINE_ID,
            &format!("No new underground-index hits for {apex} since last snapshot"),
            "info",
            MITRE,
            &format!(
                "Current catalog size {} — delta is empty (not an invented all-clear: {} sources answered).",
                hits.len(),
                reachable
            ),
            target,
            &format!("delta_empty current={}", hits.len()),
            "",
            200,
            0.9,
        ));
    }

    if findings.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }
    EngineResult::ok(
        findings,
        format!(
            "{ENGINE_ID}: {} current, {} new, baseline={baseline}",
            hits.len(),
            added.len()
        ),
    )
}

#[must_use]
pub fn underground_unavailable_json(client_id: i64) -> Value {
    json!({
        "client_id": client_id,
        "unavailable": true,
        "message": "underground exposure temporarily unavailable",
        "sources": [],
        "health": [],
        "added": [],
        "removed": [],
        "current_count": 0,
        "previous_count": 0,
        "baseline_only": false,
        "findings": [],
    })
}

pub async fn api_underground_exposure_json(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    apex: Option<&str>,
) -> Result<Value, String> {
    let apex_filter = apex
        .map(registrable_apex)
        .filter(|a| !a.is_empty() && a.contains('.'));
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rows = if let Some(ref apex) = apex_filter {
        sqlx::query(
            r#"SELECT snapshot_json, hit_count, created_at
               FROM underground_snapshots
               WHERE tenant_id = $1 AND client_id = $2
                 AND snapshot_json->>'apex' = $3
               ORDER BY created_at DESC
               LIMIT 2"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(apex)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| e.to_string())?
    } else {
        sqlx::query(
            r#"SELECT snapshot_json, hit_count, created_at
               FROM underground_snapshots
               WHERE tenant_id = $1 AND client_id = $2
               ORDER BY created_at DESC
               LIMIT 2"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| e.to_string())?
    };

    let sources: Vec<String> = UNDERGROUND_SOURCES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let persisted = sqlx::query(
        r#"SELECT id, title, severity, source, description, discovered_at
           FROM vulnerabilities
           WHERE tenant_id = $1 AND client_id = $2
             AND source = ANY($3)
             AND status NOT IN ('FIXED','FALSE_POSITIVE','VERIFIED_FIXED')
           ORDER BY discovered_at DESC
           LIMIT 200"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&sources)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;

    let findings: Vec<Value> = persisted
        .iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "title": r.try_get::<String,_>("title").unwrap_or_default(),
                "severity": r.try_get::<String,_>("severity").unwrap_or_default(),
                "source": r.try_get::<String,_>("source").unwrap_or_default(),
                "description": r.try_get::<String,_>("description").unwrap_or_default(),
                "discovered_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("discovered_at")
                    .ok()
                    .map(|d| d.to_rfc3339()),
            })
        })
        .collect();

    if rows.is_empty() {
        return Ok(json!({
            "client_id": client_id,
            "unavailable": false,
            "message": "No underground snapshot yet — run adversary_underground_delta against an authorized domain.",
            "sources": [],
            "health": [],
            "added": [],
            "removed": [],
            "current_count": 0,
            "previous_count": 0,
            "current_at": Value::Null,
            "previous_at": Value::Null,
            "baseline_only": false,
            "findings": findings,
        }));
    }

    let current_json: Value = rows[0]
        .try_get("snapshot_json")
        .map_err(|e| e.to_string())?;
    let current: UndergroundSnapshot = serde_json::from_value(current_json).unwrap_or_default();
    let current_at: chrono::DateTime<chrono::Utc> = rows[0]
        .try_get("created_at")
        .unwrap_or_else(|_| chrono::Utc::now());
    let current_count: i32 = rows[0].try_get("hit_count").unwrap_or(0);

    let (added, removed, previous_count, previous_at, baseline_only) = if rows.len() > 1 {
        let prev_json: Value = rows[1]
            .try_get("snapshot_json")
            .map_err(|e| e.to_string())?;
        let prev: UndergroundSnapshot = serde_json::from_value(prev_json).unwrap_or_default();
        let prev_at: chrono::DateTime<chrono::Utc> = rows[1]
            .try_get("created_at")
            .unwrap_or_else(|_| chrono::Utc::now());
        let prev_count: i32 = rows[1].try_get("hit_count").unwrap_or(0);
        let (added, removed) = diff_hits(&prev.hits, &current.hits);
        (added, removed, prev_count, Some(prev_at), false)
    } else {
        (Vec::new(), Vec::new(), 0, None, true)
    };

    Ok(json!({
        "client_id": client_id,
        "unavailable": false,
        "message": if baseline_only {
            "Baseline snapshot only — next hunt emits the delta."
        } else {
            "Live snapshot vs previous underground catalog."
        },
        "apex": current.apex,
        "sources": current.hits.iter().map(|h| &h.source).collect::<std::collections::BTreeSet<_>>(),
        "health": current.health,
        "added": added,
        "removed": removed,
        "current_count": current_count,
        "previous_count": previous_count,
        "current_at": current_at.to_rfc3339(),
        "previous_at": previous_at.map(|t| t.to_rfc3339()),
        "baseline_only": baseline_only,
        "hits": current.hits,
        "findings": findings,
    }))
}

/// Excel 2003 XML spreadsheet — opens natively in Excel without a zip crate.
pub fn build_underground_excel_xml(payload: &Value) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
"#,
    );
    xml.push_str("<Worksheet ss:Name=\"Hits\"><Table>\n");
    xml.push_str(
        "<Row><Cell><Data ss:Type=\"String\">Severity</Data></Cell><Cell><Data ss:Type=\"String\">Source</Data></Cell><Cell><Data ss:Type=\"String\">Title</Data></Cell><Cell><Data ss:Type=\"String\">Evidence</Data></Cell><Cell><Data ss:Type=\"String\">URL</Data></Cell></Row>\n",
    );
    let hits = payload
        .get("hits")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let findings = payload
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rows: Vec<Value> = if hits.is_empty() { findings } else { hits };
    for h in rows {
        let sev = h.get("severity").and_then(Value::as_str).unwrap_or("");
        let src = h.get("source").and_then(Value::as_str).unwrap_or("");
        let title = h.get("title").and_then(Value::as_str).unwrap_or("");
        let ev = h
            .get("evidence")
            .or_else(|| h.get("description"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let url = h.get("url").and_then(Value::as_str).unwrap_or("");
        xml.push_str(&format!(
            "<Row><Cell><Data ss:Type=\"String\">{}</Data></Cell><Cell><Data ss:Type=\"String\">{}</Data></Cell><Cell><Data ss:Type=\"String\">{}</Data></Cell><Cell><Data ss:Type=\"String\">{}</Data></Cell><Cell><Data ss:Type=\"String\">{}</Data></Cell></Row>\n",
            xml_escape(sev),
            xml_escape(src),
            xml_escape(title),
            xml_escape(ev),
            xml_escape(url),
        ));
    }
    xml.push_str("</Table></Worksheet>\n");
    xml.push_str("<Worksheet ss:Name=\"Delta\"><Table>\n");
    xml.push_str(
        "<Row><Cell><Data ss:Type=\"String\">Kind</Data></Cell><Cell><Data ss:Type=\"String\">Title</Data></Cell><Cell><Data ss:Type=\"String\">Source</Data></Cell></Row>\n",
    );
    for (kind, key) in [("added", "added"), ("removed", "removed")] {
        if let Some(arr) = payload.get(key).and_then(Value::as_array) {
            for h in arr {
                xml.push_str(&format!(
                    "<Row><Cell><Data ss:Type=\"String\">{}</Data></Cell><Cell><Data ss:Type=\"String\">{}</Data></Cell><Cell><Data ss:Type=\"String\">{}</Data></Cell></Row>\n",
                    kind,
                    xml_escape(h.get("title").and_then(Value::as_str).unwrap_or("")),
                    xml_escape(h.get("source").and_then(Value::as_str).unwrap_or("")),
                ));
            }
        }
    }
    xml.push_str("</Table></Worksheet>\n");
    xml.push_str("<Worksheet ss:Name=\"Sources\"><Table>\n");
    xml.push_str(
        "<Row><Cell><Data ss:Type=\"String\">Source</Data></Cell><Cell><Data ss:Type=\"String\">Reachable</Data></Cell><Cell><Data ss:Type=\"String\">HTTP</Data></Cell><Cell><Data ss:Type=\"String\">Hits</Data></Cell><Cell><Data ss:Type=\"String\">Message</Data></Cell></Row>\n",
    );
    if let Some(arr) = payload.get("health").and_then(Value::as_array) {
        for h in arr {
            xml.push_str(&format!(
                "<Row><Cell><Data ss:Type=\"String\">{}</Data></Cell><Cell><Data ss:Type=\"String\">{}</Data></Cell><Cell><Data ss:Type=\"String\">{}</Data></Cell><Cell><Data ss:Type=\"String\">{}</Data></Cell><Cell><Data ss:Type=\"String\">{}</Data></Cell></Row>\n",
                xml_escape(h.get("id").and_then(Value::as_str).unwrap_or("")),
                xml_escape(&h.get("ok").and_then(Value::as_bool).unwrap_or(false).to_string()),
                xml_escape(&h.get("http_status").map(|v| v.to_string()).unwrap_or_default()),
                xml_escape(&h.get("hit_count").map(|v| v.to_string()).unwrap_or_default()),
                xml_escape(h.get("message").and_then(Value::as_str).unwrap_or("")),
            ));
        }
    }
    xml.push_str("</Table></Worksheet>\n</Workbook>\n");
    xml
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ransomware_live_drops_description_false_positives() {
        let body = r#"[{"victim":"Hardware Asesorias","domain":"www.hasltda.com","group":"Deadlock","url":"https://www.ransomware.live/id/x","discovered":"2026-07-27"},{"victim":"Adobe Partner Co","domain":"adobe.com","group":"lockbit","url":"https://www.ransomware.live/id/adobe","discovered":"2026-01-01"}]"#;
        let hits = parse_ransomware_live_victims(body, "adobe.com");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].title.contains("lockbit") || hits[0].evidence.contains("adobe.com"));
        assert!(hits.iter().all(|h| h.evidence.contains("adobe.com")));
    }

    #[test]
    fn hibp_parses_verified_breach() {
        let body = r#"[{"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","PwnCount":152445165,"IsVerified":true,"IsStealerLog":false}]"#;
        let hits = parse_hibp_breaches(body, "www.adobe.com");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, "high");
        assert!(hits[0].evidence.contains("PwnCount=152445165"));
    }

    #[test]
    fn hibp_skips_unverified() {
        let body =
            r#"[{"Name":"X","Title":"X","Domain":"adobe.com","IsVerified":false,"PwnCount":1}]"#;
        assert!(parse_hibp_breaches(body, "adobe.com").is_empty());
    }

    #[test]
    fn hibp_skips_empty_domain_field() {
        let body = r#"[{"Name":"X","Title":"X","Domain":"","IsVerified":true,"PwnCount":1}]"#;
        assert!(parse_hibp_breaches(body, "adobe.com").is_empty());
    }

    #[test]
    fn hudson_rock_counts_only_no_identity_copy() {
        let body = r#"{"total_corporate_services":4,"total_user_services":12,"employees":[{"email":"secret@adobe.com"}]}"#;
        let hits = parse_hudson_rock_osint(body, "adobe.com");
        assert_eq!(hits.len(), 1);
        assert!(!hits[0].evidence.contains("secret@"));
        assert!(hits[0].evidence.contains("counts-only"));
        assert!(
            parse_hudson_rock_osint(r#"{"total_corporate_services":0}"#, "adobe.com").is_empty()
        );
    }

    #[test]
    fn threatfox_no_result_is_empty() {
        let body = r#"{"query_status":"no_result"}"#;
        assert!(parse_threatfox(body, "example.com").is_empty());
    }

    #[test]
    fn urlhaus_requires_ok_and_urls() {
        let empty = r#"{"query_status":"no_results"}"#;
        assert!(parse_urlhaus_hostinfo(empty, "example.com").is_empty());
        let hit = r#"{"query_status":"ok","urls":[{"url":"http://example.com/malware"}]}"#;
        assert_eq!(parse_urlhaus_hostinfo(hit, "example.com").len(), 1);
    }

    #[test]
    fn urlscan_ignores_benign() {
        let body = r#"{"results":[{"verdicts":{"overall":{"malicious":false}},"page":{"domain":"example.com"}}]}"#;
        assert!(parse_urlscan_malicious(body, "example.com").is_empty());
        let mal = r#"{"results":[{"verdicts":{"overall":{"malicious":true}},"page":{"domain":"example.com"},"task":{"url":"https://example.com/phish"}}]}"#;
        assert_eq!(parse_urlscan_malicious(mal, "example.com").len(), 1);
        let empty_page =
            r#"{"results":[{"verdicts":{"overall":{"malicious":true}},"page":{"domain":""}}]}"#;
        assert!(parse_urlscan_malicious(empty_page, "example.com").is_empty());
    }

    #[test]
    fn delta_detects_new_fingerprint() {
        let a = SourceHit {
            source: "hibp".into(),
            fingerprint: "aaa".into(),
            title: "old".into(),
            severity: "high".into(),
            evidence: "e".into(),
            url: "".into(),
        };
        let b = SourceHit {
            source: "hibp".into(),
            fingerprint: "bbb".into(),
            title: "new".into(),
            severity: "high".into(),
            evidence: "e".into(),
            url: "".into(),
        };
        let (added, removed) = diff_hits(std::slice::from_ref(&a), &[a.clone(), b.clone()]);
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].fingerprint, "bbb");
        assert!(removed.is_empty());
    }

    #[test]
    fn excel_xml_contains_workbook_and_escaped_cells() {
        let payload = json!({
            "hits": [{"severity":"high","source":"hibp","title":"A <B>","evidence":"x&y","url":"https://x"}]
        });
        let xml = build_underground_excel_xml(&payload);
        assert!(xml.contains("Excel.Sheet"));
        assert!(xml.contains("A &lt;B&gt;"));
        assert!(xml.contains("x&amp;y"));
        let with_health = json!({
            "health": [{"id":"hibp","ok":true,"http_status":200,"hit_count":1,"message":"ok"}]
        });
        assert!(build_underground_excel_xml(&with_health).contains("hibp"));
    }

    #[test]
    fn threatfox_matches_host_not_path_substring() {
        let steal = r#"{"query_status":"ok","data":[{"ioc":"https://stealadobe.com/payload","malware_printable":"x","threat_type":"payload"}]}"#;
        assert!(parse_threatfox(steal, "adobe.com").is_empty());
        let hit = r#"{"query_status":"ok","data":[{"ioc":"https://cdn.adobe.com/a.exe","malware_printable":"stealer","threat_type":"payload_delivery"}]}"#;
        assert_eq!(parse_threatfox(hit, "adobe.com").len(), 1);
        assert!(ioc_matches_apex("adobe.com", "adobe.com:443"));
        assert!(!ioc_matches_apex("adobe.com", "notadobe.com"));
    }

    #[test]
    fn domain_scope_rejects_partner_mentions() {
        assert!(!domain_hit_in_scope("adobe.com", "hasltda.com"));
        assert!(domain_hit_in_scope("adobe.com", "www.adobe.com"));
        assert!(domain_hit_in_scope("adobe.com", "mail.adobe.com"));
    }
}
