//! IOC feed connectors.
//!
//! Each public feed has (a) a **pure parser** `parse_*` that turns an
//! already-decoded JSON/text body into normalized [`Indicator`]s — unit-tested
//! against embedded fixtures, no network — and (b) a thin `fetch_*` that pulls
//! the live body over the audited [`crate::outbound_http`] client and parses it.
//!
//! Feeds requiring credentials (ThreatFox/URLhaus Auth-Key, OTX, MISP) fail
//! **visibly** when the key is absent: they log an error and return an empty
//! vector rather than fabricating data. This honors the live-only doctrine.

use super::{guess_type, Indicator, IocType};
use serde_json::{json, Value};
use std::time::Duration;

// Matches the platform-wide abuse.ch key name already used by
// adversary_gap_mirror / adversary_exposure_delta / public_leak_osint, so one
// key serves every abuse.ch consumer.
const ABUSE_CH_AUTH_ENV: &str = "ABUSECH_AUTH_KEY";
const OTX_KEY_ENV: &str = "OTX_API_KEY";
const MISP_URL_ENV: &str = "MISP_URL";
const MISP_KEY_ENV: &str = "MISP_API_KEY";
const CUSTOM_BLOCKLIST_ENV: &str = "IOC_CUSTOM_BLOCKLIST_URLS";

const THREATFOX_URL: &str = "https://threatfox-api.abuse.ch/api/v1/";
const URLHAUS_URL: &str = "https://urlhaus.abuse.ch/downloads/json_recent/";
const FEODO_URL: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";
const OTX_SUBSCRIBED_URL: &str = "https://otx.alienvault.com/api/v1/pulses/subscribed";

const FETCH_TIMEOUT_SECS: u64 = 30;

/// The set of feeds the orchestrator knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedSource {
    ThreatFox,
    UrlHaus,
    Feodo,
    Otx,
    Misp,
    CustomBlocklist,
}

impl FeedSource {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            FeedSource::ThreatFox => "threatfox",
            FeedSource::UrlHaus => "urlhaus",
            FeedSource::Feodo => "feodo",
            FeedSource::Otx => "otx",
            FeedSource::Misp => "misp",
            FeedSource::CustomBlocklist => "blocklist",
        }
    }

    /// True when the required credentials/config for this feed are present.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        match self {
            // Feodo's blocklist is open; ThreatFox/URLhaus now require an Auth-Key.
            FeedSource::Feodo => true,
            FeedSource::ThreatFox | FeedSource::UrlHaus => env_present(ABUSE_CH_AUTH_ENV),
            FeedSource::Otx => env_present(OTX_KEY_ENV),
            FeedSource::Misp => env_present(MISP_URL_ENV) && env_present(MISP_KEY_ENV),
            FeedSource::CustomBlocklist => env_present(CUSTOM_BLOCKLIST_ENV),
        }
    }
}

/// Resolve "is this credential configured" through the DB-first credential
/// store (dashboard-managed), falling back to the environment variable.
fn env_present(key: &str) -> bool {
    super::creds::is_set(key)
}

/// Feeds that are configured and should run this cycle.
#[must_use]
pub fn enabled_feeds() -> Vec<FeedSource> {
    [
        FeedSource::Feodo,
        FeedSource::ThreatFox,
        FeedSource::UrlHaus,
        FeedSource::Otx,
        FeedSource::Misp,
        FeedSource::CustomBlocklist,
    ]
    .into_iter()
    .filter(FeedSource::is_configured)
    .collect()
}

#[derive(Debug)]
pub enum FeedError {
    NotConfigured(&'static str),
    Client(String),
    Request(String),
    Status(u16),
    Decode(String),
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeedError::NotConfigured(k) => write!(f, "feed not configured (missing {k})"),
            FeedError::Client(s) => write!(f, "client: {s}"),
            FeedError::Request(s) => write!(f, "request: {s}"),
            FeedError::Status(c) => write!(f, "HTTP {c}"),
            FeedError::Decode(s) => write!(f, "decode: {s}"),
        }
    }
}
impl std::error::Error for FeedError {}

fn client() -> Result<reqwest::Client, FeedError> {
    crate::outbound_http::external_client_builder()
        .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
        .build()
        .map_err(|e| FeedError::Client(e.to_string()))
}

/// Dispatch a single feed fetch by source.
pub async fn fetch(source: FeedSource) -> Result<Vec<Indicator>, FeedError> {
    match source {
        FeedSource::ThreatFox => fetch_threatfox(3).await,
        FeedSource::UrlHaus => fetch_urlhaus().await,
        FeedSource::Feodo => fetch_feodo().await,
        FeedSource::Otx => fetch_otx().await,
        FeedSource::Misp => fetch_misp().await,
        FeedSource::CustomBlocklist => fetch_custom_blocklists().await,
    }
}

// ──────────────────────────────── ThreatFox ────────────────────────────────

/// Fetch recent ThreatFox IOCs (abuse.ch). Requires `ABUSECH_AUTH_KEY`.
pub async fn fetch_threatfox(days: u32) -> Result<Vec<Indicator>, FeedError> {
    let key =
        super::creds::get(ABUSE_CH_AUTH_ENV).ok_or(FeedError::NotConfigured(ABUSE_CH_AUTH_ENV))?;
    let body = json!({"query": "get_iocs", "days": days.clamp(1, 7)});
    let resp = client()?
        .post(THREATFOX_URL)
        .header("Auth-Key", key)
        .json(&body)
        .send()
        .await
        .map_err(|e| FeedError::Request(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(FeedError::Status(status.as_u16()));
    }
    let v: Value = resp
        .json()
        .await
        .map_err(|e| FeedError::Decode(e.to_string()))?;
    Ok(parse_threatfox(&v))
}

/// Pure parser for the ThreatFox `get_iocs` response envelope.
#[must_use]
pub fn parse_threatfox(v: &Value) -> Vec<Indicator> {
    let Some(data) = v.get("data").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in data {
        let raw = item.get("ioc").and_then(Value::as_str).unwrap_or("");
        if raw.is_empty() {
            continue;
        }
        let ty = item
            .get("ioc_type")
            .and_then(Value::as_str)
            .and_then(IocType::from_str_lenient)
            .or_else(|| guess_type(raw));
        let Some(ty) = ty else { continue };
        let confidence = item
            .get("confidence_level")
            .and_then(Value::as_u64)
            .map(|c| c.min(100) as u8)
            .unwrap_or(60);
        let family = item
            .get("malware_printable")
            .or_else(|| item.get("malware"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let tags = item
            .get("tags")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|t| t.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let ind = Indicator::new(ty, raw, "threatfox")
            .with_confidence(confidence)
            .with_severity(severity_from_confidence(confidence))
            .with_family(family)
            .with_tags(tags);
        if ind.is_valid() {
            out.push(ind);
        }
    }
    out
}

// ───────────────────────────────── URLhaus ─────────────────────────────────

/// Fetch URLhaus recent malware URLs (abuse.ch). Requires `ABUSECH_AUTH_KEY`.
pub async fn fetch_urlhaus() -> Result<Vec<Indicator>, FeedError> {
    let key =
        super::creds::get(ABUSE_CH_AUTH_ENV).ok_or(FeedError::NotConfigured(ABUSE_CH_AUTH_ENV))?;
    let resp = client()?
        .get(URLHAUS_URL)
        .header("Auth-Key", key)
        .send()
        .await
        .map_err(|e| FeedError::Request(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(FeedError::Status(status.as_u16()));
    }
    let v: Value = resp
        .json()
        .await
        .map_err(|e| FeedError::Decode(e.to_string()))?;
    Ok(parse_urlhaus(&v))
}

/// Pure parser for the URLhaus `json_recent` map (id → [record]).
#[must_use]
pub fn parse_urlhaus(v: &Value) -> Vec<Indicator> {
    let Some(map) = v.as_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (_id, arr) in map {
        let Some(records) = arr.as_array() else {
            continue;
        };
        for rec in records {
            let url = rec.get("url").and_then(Value::as_str).unwrap_or("");
            if url.is_empty() {
                continue;
            }
            let online = rec
                .get("url_status")
                .and_then(Value::as_str)
                .map(|s| s.eq_ignore_ascii_case("online"))
                .unwrap_or(true);
            let threat = rec
                .get("threat")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let tags = rec
                .get("tags")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let confidence = if online { 80 } else { 45 };
            let ind = Indicator::new(IocType::Url, url, "urlhaus")
                .with_confidence(confidence)
                .with_severity(if online { "high" } else { "medium" })
                .with_family(threat)
                .with_tags(tags)
                .with_reference(
                    rec.get("urlhaus_reference")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                );
            if ind.is_valid() {
                out.push(ind);
            }
        }
    }
    out
}

// ────────────────────────────────── Feodo ──────────────────────────────────

/// Fetch the Feodo Tracker C2 IP blocklist (abuse.ch, open, no key).
pub async fn fetch_feodo() -> Result<Vec<Indicator>, FeedError> {
    let bytes = crate::outbound_http::get_bytes_with_retry(
        &client()?,
        FEODO_URL,
        reqwest::header::HeaderMap::new(),
        3,
        Some("feodo"),
    )
    .await
    .map_err(|e| FeedError::Request(e.to_string()))?;
    let v: Value = serde_json::from_slice(&bytes).map_err(|e| FeedError::Decode(e.to_string()))?;
    Ok(parse_feodo(&v))
}

/// Pure parser for the Feodo ipblocklist JSON array.
#[must_use]
pub fn parse_feodo(v: &Value) -> Vec<Indicator> {
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for rec in arr {
        let ip = rec.get("ip_address").and_then(Value::as_str).unwrap_or("");
        if ip.is_empty() {
            continue;
        }
        let family = rec
            .get("malware")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut tags = vec!["c2".to_string()];
        if let Some(port) = rec.get("port").and_then(Value::as_u64) {
            tags.push(format!("port:{port}"));
        }
        let ind = Indicator::new(IocType::Ipv4, ip, "feodo")
            .with_confidence(85)
            .with_severity("high")
            .with_family(family)
            .with_tags(tags);
        if ind.is_valid() {
            out.push(ind);
        }
    }
    out
}

// ─────────────────────────────────── OTX ───────────────────────────────────

/// Fetch subscribed AlienVault OTX pulses. Requires `OTX_API_KEY`.
pub async fn fetch_otx() -> Result<Vec<Indicator>, FeedError> {
    let key = super::creds::get(OTX_KEY_ENV).ok_or(FeedError::NotConfigured(OTX_KEY_ENV))?;
    let url = format!("{OTX_SUBSCRIBED_URL}?limit=50&modified_since=");
    let resp = client()?
        .get(&url)
        .header("X-OTX-API-KEY", key)
        .send()
        .await
        .map_err(|e| FeedError::Request(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(FeedError::Status(status.as_u16()));
    }
    let v: Value = resp
        .json()
        .await
        .map_err(|e| FeedError::Decode(e.to_string()))?;
    Ok(parse_otx(&v))
}

/// Pure parser for OTX subscribed-pulses response.
#[must_use]
pub fn parse_otx(v: &Value) -> Vec<Indicator> {
    let Some(results) = v.get("results").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for pulse in results {
        let pulse_name = pulse.get("name").and_then(Value::as_str).unwrap_or("");
        let Some(indicators) = pulse.get("indicators").and_then(Value::as_array) else {
            continue;
        };
        for ind_v in indicators {
            let raw = ind_v.get("indicator").and_then(Value::as_str).unwrap_or("");
            if raw.is_empty() {
                continue;
            }
            let ty = map_otx_type(ind_v.get("type").and_then(Value::as_str).unwrap_or(""))
                .or_else(|| guess_type(raw));
            let Some(ty) = ty else { continue };
            let ind = Indicator::new(ty, raw, "otx")
                .with_confidence(65)
                .with_severity("medium")
                .with_tags(if pulse_name.is_empty() {
                    Vec::new()
                } else {
                    vec![format!("pulse:{pulse_name}")]
                });
            if ind.is_valid() {
                out.push(ind);
            }
        }
    }
    out
}

fn map_otx_type(t: &str) -> Option<IocType> {
    Some(match t {
        "IPv4" => IocType::Ipv4,
        "IPv6" => IocType::Ipv6,
        "domain" | "hostname" => IocType::Domain,
        "URL" | "URI" => IocType::Url,
        "FileHash-SHA256" => IocType::Sha256,
        "FileHash-SHA1" => IocType::Sha1,
        "FileHash-MD5" => IocType::Md5,
        "email" => IocType::Email,
        "CIDR" => IocType::Cidr,
        _ => return None,
    })
}

// ─────────────────────────────────── MISP ──────────────────────────────────

/// Fetch recent MISP attributes via `restSearch`. Requires `MISP_URL` + `MISP_API_KEY`.
pub async fn fetch_misp() -> Result<Vec<Indicator>, FeedError> {
    let base = super::creds::get(MISP_URL_ENV)
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .ok_or(FeedError::NotConfigured(MISP_URL_ENV))?;
    let key = super::creds::get(MISP_KEY_ENV).ok_or(FeedError::NotConfigured(MISP_KEY_ENV))?;
    let url = format!("{base}/attributes/restSearch");
    let body = json!({"returnFormat": "json", "to_ids": 1, "last": "7d", "limit": 2000});
    let resp = client()?
        .post(&url)
        .header("Authorization", key)
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| FeedError::Request(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(FeedError::Status(status.as_u16()));
    }
    let v: Value = resp
        .json()
        .await
        .map_err(|e| FeedError::Decode(e.to_string()))?;
    Ok(parse_misp(&v))
}

/// Pure parser for a MISP `restSearch` attribute response.
#[must_use]
pub fn parse_misp(v: &Value) -> Vec<Indicator> {
    let attrs = v
        .get("response")
        .and_then(|r| r.get("Attribute"))
        .and_then(Value::as_array);
    let Some(attrs) = attrs else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for a in attrs {
        let raw = a.get("value").and_then(Value::as_str).unwrap_or("");
        if raw.is_empty() {
            continue;
        }
        let ty = a
            .get("type")
            .and_then(Value::as_str)
            .and_then(IocType::from_str_lenient)
            .or_else(|| guess_type(raw));
        let Some(ty) = ty else { continue };
        let tags = a
            .get("Tag")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.get("name").and_then(Value::as_str).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let ind = Indicator::new(ty, raw, "misp")
            .with_confidence(75)
            .with_severity("high")
            .with_tags(tags);
        if ind.is_valid() {
            out.push(ind);
        }
    }
    out
}

// ─────────────────────────── Generic blocklists ────────────────────────────

/// Fetch + parse operator-configured plaintext blocklists.
/// `IOC_CUSTOM_BLOCKLIST_URLS` is a comma-separated list; each entry may be
/// `url` (type auto-guessed) or `type=url` to pin a class (e.g. `ipv4=https://…`).
pub async fn fetch_custom_blocklists() -> Result<Vec<Indicator>, FeedError> {
    let raw = super::creds::get(CUSTOM_BLOCKLIST_ENV)
        .ok_or(FeedError::NotConfigured(CUSTOM_BLOCKLIST_ENV))?;
    let cl = client()?;
    let mut out = Vec::new();
    for spec in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (forced_type, url) = match spec.split_once('=') {
            Some((t, u)) if IocType::from_str_lenient(t).is_some() => {
                (IocType::from_str_lenient(t), u.trim())
            }
            _ => (None, spec),
        };
        let bytes = match crate::outbound_http::get_bytes_with_retry(
            &cl,
            url,
            reqwest::header::HeaderMap::new(),
            2,
            Some("blocklist"),
        )
        .await
        {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(target: "ioc_feeds", url = %url, error = %e, "custom blocklist fetch failed");
                continue;
            }
        };
        let text = String::from_utf8_lossy(&bytes);
        out.extend(parse_blocklist(&text, forced_type, "blocklist"));
    }
    Ok(out)
}

/// Pure parser for a line-based blocklist. Lines starting with `#`, `;`, `//`
/// or blank are ignored. When `forced_type` is None, each value is classified.
#[must_use]
pub fn parse_blocklist(text: &str, forced_type: Option<IocType>, source: &str) -> Vec<Indicator> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
        {
            continue;
        }
        // Take the first whitespace- or comma-separated token as the value.
        let token = line
            .split_whitespace()
            .next()
            .unwrap_or(line)
            .split(',')
            .next()
            .unwrap_or(line)
            .trim();
        if token.is_empty() {
            continue;
        }
        let ty = forced_type.or_else(|| guess_type(token));
        let Some(ty) = ty else { continue };
        let ind = Indicator::new(ty, token, source)
            .with_confidence(70)
            .with_severity("medium");
        if ind.is_valid() {
            out.push(ind);
        }
    }
    out
}

// ─────────────────────────────── STIX 2.1 ──────────────────────────────────

/// Pure parser for a STIX 2.x bundle: extracts `indicator` SDOs and decodes
/// the common `pattern` shapes into normalized indicators. Also accepts bare
/// observable SCOs (`ipv4-addr`, `domain-name`, `file`).
#[must_use]
pub fn parse_stix_bundle(v: &Value) -> Vec<Indicator> {
    let Some(objects) = v.get("objects").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for obj in objects {
        let otype = obj.get("type").and_then(Value::as_str).unwrap_or("");
        match otype {
            "indicator" => {
                let pattern = obj.get("pattern").and_then(Value::as_str).unwrap_or("");
                let confidence = obj
                    .get("confidence")
                    .and_then(Value::as_u64)
                    .map(|c| c.min(100) as u8)
                    .unwrap_or(70);
                for (ty, val) in parse_stix_pattern(pattern) {
                    let ind = Indicator::new(ty, val, "stix")
                        .with_confidence(confidence)
                        .with_severity(severity_from_confidence(confidence));
                    if ind.is_valid() {
                        out.push(ind);
                    }
                }
            }
            "ipv4-addr" | "ipv6-addr" | "domain-name" | "url" | "email-addr" => {
                if let Some(val) = obj.get("value").and_then(Value::as_str) {
                    let ty = match otype {
                        "ipv4-addr" => IocType::Ipv4,
                        "ipv6-addr" => IocType::Ipv6,
                        "domain-name" => IocType::Domain,
                        "url" => IocType::Url,
                        _ => IocType::Email,
                    };
                    let ind = Indicator::new(ty, val, "stix").with_confidence(70);
                    if ind.is_valid() {
                        out.push(ind);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Decode the value(s) out of a STIX pattern expression. Handles the common
/// single-term comparison shapes; multi-term `AND`/`OR` patterns yield each term.
#[must_use]
pub fn parse_stix_pattern(pattern: &str) -> Vec<(IocType, String)> {
    let mut out = Vec::new();
    // Strip the outer [ ] and split on boolean operators.
    let inner = pattern.trim().trim_start_matches('[').trim_end_matches(']');
    for term in inner
        .split([';'])
        .flat_map(|t| t.split(" AND "))
        .flat_map(|t| t.split(" OR "))
    {
        let term = term.trim();
        let Some((lhs, rhs)) = term.split_once('=') else {
            continue;
        };
        let lhs = lhs.trim();
        let val = rhs.trim().trim_matches(|c| c == '\'' || c == '"').trim();
        if val.is_empty() {
            continue;
        }
        let ty = match lhs {
            "ipv4-addr:value" => IocType::Ipv4,
            "ipv6-addr:value" => IocType::Ipv6,
            "domain-name:value" => IocType::Domain,
            "url:value" => IocType::Url,
            "email-addr:value" | "email-message:from_ref.value" => IocType::Email,
            l if l.contains("SHA-256") || l.contains("SHA256") => IocType::Sha256,
            l if l.contains("SHA-1") || l.contains("SHA1") => IocType::Sha1,
            l if l.contains("MD5") => IocType::Md5,
            _ => continue,
        };
        out.push((ty, val.to_string()));
    }
    out
}

/// Map a 0..=100 confidence to a severity label.
#[must_use]
pub fn severity_from_confidence(c: u8) -> &'static str {
    match c {
        90..=u8::MAX => "critical",
        70..=89 => "high",
        40..=69 => "medium",
        _ => "low",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn threatfox_parser_extracts_typed_indicators() {
        let v = json!({
            "query_status": "ok",
            "data": [
                {"ioc": "185.220.101.5:443", "ioc_type": "ip:port", "malware_printable": "Cobalt Strike", "confidence_level": 100, "tags": ["cobaltstrike"]},
                {"ioc": "evil-c2.example.net", "ioc_type": "domain", "confidence_level": 75},
                {"ioc": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ioc_type": "sha256_hash", "confidence_level": 90},
                {"ioc": "", "ioc_type": "domain"}
            ]
        });
        let inds = parse_threatfox(&v);
        assert_eq!(inds.len(), 3);
        let ip = inds.iter().find(|i| i.ioc_type == IocType::Ipv4).unwrap();
        assert_eq!(ip.value_norm, "185.220.101.5");
        assert_eq!(ip.confidence, 100);
        assert_eq!(ip.severity, "critical");
        assert!(inds.iter().any(|i| i.ioc_type == IocType::Sha256));
        assert!(inds.iter().any(|i| i.ioc_type == IocType::Domain));
    }

    #[test]
    fn urlhaus_parser_reads_nested_map() {
        let v = json!({
            "100": [{"url": "http://bad.example/evil.exe", "url_status": "online", "threat": "malware_download", "tags": ["exe"]}],
            "101": [{"url": "http://old.example/x", "url_status": "offline", "threat": "malware_download"}]
        });
        let inds = parse_urlhaus(&v);
        assert_eq!(inds.len(), 2);
        let online = inds
            .iter()
            .find(|i| i.value_norm.contains("bad.example"))
            .unwrap();
        assert_eq!(online.severity, "high");
        assert_eq!(online.confidence, 80);
    }

    #[test]
    fn feodo_parser_reads_ip_array() {
        let v = json!([
            {"ip_address": "1.2.3.4", "port": 443, "malware": "Emotet"},
            {"ip_address": "", "port": 80}
        ]);
        let inds = parse_feodo(&v);
        assert_eq!(inds.len(), 1);
        assert_eq!(inds[0].value_norm, "1.2.3.4");
        assert_eq!(inds[0].malware_family, "Emotet");
        assert!(inds[0].tags.iter().any(|t| t == "port:443"));
    }

    #[test]
    fn otx_parser_walks_pulses_and_maps_types() {
        let v = json!({
            "results": [{
                "name": "APT-X infra",
                "indicators": [
                    {"indicator": "9.9.9.9", "type": "IPv4"},
                    {"indicator": "mal.example.org", "type": "domain"},
                    {"indicator": "deadbeef", "type": "FileHash-MD5"}
                ]
            }]
        });
        let inds = parse_otx(&v);
        // deadbeef is not a valid md5 length → dropped.
        assert_eq!(inds.len(), 2);
        assert!(inds
            .iter()
            .any(|i| i.tags.iter().any(|t| t == "pulse:APT-X infra")));
    }

    #[test]
    fn misp_parser_reads_restsearch_attrs() {
        let v = json!({
            "response": {"Attribute": [
                {"type": "ip-dst", "value": "5.6.7.8", "Tag": [{"name": "tlp:amber"}]},
                {"type": "domain", "value": "phish.example.com"}
            ]}
        });
        let inds = parse_misp(&v);
        assert_eq!(inds.len(), 2);
        assert!(inds.iter().any(|i| i.tags.iter().any(|t| t == "tlp:amber")));
    }

    #[test]
    fn blocklist_parser_skips_comments_and_classifies() {
        let text =
            "# header\n\n8.8.8.8\n; comment\nevil.example.com\n// c++ comment\n1.2.3.4 some note";
        let inds = parse_blocklist(text, None, "blocklist");
        assert_eq!(inds.len(), 3);
        assert!(inds.iter().any(|i| i.value_norm == "8.8.8.8"));
        assert!(inds.iter().any(|i| i.value_norm == "evil.example.com"));
        assert!(inds.iter().any(|i| i.value_norm == "1.2.3.4"));
    }

    #[test]
    fn blocklist_forced_type_pins_class() {
        let text = "10.0.0.0/8\n172.16.0.0/12";
        let inds = parse_blocklist(text, Some(IocType::Cidr), "blocklist");
        assert_eq!(inds.len(), 2);
        assert!(inds.iter().all(|i| i.ioc_type == IocType::Cidr));
    }

    #[test]
    fn stix_pattern_decodes_common_shapes() {
        assert_eq!(
            parse_stix_pattern("[ipv4-addr:value = '1.2.3.4']"),
            vec![(IocType::Ipv4, "1.2.3.4".to_string())]
        );
        assert_eq!(
            parse_stix_pattern("[domain-name:value = 'evil.com']"),
            vec![(IocType::Domain, "evil.com".to_string())]
        );
        let h = parse_stix_pattern("[file:hashes.'SHA-256' = 'abc123']");
        assert_eq!(h, vec![(IocType::Sha256, "abc123".to_string())]);
    }

    #[test]
    fn stix_bundle_parses_indicators_and_scos() {
        let v = json!({
            "type": "bundle",
            "objects": [
                {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.9']", "confidence": 95},
                {"type": "domain-name", "value": "sco.example.net"},
                {"type": "identity", "name": "ignored"}
            ]
        });
        let inds = parse_stix_bundle(&v);
        assert_eq!(inds.len(), 2);
        let ip = inds.iter().find(|i| i.ioc_type == IocType::Ipv4).unwrap();
        assert_eq!(ip.confidence, 95);
        assert_eq!(ip.severity, "critical");
    }

    #[test]
    fn enabled_feeds_always_includes_open_feodo() {
        // Feodo needs no key, so it is always enabled regardless of env.
        assert!(enabled_feeds().contains(&FeedSource::Feodo));
    }
}
