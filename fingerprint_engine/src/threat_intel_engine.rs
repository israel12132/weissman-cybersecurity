//! Module 7: Autonomous Zero-Day Radar & Safe Probe Synthesis.
//! Live NVD/OSV/RSS feeds, LLM probe synthesis via OpenAI-compatible API (vLLM; detection only), execute against client assets.

use crate::engine_result::EngineResult;
use crate::intel_http_cache;
use crate::outbound_http::{external_json_client, get_bytes_with_retry};
use crate::stealth_engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use weissman_engines::openai_chat::{self, DEFAULT_LLM_BASE_URL};

const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const LLM_TIMEOUT_SECS: u64 = 60;
const TARGET_TIMEOUT_SECS: u64 = 12;
const PROBE_PROMPT: &str = r#"Analyze this vulnerability description. Generate a safe, non-destructive HTTP detection signature to verify if a server is vulnerable. Detection ONLY: no exploits, no reverse shells, no destructive payloads.
Return ONLY a valid JSON object with these exact keys:
- "path": string (e.g. "/api/version" or "/")
- "method": string, "GET" or "POST" (default GET)
- "headers": object or null (e.g. {"User-Agent":"Scanner"})
- "query_params": object or null (e.g. {"q":"1"})
- "expected_regex": string, a regex pattern that if matched in the response body indicates the service may be vulnerable (keep it short and safe)

Example: {"path":"/","method":"GET","headers":null,"query_params":null,"expected_regex":"(?i)vulnerable|version 1\\.0"}
Output nothing but the JSON object."#;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SafeProbe {
    pub path: String,
    #[serde(default)]
    pub method: String,
    pub headers: Option<HashMap<String, String>>,
    pub query_params: Option<HashMap<String, String>>,
    pub expected_regex: Option<String>,
}

/// Event for live Zero-Day Radar UI (feed, synthesis, exposure).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)] // Feed/Synthesis payloads are large by design for the stream API
pub enum RadarStreamEvent {
    Feed {
        items: Vec<ThreatFeedItem>,
    },
    Synthesis {
        item: ThreatFeedItem,
        probe: Option<SafeProbe>,
    },
    ScanProgress {
        current: usize,
        total: usize,
    },
    Exposure {
        finding: Value,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatFeedItem {
    pub source: String,
    pub external_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub published_at: String,
}

#[derive(Clone, Debug)]
pub struct ThreatIntelConfig {
    pub llm_base_url: String,
    pub llm_model: String,
    pub enable_zero_day_probing: bool,
    pub custom_feed_urls: Vec<String>,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            llm_base_url: DEFAULT_LLM_BASE_URL.to_string(),
            llm_model: String::new(),
            enable_zero_day_probing: true,
            custom_feed_urls: vec![],
        }
    }
}

fn target_client(stealth: Option<&stealth_engine::StealthConfig>) -> reqwest::Client {
    match stealth {
        Some(s) => stealth_engine::build_client(s, TARGET_TIMEOUT_SECS),
        None => reqwest::Client::builder()
            .timeout(Duration::from_secs(TARGET_TIMEOUT_SECS))
            .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
    }
}

/// Fetch recent CVEs from NVD 2.0 API. **`NVD_API_KEY` required** — otherwise returns empty and logs.
pub async fn fetch_nvd_recent(days_back: u32) -> Vec<ThreatFeedItem> {
    if !crate::nvd_cve::nvd_api_key_present() {
        tracing::error!(
            target: "nvd",
            "NVD_API_KEY missing — fetch_nvd_recent disabled; threat intel NVD feed empty"
        );
        return vec![];
    }
    let cache_key = format!("{}", days_back);
    if let Some(cached) = intel_http_cache::nvd_recent_cache().get(&cache_key).await {
        if let Ok(data) = serde_json::from_slice::<Value>(cached.as_ref()) {
            return parse_nvd_recent_value(&data);
        }
    }
    let client = match external_json_client() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(target: "nvd", error = %e, "external JSON client build failed");
            return vec![];
        }
    };
    let end = chrono::Utc::now();
    let start = end - chrono::Duration::days(days_back as i64);
    let url = format!(
        "{}?pubStartDate={}&pubEndDate={}&resultsPerPage=50",
        NVD_URL,
        start.format("%Y-%m-%dT00:00:00.000"),
        end.format("%Y-%m-%dT23:59:59.999")
    );
    let mut headers = reqwest::header::HeaderMap::new();
    if let Ok(k) = std::env::var("NVD_API_KEY").map(|s| s.trim().to_string()) {
        if !k.is_empty() {
            if let (Ok(name), Ok(val)) = (
                reqwest::header::HeaderName::from_bytes(b"apiKey"),
                reqwest::header::HeaderValue::from_str(&k),
            ) {
                headers.insert(name, val);
            }
        }
    }
    let bytes = match get_bytes_with_retry(&client, &url, headers, 4, Some("intel_rss")).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(target: "nvd", error = %e, "NVD recent fetch failed");
            return vec![];
        }
    };
    let data: Value = match serde_json::from_slice(&bytes) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(target: "nvd", error = %e, "NVD JSON decode failed");
            return vec![];
        }
    };
    let _ = intel_http_cache::nvd_recent_cache()
        .insert(cache_key, std::sync::Arc::new(bytes))
        .await;
    parse_nvd_recent_value(&data)
}

fn parse_nvd_recent_value(data: &Value) -> Vec<ThreatFeedItem> {
    let empty: Vec<Value> = vec![];
    let vulns = data
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let mut out = Vec::new();
    for v in vulns {
        let cve = match v.get("cve").and_then(|c| c.as_object()) {
            Some(c) => c,
            None => continue,
        };
        let id = cve
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let mut desc = String::new();
        if let Some(descs) = cve.get("descriptions").and_then(|d| d.as_array()) {
            for d in descs {
                if d.get("lang").and_then(|l| l.as_str()) == Some("en") {
                    desc = d
                        .get("value")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    break;
                }
            }
        }
        if desc.is_empty() {
            continue;
        }
        let mut severity = "MEDIUM".to_string();
        if let Some(metrics) = cve.get("metrics").and_then(|m| m.as_object()) {
            for (_, v) in metrics {
                if let Some(arr) = v.as_array() {
                    for m in arr {
                        if let Some(s) = m
                            .get("cvssData")
                            .and_then(|d| d.get("baseSeverity"))
                            .and_then(|s| s.as_str())
                        {
                            severity = s.to_uppercase();
                            break;
                        }
                    }
                }
            }
        }
        let published = cve
            .get("published")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();
        out.push(ThreatFeedItem {
            source: "NVD".to_string(),
            external_id: id.clone(),
            title: format!("CVE: {}", id),
            description: desc.chars().take(4000).collect(),
            severity,
            published_at: published,
        });
    }
    out
}

/// Parse RSS/XML feed and return threat items (generic severity from title/description).
pub async fn fetch_rss_feed(feed_url: &str) -> Vec<ThreatFeedItem> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("Weissman-ThreatIntel/1.0")
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let body = match client.get(feed_url).send().await {
        Ok(r) => r.text().await.unwrap_or_default(),
        Err(_) => return vec![],
    };
    parse_rss_body(&body, feed_url)
}

fn parse_rss_body(xml: &str, source: &str) -> Vec<ThreatFeedItem> {
    let mut out = Vec::new();
    let rest = xml.trim_start();
    if !rest.starts_with("<?xml") && !rest.starts_with("<rss") && !rest.starts_with("<feed") {
        return out;
    }
    let items = if rest.contains("<item>") {
        rest.split("<item>").skip(1).collect::<Vec<_>>()
    } else if rest.contains("<entry>") {
        rest.split("<entry>").skip(1).collect::<Vec<_>>()
    } else {
        return out;
    };
    for item in items {
        let title = extract_tag(item, "title")
            .unwrap_or_else(|| extract_tag(item, "summary").unwrap_or_default());
        let desc = extract_tag(item, "description")
            .or_else(|| extract_tag(item, "content"))
            .unwrap_or_else(|| title.clone());
        let link = extract_tag(item, "link").unwrap_or_default();
        let id = if link.is_empty() {
            title.chars().take(80).collect()
        } else {
            link
        };
        let published = extract_tag(item, "pubDate")
            .or_else(|| extract_tag(item, "published"))
            .unwrap_or_default();
        let severity = if desc.to_uppercase().contains("CRITICAL")
            || title.to_uppercase().contains("CRITICAL")
        {
            "CRITICAL"
        } else if desc.to_uppercase().contains("HIGH") || title.to_uppercase().contains("HIGH") {
            "HIGH"
        } else {
            "MEDIUM"
        };
        out.push(ThreatFeedItem {
            source: source.to_string(),
            external_id: id,
            title,
            description: desc.chars().take(4000).collect(),
            severity: severity.to_string(),
            published_at: published,
        });
    }
    out
}

fn extract_tag(fragment: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = fragment.find(&open)?;
    let rest = &fragment[start + open.len()..];
    let end = rest.find(&close)?;
    let inner = &rest[..end];
    let inner = inner.replace("<![CDATA[", "").replace("]]>", "");
    Some(inner.trim().to_string())
}

/// Call local vLLM (OpenAI `/v1/chat/completions`) to synthesize SafeProbe from vulnerability description.
pub async fn synthesize_probe(
    llm_base: &str,
    llm_model: &str,
    description: &str,
    llm_tenant_id: Option<i64>,
) -> Option<SafeProbe> {
    let prompt = format!(
        "{}\n\nVulnerability description:\n{}\n\nJSON only:",
        PROBE_PROMPT,
        description.chars().take(3000).collect::<String>()
    );
    let client = openai_chat::llm_http_client(LLM_TIMEOUT_SECS);
    let model = openai_chat::resolve_llm_model(llm_model);
    let text = openai_chat::chat_completion_text(
        &client,
        llm_base,
        &model,
        None,
        &prompt,
        0.2,
        512,
        llm_tenant_id,
        "threat_intel_probe",
        true,
    )
    .await
    .ok()?;
    parse_probe_json(&text)
}

fn parse_probe_json(text: &str) -> Option<SafeProbe> {
    let trimmed = text.trim();
    let start = trimmed.find('{')?;
    let end = trimmed.rfind('}')? + 1;
    let json_str = trimmed.get(start..end)?;
    let v: Value = serde_json::from_str(json_str).ok()?;
    let path = v
        .get("path")
        .and_then(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let method = v
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("GET")
        .to_uppercase();
    let method = if method == "POST" { "POST" } else { "GET" }.to_string();
    let headers = v.get("headers").and_then(|h| h.as_object()).map(|m| {
        m.iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect()
    });
    let query_params = v.get("query_params").and_then(|q| q.as_object()).map(|m| {
        m.iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect()
    });
    let expected_regex = v
        .get("expected_regex")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string());
    Some(SafeProbe {
        path,
        method,
        headers,
        query_params,
        expected_regex,
    })
}

/// Execute one SafeProbe against a base URL. Returns true if expected_regex matches response body.
pub async fn execute_probe(
    base_url: &str,
    probe: &SafeProbe,
    client: &reqwest::Client,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> bool {
    let base = base_url.trim_end_matches('/');
    let path = probe.path.trim_start_matches('/');
    let url = if path.is_empty() {
        base.to_string()
    } else {
        format!("{}/{}", base, path)
    };
    let mut req = match probe.method.as_str() {
        "POST" => client.post(&url),
        _ => client.get(&url),
    };
    if let Some(ref params) = probe.query_params {
        req = req.query(params);
    }
    if let Some(ref h) = probe.headers {
        let mut map = reqwest::header::HeaderMap::new();
        for (k, v) in h {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::try_from(k.as_str()),
                reqwest::header::HeaderValue::from_str(v),
            ) {
                map.insert(name, value);
            }
        }
        req = req.headers(map);
    }
    if let Some(s) = stealth {
        req = req.headers(stealth_engine::random_morph_headers(s));
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(_) => return false,
    };
    let body = resp.text().await.unwrap_or_default();
    let re = match &probe.expected_regex {
        Some(r) => match Regex::new(r) {
            Ok(re) => re,
            Err(_) => return false,
        },
        None => return false,
    };
    re.is_match(&body)
}

/// (client_id, base_url) for assigning findings to clients.
pub type RadarTarget = (String, String);

/// Run zero-day radar: fetch feeds, synthesize probes for new critical/high, execute against targets.
pub async fn run_zero_day_radar(
    targets: &[RadarTarget],
    stealth: Option<&stealth_engine::StealthConfig>,
    config: &ThreatIntelConfig,
    event_tx: Option<tokio::sync::mpsc::UnboundedSender<RadarStreamEvent>>,
    llm_tenant_id: Option<i64>,
) -> EngineResult {
    if !config.enable_zero_day_probing || targets.is_empty() {
        return EngineResult::ok(vec![], "Zero-day probing disabled or no targets");
    }
    let config = config.clone();
    let stealth_owned: Option<stealth_engine::StealthConfig> = stealth.cloned();
    let stealth = stealth_owned.as_ref();
    let mut all_feed = fetch_nvd_recent(7).await;
    for url in config.custom_feed_urls.clone() {
        let u = url.trim();
        if !u.is_empty() {
            let items = fetch_rss_feed(u).await;
            all_feed.extend(items);
        }
    }
    if let Some(ref tx) = event_tx {
        let _ = tx.send(RadarStreamEvent::Feed {
            items: all_feed.clone(),
        });
    }
    let critical_high: Vec<_> = all_feed
        .into_iter()
        .filter(|i| i.severity == "CRITICAL" || i.severity == "HIGH")
        .take(5)
        .collect();
    let num_threats = critical_high.len();
    let llm_base: String = if config.llm_base_url.is_empty() {
        DEFAULT_LLM_BASE_URL.to_string()
    } else {
        config.llm_base_url.clone()
    };
    let client = target_client(stealth);
    let mut findings = Vec::new();
    for idx in 0..critical_high.len() {
        let item = critical_high[idx].clone();
        if let Some(ref tx) = event_tx {
            let _ = tx.send(RadarStreamEvent::ScanProgress {
                current: idx,
                total: num_threats,
            });
        }
        let probe =
            synthesize_probe(llm_base.as_str(), &config.llm_model, &item.description, llm_tenant_id)
                .await;
        if let Some(ref tx) = event_tx {
            let _ = tx.send(RadarStreamEvent::Synthesis {
                item: item.clone(),
                probe: probe.clone(),
            });
        }
        let probe = match probe {
            Some(p) => p,
            None => continue,
        };
        for (client_id, base) in targets.to_vec() {
            if let Some(s) = stealth {
                stealth_engine::apply_jitter(s);
            }
            if execute_probe(base.as_str(), &probe, &client, stealth).await {
                let finding = serde_json::json!({
                    "type": "zero_day_radar",
                    "subtype": "safe_probe_match",
                    "severity": "critical",
                    "title": format!("Zero-day exposure: {} (detection match)", item.external_id),
                    "cve_id": item.external_id,
                    "client_id": client_id,
                    "description": item.description.chars().take(500).collect::<String>(),
                    "target_url": base,
                    "probe_path": probe.path,
                    "remediation": "Apply vendor patch; restrict access; monitor. This was a safe detection probe only."
                });
                if let Some(ref tx) = event_tx {
                    let _ = tx.send(RadarStreamEvent::Exposure {
                        finding: finding.clone(),
                    });
                }
                findings.push(finding);
            }
        }
    }
    if let Some(ref tx) = event_tx {
        let _ = tx.send(RadarStreamEvent::ScanProgress {
            current: num_threats,
            total: num_threats,
        });
    }
    let msg = format!(
        "Zero-Day Radar: {} critical/high threats processed, {} exposures detected",
        num_threats,
        findings.len()
    );
    EngineResult::ok(findings, msg)
}
