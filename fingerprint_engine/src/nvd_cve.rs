//! Live correlation with [NIST NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
//! (`keywordSearch`). **`NVD_API_KEY` is required** in production — without it, this module returns
//! [`NvdFetchError::ApiKeyMissing`] and logs at error level.

use crate::intel_http_cache;
use crate::outbound_http::{external_json_client, get_bytes_with_retry, OutboundHttpError};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

const NVD_CVE_V2: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NvdCveBrief {
    pub id: String,
    pub description: String,
    pub base_severity: Option<String>,
}

#[derive(Debug, Clone)]
pub enum NvdFetchError {
    ApiKeyMissing,
    KeywordTooShort,
    HttpClient(String),
    HttpStatus(u16),
    Body(String),
    Json(String),
    MissingVulnerabilitiesArray,
    Outbound(OutboundHttpError),
}

impl std::fmt::Display for NvdFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NvdFetchError::ApiKeyMissing => write!(f, "NVD_API_KEY not configured"),
            NvdFetchError::KeywordTooShort => write!(f, "keyword too short"),
            NvdFetchError::HttpClient(s) => write!(f, "HTTP client: {}", s),
            NvdFetchError::HttpStatus(c) => write!(f, "HTTP status {}", c),
            NvdFetchError::Body(s) => write!(f, "read body: {}", s),
            NvdFetchError::Json(s) => write!(f, "JSON: {}", s),
            NvdFetchError::MissingVulnerabilitiesArray => {
                write!(f, "response missing vulnerabilities array")
            }
            NvdFetchError::Outbound(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for NvdFetchError {}

impl From<OutboundHttpError> for NvdFetchError {
    fn from(e: OutboundHttpError) -> Self {
        NvdFetchError::Outbound(e)
    }
}

/// Returns true when `NVD_API_KEY` is non-empty (UI / engine gating without logging).
#[must_use]
pub fn nvd_api_key_present() -> bool {
    std::env::var("NVD_API_KEY")
        .ok()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

fn nvd_api_key_required() -> Result<String, NvdFetchError> {
    let k = std::env::var("NVD_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    match k {
        Some(s) => Ok(s),
        None => {
            tracing::error!(
                target: "nvd",
                "NVD_API_KEY is not set — NVD keyword search is disabled; set NVD_API_KEY for NIST API access"
            );
            Err(NvdFetchError::ApiKeyMissing)
        }
    }
}

fn severity_from_cve_json(cve: &Value) -> Option<String> {
    let metrics = cve.get("metrics")?;
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        if let Some(arr) = metrics.get(key).and_then(|x| x.as_array()) {
            if let Some(first) = arr.first() {
                if let Some(cvss) = first.get("cvssData") {
                    if let Some(s) = cvss.get("baseSeverity").and_then(|x| x.as_str()) {
                        return Some(s.to_string());
                    }
                    if let Some(s) = cvss.get("version").and_then(|x| x.as_str()) {
                        if let Some(score) = cvss.get("baseScore").and_then(|x| x.as_f64()) {
                            return Some(format!("CVSS{} {:.1}", s, score));
                        }
                    }
                }
            }
        }
    }
    None
}

fn description_en(cve: &Value) -> String {
    cve.pointer("/descriptions")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .find(|x| x.get("lang").and_then(|l| l.as_str()) == Some("en"))
                .or_else(|| arr.first())
                .and_then(|x| x.get("value").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default()
}

fn parse_nvd_response_bytes(body: &[u8]) -> Result<Vec<NvdCveBrief>, NvdFetchError> {
    let v: Value = serde_json::from_slice(body).map_err(|e| NvdFetchError::Json(e.to_string()))?;
    let Some(vulns) = v.get("vulnerabilities").and_then(|x| x.as_array()) else {
        return Err(NvdFetchError::MissingVulnerabilitiesArray);
    };
    let mut out = Vec::new();
    for item in vulns {
        let Some(cve) = item.get("cve") else {
            continue;
        };
        let Some(id) = cve.get("id").and_then(|x| x.as_str()) else {
            continue;
        };
        out.push(NvdCveBrief {
            id: id.to_string(),
            description: description_en(cve),
            base_severity: severity_from_cve_json(cve),
        });
    }
    Ok(out)
}

/// Keyword search against NVD (async client, cached ~10m, retries 429/5xx).
pub async fn fetch_keyword_cves(
    keyword: &str,
    results_per_page: u32,
) -> Result<Vec<NvdCveBrief>, NvdFetchError> {
    let api_key = nvd_api_key_required()?;
    let kw = keyword.trim();
    if kw.len() < 2 {
        return Err(NvdFetchError::KeywordTooShort);
    }
    let n = results_per_page.clamp(1, 50);
    let cache_key = format!("{}|{}", kw, n);
    let cache = intel_http_cache::nvd_keyword_cache();
    if let Some(hit) = cache.get(&cache_key).await {
        return parse_nvd_response_bytes(hit.as_ref());
    }

    let client = external_json_client().map_err(|e| NvdFetchError::HttpClient(e.to_string()))?;
    let encoded = urlencoding::encode(kw);
    let url = format!("{NVD_CVE_V2}?keywordSearch={encoded}&resultsPerPage={n}");

    let mut headers = HeaderMap::new();
    let (Ok(name), Ok(val)) = (
        HeaderName::from_bytes(b"apiKey"),
        HeaderValue::from_str(&api_key),
    ) else {
        return Err(NvdFetchError::HttpClient(
            "invalid NVD apiKey header".into(),
        ));
    };
    headers.insert(name, val);

    let bytes = get_bytes_with_retry(&client, &url, headers, 4, Some("nvd")).await?;
    let _ = cache.insert(cache_key, Arc::new(bytes.clone())).await;
    parse_nvd_response_bytes(&bytes)
}

#[must_use]
pub fn nvd_catalog_json_value(briefs: &[NvdCveBrief], limit: usize) -> Value {
    let items: Vec<Value> = briefs
        .iter()
        .take(limit)
        .map(|b| {
            json!({
                "id": b.id,
                "description": b.description,
                "base_severity": b.base_severity,
            })
        })
        .collect();
    json!({ "items": items })
}

#[must_use]
pub fn format_context_block(briefs: &[NvdCveBrief]) -> String {
    if briefs.is_empty() {
        return String::new();
    }
    let mut s = String::from("NVD context (keyword search):\n");
    for b in briefs.iter().take(12) {
        let sev = b
            .base_severity
            .as_deref()
            .map(|x| format!(" [{}]", x))
            .unwrap_or_default();
        s.push_str(&format!("- {}{}: {}\n", b.id, sev, b.description));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brief(id: &str, desc: &str, sev: Option<&str>) -> NvdCveBrief {
        NvdCveBrief {
            id: id.to_string(),
            description: desc.to_string(),
            base_severity: sev.map(|s| s.to_string()),
        }
    }

    #[test]
    fn severity_prefers_base_severity_and_metric_order() {
        // v3.1 baseSeverity present.
        let cve = json!({"metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]}});
        assert_eq!(severity_from_cve_json(&cve).as_deref(), Some("HIGH"));

        // v3.1 preferred over v3.0.
        let cve = json!({"metrics": {
            "cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}],
            "cvssMetricV30": [{"cvssData": {"baseSeverity": "LOW"}}]
        }});
        assert_eq!(severity_from_cve_json(&cve).as_deref(), Some("CRITICAL"));

        // Falls through to v2 when v3.x absent.
        let cve = json!({"metrics": {"cvssMetricV2": [{"cvssData": {"baseSeverity": "MEDIUM"}}]}});
        assert_eq!(severity_from_cve_json(&cve).as_deref(), Some("MEDIUM"));
    }

    #[test]
    fn severity_formats_version_and_score_when_no_base_severity() {
        let cve = json!({"metrics": {"cvssMetricV31": [{"cvssData": {
            "version": "3.1",
            "baseScore": 9.8
        }}]}});
        assert_eq!(severity_from_cve_json(&cve).as_deref(), Some("CVSS3.1 9.8"));
    }

    #[test]
    fn severity_none_when_missing() {
        assert_eq!(severity_from_cve_json(&json!({})), None);
        assert_eq!(severity_from_cve_json(&json!({"metrics": {}})), None);
        // Present metric but no usable cvssData fields.
        assert_eq!(
            severity_from_cve_json(&json!({"metrics": {"cvssMetricV31": [{"cvssData": {}}]}})),
            None
        );
    }

    #[test]
    fn description_prefers_english() {
        let cve = json!({"descriptions": [
            {"lang": "es", "value": "hola"},
            {"lang": "en", "value": "hello"}
        ]});
        assert_eq!(description_en(&cve), "hello");
    }

    #[test]
    fn description_falls_back_to_first_then_empty() {
        // No English => first entry.
        let cve = json!({"descriptions": [{"lang": "es", "value": "hola"}]});
        assert_eq!(description_en(&cve), "hola");
        // No descriptions key at all => empty.
        assert_eq!(description_en(&json!({})), "");
        // English entry present but no value => empty string.
        let cve = json!({"descriptions": [{"lang": "en"}]});
        assert_eq!(description_en(&cve), "");
    }

    #[test]
    fn parse_response_bytes_extracts_briefs() {
        let v = json!({"vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [{"lang": "en", "value": "Log4Shell"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]}
            }
        }]});
        let bytes = serde_json::to_vec(&v).unwrap();
        let out = parse_nvd_response_bytes(&bytes).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "CVE-2021-44228");
        assert_eq!(out[0].description, "Log4Shell");
        assert_eq!(out[0].base_severity.as_deref(), Some("CRITICAL"));
    }

    #[test]
    fn parse_response_bytes_skips_incomplete_items() {
        // First item missing `cve`, second missing `id` => both skipped.
        let v = json!({"vulnerabilities": [
            {"notcve": {}},
            {"cve": {"descriptions": []}},
            {"cve": {"id": "CVE-2020-0001"}}
        ]});
        let bytes = serde_json::to_vec(&v).unwrap();
        let out = parse_nvd_response_bytes(&bytes).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "CVE-2020-0001");
        assert_eq!(out[0].description, "");
        assert_eq!(out[0].base_severity, None);
    }

    #[test]
    fn parse_response_bytes_errors() {
        // Missing vulnerabilities array.
        let bytes = serde_json::to_vec(&json!({"foo": 1})).unwrap();
        assert!(matches!(
            parse_nvd_response_bytes(&bytes),
            Err(NvdFetchError::MissingVulnerabilitiesArray)
        ));
        // Invalid JSON.
        assert!(matches!(
            parse_nvd_response_bytes(b"not json"),
            Err(NvdFetchError::Json(_))
        ));
    }

    #[test]
    fn catalog_json_respects_limit_and_null_severity() {
        let briefs = vec![
            brief("CVE-1", "d1", Some("HIGH")),
            brief("CVE-2", "d2", None),
        ];
        // limit 1 => only first item.
        assert_eq!(
            nvd_catalog_json_value(&briefs, 1),
            json!({"items": [{"id": "CVE-1", "description": "d1", "base_severity": "HIGH"}]})
        );
        // Full list; None severity serializes to null.
        assert_eq!(
            nvd_catalog_json_value(&briefs, 10),
            json!({"items": [
                {"id": "CVE-1", "description": "d1", "base_severity": "HIGH"},
                {"id": "CVE-2", "description": "d2", "base_severity": null}
            ]})
        );
        // limit 0 => empty items.
        assert_eq!(nvd_catalog_json_value(&briefs, 0), json!({"items": []}));
    }

    #[test]
    fn context_block_formatting() {
        assert_eq!(format_context_block(&[]), "");
        assert_eq!(
            format_context_block(&[brief("CVE-1", "boom", Some("HIGH"))]),
            "NVD context (keyword search):\n- CVE-1 [HIGH]: boom\n"
        );
        // No severity => no bracket segment.
        assert_eq!(
            format_context_block(&[brief("CVE-1", "boom", None)]),
            "NVD context (keyword search):\n- CVE-1: boom\n"
        );
    }

    #[test]
    fn fetch_error_display() {
        assert_eq!(
            NvdFetchError::ApiKeyMissing.to_string(),
            "NVD_API_KEY not configured"
        );
        assert_eq!(
            NvdFetchError::KeywordTooShort.to_string(),
            "keyword too short"
        );
        assert_eq!(
            NvdFetchError::HttpStatus(500).to_string(),
            "HTTP status 500"
        );
        assert_eq!(NvdFetchError::Json("x".into()).to_string(), "JSON: x");
        assert_eq!(NvdFetchError::Body("b".into()).to_string(), "read body: b");
        assert_eq!(
            NvdFetchError::HttpClient("c".into()).to_string(),
            "HTTP client: c"
        );
        assert_eq!(
            NvdFetchError::MissingVulnerabilitiesArray.to_string(),
            "response missing vulnerabilities array"
        );
    }

    #[test]
    fn brief_serde_round_trip() {
        let b = brief("CVE-2021-1", "desc", Some("HIGH"));
        let val = serde_json::to_value(&b).unwrap();
        assert_eq!(
            val,
            json!({"id": "CVE-2021-1", "description": "desc", "base_severity": "HIGH"})
        );
        let back: NvdCveBrief = serde_json::from_value(val).unwrap();
        assert_eq!(back.id, "CVE-2021-1");
        assert_eq!(back.description, "desc");
        assert_eq!(back.base_severity.as_deref(), Some("HIGH"));
    }
}
