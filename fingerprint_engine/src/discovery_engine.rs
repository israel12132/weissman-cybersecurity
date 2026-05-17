//! Spider-Sense Crawler: deep-crawl, JS/HTML extraction, Link/Location headers.
//! Predictive AI: local LLM (vLLM OpenAI API) → predicted high-value paths from naming conventions.

use crate::engine_result::EngineResult;
use crate::regex_util::never_matches;
use crate::stealth_engine;
use futures::stream::{self, StreamExt};
use regex::Regex;
use reqwest::Url;
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use weissman_engines::openai_chat::{self, DEFAULT_LLM_BASE_URL};

const LLM_TIMEOUT_SECS: u64 = 26;
const PREDICTED_PATHS_LIMIT: usize = 100;

const CRAWL_TIMEOUT_SECS: u64 = 9;
const MAX_PAGES_PER_BASE: usize = 40;
const MAX_JS_PER_BASE: usize = 20;
/// Parallel HTML page fetches per spider wave (BFS batch).
const CRAWL_PAGE_CONCURRENCY: usize = 12;
/// Parallel `.js` asset fetches after HTML phase.
const DISCOVERY_JS_CONCURRENCY: usize = 16;
/// Parallel GraphQL introspection POSTs (base × path grid).
const GRAPHQL_PROBE_CONCURRENCY: usize = 24;

fn html_href_src_action_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?i)(?:href|src|action)\s*=\s*["']([^"']+)["']"#)
            .unwrap_or_else(|_| never_matches())
    })
}
fn url_in_js_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?:["']|`)(/[^"'`\s]*)(?:["']|`)"#).unwrap_or_else(|_| never_matches())
    })
}
fn html_comment_path_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"<!--\s*([^>]*?/[\w/.%-]*)\s*-->"#).unwrap_or_else(|_| never_matches())
    })
}
fn html_link_src_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?i)(?:href|src)\s*=\s*["']([^"']+)["']"#).unwrap_or_else(|_| never_matches())
    })
}
fn js_src_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?i)src\s*=\s*["']([^"']+\.js[^"']*)["']"#)
            .unwrap_or_else(|_| never_matches())
    })
}

fn normalize_path(path: &str) -> String {
    let path = path.trim().trim_start_matches('/');
    if path.is_empty() {
        return "/".to_string();
    }
    format!("/{}", path)
}

/// Extract paths from HTML: href="...", src="...", action="...", data-* attributes with URLs.
fn extract_from_html(html: &str, _base_path: &str) -> Vec<String> {
    let mut out = HashSet::new();
    let href_re = html_href_src_action_re();
    let url_in_js = url_in_js_re();
    let comment_re = html_comment_path_re();

    for cap in href_re.captures_iter(html) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str().trim();
            if s.starts_with('/') && !s.starts_with("//") {
                out.insert(normalize_path(s.split('?').next().unwrap_or(s)));
            }
        }
    }
    for cap in url_in_js.captures_iter(html) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str().trim();
            if s.len() > 1 && s.len() < 400 {
                out.insert(normalize_path(s.split('?').next().unwrap_or(s)));
            }
        }
    }
    for cap in comment_re.captures_iter(html) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str().trim();
            if s.starts_with('/') {
                out.insert(normalize_path(s.split('?').next().unwrap_or(s)));
            }
        }
    }
    out.into_iter().collect()
}

/// Extract API routes and paths from JavaScript: /api/..., fetch("/..."), axios.get("..."), etc.
fn extract_from_js(js: &str) -> Vec<String> {
    let mut out = HashSet::new();
    let patterns = [
        r#"(?:fetch|axios\.(?:get|post|put|delete)|\.get\s*\(\s*)["']([^"']+)"#,
        r#"["'](\s*/[a-zA-Z0-9/_{}-]+)\s*["']"#,
        r#"(?:path|route|url)\s*:\s*["']([^"']+)"#,
        r#"/api/[a-zA-Z0-9/_.-]+"#,
        r#"/v[0-9]+/[a-zA-Z0-9/_.-]+"#,
    ];
    for pat in &patterns {
        if let Ok(re) = Regex::new(pat) {
            for cap in re.captures_iter(js) {
                let s = if cap.len() > 1 {
                    cap.get(1).map(|m| m.as_str())
                } else {
                    cap.get(0).map(|m| m.as_str())
                };
                if let Some(s) = s {
                    let s = s.trim().trim_matches(|c| c == '"' || c == '\'' || c == '`');
                    if s.starts_with('/') && s.len() < 400 {
                        out.insert(normalize_path(s.split('?').next().unwrap_or(s)));
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Parse Link and Location headers for redirects and related URLs.
fn extract_from_headers(headers: &reqwest::header::HeaderMap) -> Vec<String> {
    let mut out = Vec::new();
    for (name, value) in headers.iter() {
        if name.as_str().eq_ignore_ascii_case("location") {
            if let Ok(s) = value.to_str() {
                let s = s.trim();
                if s.starts_with('/') && !s.starts_with("//") {
                    out.push(normalize_path(s.split('?').next().unwrap_or(s)));
                }
            }
        }
        if name.as_str().eq_ignore_ascii_case("link") {
            if let Ok(s) = value.to_str() {
                for part in s.split(',') {
                    if let Some(url) = part.split(';').next() {
                        let url = url.trim().trim_matches(|c| c == '<' || c == '>');
                        if url.starts_with('/') && url.len() < 400 {
                            out.push(normalize_path(url.split('?').next().unwrap_or(url)));
                        }
                    }
                }
            }
        }
    }
    out
}

/// Single page fetch; returns (body, status, paths_from_headers).
async fn fetch_page(
    client: &reqwest::Client,
    url: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> Option<(String, u16, Vec<String>)> {
    let req = match stealth {
        Some(s) => {
            stealth_engine::apply_jitter(s);
            client
                .get(url)
                .headers(stealth_engine::random_morph_headers(s))
        }
        None => client.get(url),
    };
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.text().await.ok()?;
    let paths = extract_from_headers(&headers);
    Some((body, status, paths))
}

/// Crawl a list of base URLs: fetch HTML and linked JS, extract all paths. Record 403 paths for BOLA/fuzzing.
pub async fn run_spider_crawl(
    base_urls: &[String],
    stealth: Option<&stealth_engine::StealthConfig>,
    existing_paths: &mut HashSet<String>,
    paths_403: &mut Vec<String>,
) -> EngineResult {
    let base_urls: Vec<String> = base_urls.to_vec();
    let stealth_owned: Option<stealth_engine::StealthConfig> = stealth.cloned();
    let client = match stealth_owned.as_ref() {
        Some(s) => stealth_engine::build_client(s, CRAWL_TIMEOUT_SECS),
        None => reqwest::Client::builder()
            .timeout(Duration::from_secs(CRAWL_TIMEOUT_SECS))
            .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
    };
    let client = Arc::new(client);
    let stealth_arc: Option<Arc<stealth_engine::StealthConfig>> =
        stealth_owned.map(|s| Arc::new(s));

    let mut to_fetch: Vec<String> = base_urls
        .iter()
        .map(|u| u.trim_end_matches('/').to_string())
        .take(MAX_PAGES_PER_BASE)
        .collect();
    let mut fetched = HashSet::<String>::new();
    let mut js_urls = Vec::new();

    while !to_fetch.is_empty() && fetched.len() < MAX_PAGES_PER_BASE {
        let room = MAX_PAGES_PER_BASE.saturating_sub(fetched.len());
        let cap = room.min(CRAWL_PAGE_CONCURRENCY);
        let mut batch = Vec::new();
        while batch.len() < cap && !to_fetch.is_empty() {
            let url = to_fetch.pop().expect("nonempty");
            if fetched.contains(&url) {
                continue;
            }
            batch.push(url);
        }
        if batch.is_empty() {
            continue;
        }
        let results: Vec<(String, Option<(String, u16, Vec<String>)>)> =
            stream::iter(batch.into_iter().map(|url| {
                let c = Arc::clone(&client);
                let st = stealth_arc.clone();
                async move {
                    let r = fetch_page(c.as_ref(), &url, st.as_deref()).await;
                    (url, r)
                }
            }))
            .buffer_unordered(CRAWL_PAGE_CONCURRENCY)
            .collect()
            .await;

        for (url, opt) in results {
            if fetched.contains(&url) {
                continue;
            }
            fetched.insert(url.clone());
            let Some((body, status, header_paths)) = opt else {
                continue;
            };
            if status == 403 {
                if let Ok(parsed) = Url::parse(&url) {
                    let path = parsed.path().to_string();
                    if !path.is_empty() && path != "/" {
                        paths_403.push(path);
                    }
                }
            }
            for p in &header_paths {
                existing_paths.insert(p.clone());
            }
            let is_html = body.trim_start().starts_with("<!") || body.contains("<html");
            if is_html {
                let from_html = extract_from_html(&body, "");
                for p in from_html {
                    existing_paths.insert(p);
                }
                for link in extract_html_links(&body, &url) {
                    let full = if link.starts_with("http") {
                        link.clone()
                    } else {
                        resolve_relative(&url, &link)
                    };
                    if full.starts_with("http")
                        && base_urls
                            .iter()
                            .any(|b| full.starts_with(b.trim_end_matches('/')))
                    {
                        if !fetched.contains(&full) && !to_fetch.contains(&full) {
                            to_fetch.push(full);
                        }
                    }
                    if link.starts_with('/') {
                        existing_paths
                            .insert(normalize_path(link.split('?').next().unwrap_or(&link)));
                    }
                }
                for js_ref in extract_js_refs(&body) {
                    let full_js = resolve_relative(&url, &js_ref);
                    if full_js.starts_with("http") && !js_urls.contains(&full_js) {
                        js_urls.push(full_js);
                    }
                }
            }
        }
    }

    let js_list: Vec<String> = js_urls.into_iter().take(MAX_JS_PER_BASE).collect();
    let js_results: Vec<(String, Option<(String, u16, Vec<String>)>)> =
        stream::iter(js_list.into_iter().map(|js_url| {
            let c = Arc::clone(&client);
            let st = stealth_arc.clone();
            async move {
                let r = fetch_page(c.as_ref(), &js_url, st.as_deref()).await;
                (js_url, r)
            }
        }))
        .buffer_unordered(DISCOVERY_JS_CONCURRENCY)
        .collect()
        .await;
    for (js_url, opt) in js_results {
        let Some((body, status, _)) = opt else {
            continue;
        };
        if status == 403 {
            if let Ok(parsed) = Url::parse(&js_url) {
                paths_403.push(parsed.path().to_string());
            }
        }
        for p in extract_from_js(&body) {
            existing_paths.insert(p);
        }
    }

    let msg = format!(
        "Spider: {} pages, {} paths, {} 403 (target for BOLA/fuzz)",
        fetched.len(),
        existing_paths.len(),
        paths_403.len()
    );
    EngineResult::ok(
        vec![serde_json::json!({
            "type": "discovery_crawler",
            "paths_count": existing_paths.len(),
            "pages_crawled": fetched.len(),
            "paths_403_count": paths_403.len(),
            "message": msg
        })],
        msg,
    )
}

fn extract_html_links(html: &str, _base: &str) -> Vec<String> {
    let mut out = Vec::new();
    let re = html_link_src_re();
    for cap in re.captures_iter(html) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str().trim();
            if !s.is_empty() && !s.starts_with("#") && !s.starts_with("javascript:") {
                out.push(s.to_string());
            }
        }
    }
    out
}

fn extract_js_refs(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let re = js_src_re();
    for cap in re.captures_iter(html) {
        if let Some(m) = cap.get(1) {
            out.push(m.as_str().trim().to_string());
        }
    }
    out
}

fn resolve_relative(base: &str, rel: &str) -> String {
    if rel.starts_with("http") {
        return rel.to_string();
    }
    let base = base.trim_end_matches('/');
    let base_dir = base.rsplit_once('/').map(|(d, _)| d).unwrap_or(base);
    if rel.starts_with('/') {
        if let Ok(u) = Url::parse(base) {
            let origin = u.origin().ascii_serialization();
            if !origin.is_empty() {
                return format!("{}{}", origin, rel);
            }
        }
    }
    format!("{}/{}", base_dir, rel.trim_start_matches('/'))
}

/// Predictive AI: given discovered paths, ask the LLM (OpenAI-compatible) to predict high-value paths.
pub async fn predict_paths_llm(
    discovered_paths: &[String],
    llm_base: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> Vec<String> {
    let sample: String = discovered_paths
        .iter()
        .take(50)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    if sample.is_empty() {
        return vec![];
    }
    let base = if llm_base.trim().is_empty() {
        DEFAULT_LLM_BASE_URL
    } else {
        llm_base.trim()
    };
    let prompt = format!(
        r#"You are a security researcher. Given these API/web paths discovered on a target:

{}
 
Predict exactly 100 additional high-value paths that likely exist on the same target, based on naming conventions and common patterns (e.g. if /api/v1/auth exists, predict /api/v1/admin, /api/v1/config, /api/v1/users, /api/v2/auth, etc.). Include admin, config, debug, backup, internal, graphql, swagger, actuator, health, metrics, login, register, and framework-specific paths.
Output ONLY one path per line, each line starting with /. No explanations. Exactly 100 lines."#,
        sample
    );
    let client = openai_chat::llm_http_client(LLM_TIMEOUT_SECS);
    let model = openai_chat::resolve_llm_model(llm_model);
    let text = match openai_chat::chat_completion_text(
        &client,
        base,
        &model,
        None,
        &prompt,
        0.4,
        2048,
        llm_tenant_id,
        "discovery_predict_paths",
        true,
    )
    .await
    {
        Ok(t) => t,
        Err(_) => return vec![],
    };
    let mut out = HashSet::new();
    for line in text.lines() {
        let line = line.trim().trim_start_matches('*').trim();
        if line.starts_with('/') && line.len() < 400 {
            let path = line.split('?').next().unwrap_or(line).to_string();
            out.insert(path);
            if out.len() >= PREDICTED_PATHS_LIMIT {
                break;
            }
        }
    }
    out.into_iter().collect()
}

/// P1: GraphQL introspection — probe /graphql and /api/graphql; if __schema present, return paths for fuzzing.
pub async fn run_graphql_introspection(
    base_urls: &[String],
    stealth: Option<&stealth_engine::StealthConfig>,
) -> Vec<String> {
    let base_urls = base_urls.to_vec();
    let stealth_owned: Option<stealth_engine::StealthConfig> = stealth.cloned();
    const INTROSPECTION_QUERY: &str =
        r#"{"query":"query Introspection { __schema { types { name } } }"}"#;
    let timeout_secs = 6u64;
    let client = match stealth_owned.as_ref() {
        Some(s) => stealth_engine::build_client(s, timeout_secs),
        None => reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
    };
    let client = Arc::new(client);
    let stealth_arc: Option<Arc<stealth_engine::StealthConfig>> =
        stealth_owned.map(|s| Arc::new(s));
    let paths_to_try = ["/graphql", "/api/graphql", "/v1/graphql", "/query"];
    let mut jobs = Vec::new();
    for base in base_urls.iter().take(10) {
        let base = base.trim_end_matches('/').to_string();
        for path in paths_to_try {
            jobs.push((base.clone(), path.to_string()));
        }
    }
    let query_body = INTROSPECTION_QUERY.to_string();
    let rows: Vec<Option<(String, u16, String)>> = stream::iter(jobs.into_iter().map(
        |(base, path)| {
            let client = Arc::clone(&client);
            let stealth_j = stealth_arc.clone();
            let url = format!("{base}{path}");
            let body = query_body.clone();
            async move {
                if let Some(s) = stealth_j.as_deref() {
                    stealth_engine::apply_jitter(s);
                }
                let req = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(body);
                let req = if let Some(s) = stealth_j.as_deref() {
                    req.headers(stealth_engine::random_morph_headers(s))
                } else {
                    req
                };
                let resp = req.send().await.ok()?;
                let status = resp.status().as_u16();
                let text = resp.text().await.ok()?;
                Some((path, status, text))
            }
        },
    ))
    .buffer_unordered(GRAPHQL_PROBE_CONCURRENCY)
    .collect()
    .await;

    let mut out = HashSet::new();
    for triple in rows.into_iter().flatten() {
        let (path, status, body) = triple;
        if stealth_engine::is_waf_or_rate_limit(status, &body) {
            if let Some(s) = stealth_arc.as_deref() {
                stealth_engine::apply_rotation_delay(s);
            }
            continue;
        }
        if status < 200 || status >= 300 {
            continue;
        }
        if body.contains("__schema") || body.contains("data") {
            out.insert(path.clone());
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(types) = v
                    .get("data")
                    .and_then(|d| d.get("__schema"))
                    .and_then(|s| s.get("types"))
                    .and_then(|t| t.as_array())
                {
                    for t in types.iter().take(50) {
                        if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                            if !name.starts_with("__") && name.len() < 100 {
                                out.insert(format!("/graphql#{name}"));
                            }
                        }
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}
