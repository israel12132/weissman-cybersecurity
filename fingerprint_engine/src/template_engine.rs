//! Template-based HTTP engine (YAML): run request/response rules without changing core logic.
//!
//! This module is intentionally generic: it executes **operator-supplied** templates and returns
//! structured step-by-step evidence. It does not ship with weaponized payloads.

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TemplateDoc {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
    /// "all" (default), "any", or "last"
    #[serde(default)]
    pub success_condition: Option<String>,
    pub steps: Vec<TemplateStep>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TemplateStep {
    pub id: String,
    pub request: TemplateRequest,
    #[serde(default)]
    pub extractors: Vec<TemplateExtractor>,
    #[serde(default)]
    pub matchers_condition: Option<String>, // "and" | "or"
    #[serde(default)]
    pub matchers: Vec<TemplateMatcher>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TemplateRequest {
    pub method: String,
    /// Absolute URL or path relative to BaseURL.
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TemplateExtractor {
    /// Extract a header into `state[name]`.
    Header { name: String, header: String },
    /// Extract a regex capture group from response body into `state[name]`.
    Regex {
        name: String,
        regex: String,
        #[serde(default)]
        group: Option<usize>,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TemplateMatcher {
    Status { statuses: Vec<u16> },
    BodyContains { contains: String },
    HeaderContains { header: String, contains: String },
    Regex { regex: String },
    DurationGtMs { ms: u64 },
}

#[derive(Clone, Debug, Serialize)]
pub struct TemplateCatalogItem {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub steps: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct StepRunResult {
    pub id: String,
    pub request: serde_json::Value,
    pub response: serde_json::Value,
    pub extracted: BTreeMap<String, String>,
    pub matcher_results: Vec<serde_json::Value>,
    pub matched: bool,
    pub duration_ms: u64,
    pub state_after: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TemplateRunResult {
    pub template: TemplateCatalogItem,
    pub target_url: String,
    pub matched: bool,
    pub verification: serde_json::Value,
    pub steps: Vec<StepRunResult>,
}

pub fn builtin_catalog() -> Vec<TemplateCatalogItem> {
    builtin_templates()
        .into_iter()
        .map(|t| TemplateCatalogItem {
            id: t.id.to_string(),
            name: t.name.to_string(),
            description: t.description.to_string(),
            severity: t.severity.to_string(),
            steps: t.steps.len(),
        })
        .collect()
}

pub fn builtin_template_yaml(id: &str) -> Option<&'static str> {
    match id {
        "http_baseline" => Some(include_str!("../templates/http_baseline.yaml")),
        "reflected_xss_token" => Some(include_str!("../templates/reflected_xss_token.yaml")),
        "multi_step_state_chain" => Some(include_str!("../templates/multi_step_state_chain.yaml")),
        _ => None,
    }
}

fn builtin_templates() -> Vec<TemplateDoc> {
    let mut out = Vec::new();
    for id in [
        "http_baseline",
        "reflected_xss_token",
        "multi_step_state_chain",
    ] {
        if let Some(yaml) = builtin_template_yaml(id) {
            if let Ok(t) = serde_yaml::from_str::<TemplateDoc>(yaml) {
                out.push(t);
            }
        }
    }
    out
}

fn normalize_base_url(target: &str) -> String {
    let t = target.trim();
    if t.is_empty() {
        return "".to_string();
    }
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

fn join_url(base_url: &str, path_or_url: &str) -> String {
    let p = path_or_url.trim();
    if p.starts_with("http://") || p.starts_with("https://") {
        return p.to_string();
    }
    let b = base_url.trim_end_matches('/');
    let p2 = if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{p}")
    };
    format!("{b}{p2}")
}

fn render_string(
    s: &str,
    base_url: &str,
    vars: &BTreeMap<String, String>,
    state: &BTreeMap<String, String>,
) -> String {
    let mut out = s.to_string();
    out = out.replace("{{BaseURL}}", base_url);
    for (k, v) in vars {
        out = out.replace(&format!("{{{{vars.{k}}}}}"), v);
    }
    for (k, v) in state {
        out = out.replace(&format!("{{{{state.{k}}}}}"), v);
    }
    out
}

fn headers_to_map(headers: &reqwest::header::HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in headers.iter() {
        if let Ok(s) = v.to_str() {
            out.insert(k.as_str().to_lowercase(), s.to_string());
        }
    }
    out
}

fn eval_matcher(
    matcher: &TemplateMatcher,
    status: u16,
    headers: &BTreeMap<String, String>,
    body: &str,
    duration_ms: u64,
    rendered_contains: &str,
    rendered_regex: &str,
) -> (bool, serde_json::Value) {
    match matcher {
        TemplateMatcher::Status { statuses } => {
            let ok = statuses.iter().any(|s| *s == status);
            (
                ok,
                json!({"type":"status","status":status,"expected":statuses,"ok":ok}),
            )
        }
        TemplateMatcher::BodyContains { .. } => {
            let ok = body.contains(rendered_contains);
            (
                ok,
                json!({"type":"body_contains","contains":rendered_contains,"ok":ok}),
            )
        }
        TemplateMatcher::HeaderContains { header, .. } => {
            let hv = headers
                .get(&header.to_lowercase())
                .cloned()
                .unwrap_or_default();
            let ok = hv.contains(rendered_contains);
            (
                ok,
                json!({"type":"header_contains","header":header,"contains":rendered_contains,"observed":hv,"ok":ok}),
            )
        }
        TemplateMatcher::Regex { .. } => {
            let re = regex::Regex::new(rendered_regex)
                .unwrap_or_else(|_| crate::regex_util::never_matches());
            let ok = re.is_match(body);
            (ok, json!({"type":"regex","regex":rendered_regex,"ok":ok}))
        }
        TemplateMatcher::DurationGtMs { ms } => {
            let ok = duration_ms >= *ms;
            (
                ok,
                json!({"type":"duration_gt_ms","duration_ms":duration_ms,"threshold_ms":ms,"ok":ok}),
            )
        }
    }
}

fn eval_matchers(condition: &str, items: &[bool]) -> bool {
    if items.is_empty() {
        return true;
    }
    match condition {
        "or" => items.iter().any(|v| *v),
        _ => items.iter().all(|v| *v),
    }
}

fn extract_into_state(
    extractor: &TemplateExtractor,
    headers: &BTreeMap<String, String>,
    body: &str,
    out: &mut BTreeMap<String, String>,
) -> Option<(String, String)> {
    match extractor {
        TemplateExtractor::Header { name, header } => {
            let v = headers
                .get(&header.to_lowercase())
                .cloned()
                .unwrap_or_default();
            out.insert(name.to_string(), v.clone());
            Some((name.to_string(), v))
        }
        TemplateExtractor::Regex { name, regex, group } => {
            let re = regex::Regex::new(regex).ok()?;
            let caps = re.captures(body)?;
            let g = group.unwrap_or(1);
            let m = caps.get(g)?;
            let v = m.as_str().to_string();
            out.insert(name.to_string(), v.clone());
            Some((name.to_string(), v))
        }
    }
}

async fn fetch_limited_text(
    resp: reqwest::Response,
    max_bytes: usize,
) -> (u16, BTreeMap<String, String>, String) {
    let status = resp.status().as_u16();
    let headers = headers_to_map(resp.headers());
    let bytes = resp.bytes().await.unwrap_or_default();
    let limited = if bytes.len() > max_bytes {
        &bytes[..max_bytes]
    } else {
        &bytes[..]
    };
    let body = String::from_utf8_lossy(limited).into_owned();
    (status, headers, body)
}

pub async fn run_template(
    template: TemplateDoc,
    target_url: &str,
    max_body_bytes: usize,
) -> Result<TemplateRunResult, String> {
    let base = normalize_base_url(target_url);
    if base.is_empty() {
        return Err("target_url required".into());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let mut state: BTreeMap<String, String> = BTreeMap::new();
    let mut steps_out: Vec<StepRunResult> = Vec::new();
    let vars = template.vars.clone();

    for step in &template.steps {
        let method = step.request.method.trim().to_uppercase();
        let raw_path = render_string(&step.request.path, &base, &vars, &state);
        let url = join_url(&base, &raw_path);

        let mut headers = reqwest::header::HeaderMap::new();
        for (k, v) in &step.request.headers {
            let hk = match reqwest::header::HeaderName::from_bytes(k.as_bytes()) {
                Ok(x) => x,
                Err(_) => continue,
            };
            let rv = render_string(v, &base, &vars, &state);
            if let Ok(hv) = reqwest::header::HeaderValue::from_str(&rv) {
                headers.insert(hk, hv);
            }
        }

        let timeout = step
            .request
            .timeout_ms
            .unwrap_or(15_000)
            .max(100)
            .min(120_000);

        let body = step
            .request
            .body
            .as_deref()
            .map(|b| render_string(b, &base, &vars, &state));

        let start = std::time::Instant::now();
        let mut req = client
            .request(
                method
                    .parse::<reqwest::Method>()
                    .unwrap_or(reqwest::Method::GET),
                &url,
            )
            .headers(headers)
            .timeout(Duration::from_millis(timeout));
        if let Some(ref b) = body {
            req = req.body(b.clone());
        }

        let resp = req.send().await;
        let duration_ms = start.elapsed().as_millis() as u64;

        let (status, resp_headers, resp_body) = match resp {
            Ok(r) => fetch_limited_text(r, max_body_bytes).await,
            Err(e) => {
                let rr = StepRunResult {
                    id: step.id.clone(),
                    request: json!({
                        "method": method,
                        "url": url,
                        "timeout_ms": timeout,
                        "headers": step.request.headers,
                        "body": body,
                    }),
                    response: json!({"error": e.to_string()}),
                    extracted: BTreeMap::new(),
                    matcher_results: vec![
                        json!({"type":"network_error","error":e.to_string(),"ok":false}),
                    ],
                    matched: false,
                    duration_ms,
                    state_after: state.clone(),
                };
                steps_out.push(rr);
                continue;
            }
        };

        let mut extracted: BTreeMap<String, String> = BTreeMap::new();
        for ex in &step.extractors {
            if let Some((k, v)) = extract_into_state(ex, &resp_headers, &resp_body, &mut state) {
                extracted.insert(k, v);
            }
        }

        let cond = step
            .matchers_condition
            .as_deref()
            .unwrap_or("and")
            .trim()
            .to_lowercase();
        let mut matcher_results = Vec::new();
        let mut matcher_bools = Vec::new();
        for m in &step.matchers {
            let rendered_contains = match m {
                TemplateMatcher::BodyContains { contains } => {
                    render_string(contains, &base, &vars, &state)
                }
                TemplateMatcher::HeaderContains { contains, .. } => {
                    render_string(contains, &base, &vars, &state)
                }
                _ => "".to_string(),
            };
            let rendered_regex = match m {
                TemplateMatcher::Regex { regex } => render_string(regex, &base, &vars, &state),
                _ => "".to_string(),
            };
            let (ok, detail) = eval_matcher(
                m,
                status,
                &resp_headers,
                &resp_body,
                duration_ms,
                &rendered_contains,
                &rendered_regex,
            );
            matcher_bools.push(ok);
            matcher_results.push(detail);
        }
        let matched = eval_matchers(&cond, &matcher_bools);

        steps_out.push(StepRunResult {
            id: step.id.clone(),
            request: json!({
                "method": method,
                "url": url,
                "timeout_ms": timeout,
                "headers": step.request.headers,
                "body": body,
            }),
            response: json!({
                "status": status,
                "headers": resp_headers,
                "body_preview": resp_body.chars().take(2000).collect::<String>(),
            }),
            extracted,
            matcher_results,
            matched,
            duration_ms,
            state_after: state.clone(),
        });
    }

    let success = template
        .success_condition
        .as_deref()
        .unwrap_or("all")
        .trim()
        .to_lowercase();
    let overall_matched = match success.as_str() {
        "any" => steps_out.iter().any(|s| s.matched),
        "last" => steps_out.last().map(|s| s.matched).unwrap_or(false),
        _ => steps_out.iter().all(|s| s.matched),
    };
    let verification = if overall_matched {
        json!({
            "verified": true,
            "method": "template_matchers",
            "evidence": "All steps satisfied their matchers.",
        })
    } else {
        json!({
            "verified": false,
            "method": "template_matchers",
            "evidence": "One or more steps did not satisfy matchers.",
        })
    };

    Ok(TemplateRunResult {
        template: TemplateCatalogItem {
            id: template.id,
            name: template.name,
            description: template.description,
            severity: template.severity,
            steps: template.steps.len(),
        },
        target_url: base,
        matched: overall_matched,
        verification,
        steps: steps_out,
    })
}
