//! Semantic business-logic fuzzing & OpenAPI state machine (Module 4).

use async_trait::async_trait;
use quick_xml::events::Event;
use quick_xml::Reader;
use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::warn;
use weissman_core::models::semantic::{SemanticConfig, StateEdge, StateNode};

use crate::context::{EngineRunOutcome, ScanContext};
use crate::engine_trait::CyberEngine;
use crate::openai_chat::{
    chat_completion_text, llm_http_client, resolve_llm_model, DEFAULT_LLM_BASE_URL,
};
use crate::result::EngineResult;
use crate::stealth;

use super::wordlist::{expand_recursive_directory_paths, expanded_path_wordlist};

const SPEC_PATHS: [&str; 4] = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v2/api-docs",
];
const TARGET_TIMEOUT_SECS: u64 = 10;
const LLM_TIMEOUT_SECS: u64 = 120;
const LLM_MAX_TOKENS_SCHEMA: u32 = 1024;
const LLM_MAX_TOKENS_CURL: u32 = 512;
const MAX_PAYLOADS_PER_ENDPOINT: usize = 5;
const BUSINESS_LOGIC_PROMPT: &str = r#"Analyze this API endpoint schema and parameter names. Generate exactly 5 DISTINCT HTTP request payloads tailored to THIS schema — do not repeat generic templates; combine field names from the schema with edge cases (type confusion, signed/unsigned wrap, Unicode normalization, nested object injection, array bounds, null vs missing vs empty string, impossible dates, role/tenant_id tampering if such fields exist). Aim for payloads unlikely to appear in static wordlists. Output ONLY a JSON array of objects, each with a "body" field (string or object). No markdown. Example shape: [{"body":{"price":-1}},{"body":{"quantity":0}}]"#;

#[derive(Debug, Clone)]
pub struct SemanticFuzzResult {
    pub result: EngineResult,
    pub state_nodes: Vec<StateNode>,
    pub state_edges: Vec<StateEdge>,
    pub reasoning_log: String,
}

fn normalize_base(target: &str) -> String {
    let base = target.trim().trim_end_matches('/');
    if base.is_empty() {
        return String::new();
    }
    if base.starts_with("http://") || base.starts_with("https://") {
        return base.to_string();
    }
    format!("https://{}", base)
}

fn apply_stealth_req(
    req: reqwest::RequestBuilder,
    st: Option<&stealth::StealthConfig>,
) -> reqwest::RequestBuilder {
    match st {
        Some(s) => req.headers(stealth::random_morph_headers(s)),
        None => req,
    }
}

/// Fetch OpenAPI and return state machine only (for UI). No LLM calls.
pub async fn get_state_machine(target: &str) -> Option<(Vec<StateNode>, Vec<StateEdge>)> {
    let base = normalize_base(target);
    if base.is_empty() {
        return None;
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(TARGET_TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .ok()?;
    let spec = fetch_openapi(&base, &client, None).await?;
    Some(parse_state_machine(&spec))
}

async fn fetch_openapi(
    base: &str,
    client: &reqwest::Client,
    st: Option<&stealth::StealthConfig>,
) -> Option<Value> {
    for path in &SPEC_PATHS {
        if let Some(s) = st {
            stealth::apply_jitter(s);
        }
        let url = format!("{}{}", base, path);
        let req = apply_stealth_req(client.get(&url), st);
        if let Ok(r) = req.send().await {
            if r.status().is_success() {
                if let Ok(v) = r.json::<Value>().await {
                    return Some(v);
                }
            }
        }
    }
    None
}

fn path_order_rank(path: &str) -> u8 {
    let p = path.to_lowercase();
    if p.contains("login") || p.contains("auth") || p.contains("signin") {
        return 0;
    }
    if p.contains("cart") || p.contains("basket") || p.contains("order") && !p.contains("checkout")
    {
        return 1;
    }
    if p.contains("checkout") || p.contains("payment") || p.contains("pay") {
        return 2;
    }
    if p.contains("refund") || p.contains("cancel") {
        return 3;
    }
    4
}

/// Parse spec into state machine nodes and edges.
pub fn parse_state_machine(spec: &Value) -> (Vec<StateNode>, Vec<StateEdge>) {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let empty: serde_json::Map<String, Value> = serde_json::Map::new();
    let paths = spec
        .get("paths")
        .and_then(|p| p.as_object())
        .unwrap_or(&empty);
    let mut path_methods: Vec<(String, String, String)> = Vec::new();
    for (path, path_item) in paths {
        let path_item = match path_item.as_object() {
            Some(o) => o,
            None => continue,
        };
        for method in ["get", "post", "put", "patch", "delete"] {
            if path_item.get(method).is_none() {
                continue;
            }
            let summary = path_item
                .get(method)
                .and_then(|o| o.get("summary").and_then(|s| s.as_str()))
                .unwrap_or("")
                .to_string();
            let id = format!(
                "{}_{}",
                method.to_uppercase(),
                path.replace('/', "_").trim_start_matches('_')
            );
            path_methods.push((path.clone(), method.to_string(), summary.clone()));
            nodes.push(StateNode {
                id: id.clone(),
                path: path.clone(),
                method: method.to_uppercase(),
                summary,
            });
        }
    }
    path_methods.sort_by(|a, b| {
        let ra = path_order_rank(&a.0);
        let rb = path_order_rank(&b.0);
        ra.cmp(&rb).then_with(|| a.0.cmp(&b.0))
    });
    for i in 1..path_methods.len() {
        let from_id = format!(
            "{}_{}",
            path_methods[i - 1].1.to_uppercase(),
            path_methods[i - 1]
                .0
                .replace('/', "_")
                .trim_start_matches('_')
        );
        let to_id = format!(
            "{}_{}",
            path_methods[i].1.to_uppercase(),
            path_methods[i].0.replace('/', "_").trim_start_matches('_')
        );
        edges.push(StateEdge {
            id: format!("e-{}-{}", from_id, to_id),
            from_id,
            to_id,
            edge_type: "sequence".to_string(),
        });
    }
    (nodes, edges)
}

fn schema_summary_for_endpoint(spec: &Value, path: &str, method: &str) -> String {
    let empty: serde_json::Map<String, Value> = serde_json::Map::new();
    let paths = spec
        .get("paths")
        .and_then(|p| p.as_object())
        .unwrap_or(&empty);
    let path_item = match paths.get(path) {
        Some(v) => v.as_object(),
        None => return String::new(),
    };
    let path_item = match path_item {
        Some(o) => o,
        None => return String::new(),
    };
    let op = path_item.get(method).and_then(|v| v.as_object());
    let op = match op {
        Some(o) => o,
        None => return String::new(),
    };
    let summary = op.get("summary").and_then(|s| s.as_str()).unwrap_or("");
    let empty_params: Vec<Value> = vec![];
    let params = op
        .get("parameters")
        .and_then(|p| p.as_array())
        .unwrap_or(&empty_params);
    let req_body = op.get("requestBody");
    let mut s = format!(
        "Path: {} {} Summary: {}\nParameters: ",
        path,
        method.to_uppercase(),
        summary
    );
    for p in params {
        if let Some(obj) = p.as_object() {
            let name = obj.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let schema = obj.get("schema").cloned().unwrap_or(serde_json::json!({}));
            s.push_str(&format!("{} ({}) ", name, schema));
        }
    }
    if let Some(rb) = req_body {
        s.push_str(&format!("\nRequestBody: {}", rb));
    }
    s
}

async fn vllm_generate_payloads(
    llm_base_url: &str,
    llm_model: &str,
    schema_text: &str,
    temperature: f64,
    llm_tenant_id: Option<i64>,
) -> (Vec<Value>, String) {
    let client = llm_http_client(LLM_TIMEOUT_SECS);
    let model = resolve_llm_model(llm_model);
    let user = format!(
        "{}\n\nSchema:\n{}\n\nOutput ONLY a JSON array of payload objects with \"body\" field.",
        BUSINESS_LOGIC_PROMPT, schema_text
    );
    let mut reasoning_log = format!(
        "[vLLM] Prompt (excerpt): {}...\n",
        user.chars().take(400).collect::<String>()
    );
    let text = match chat_completion_text(
        &client,
        llm_base_url,
        model.as_str(),
        Some("You assist authorized security testing. Output only valid JSON arrays as requested."),
        &user,
        temperature,
        LLM_MAX_TOKENS_SCHEMA,
        llm_tenant_id,
        "semantic_payloads",
        true,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            let detail = serde_json::to_string(&e.to_client_value()).unwrap_or_default();
            warn!(
                target: "semantic_ai_fuzz",
                error = %e,
                detail = %detail,
                "vLLM payload generation failed (check llm_base_url / model / network)"
            );
            reasoning_log.push_str(&format!("[vLLM] Request failed: {e} detail={detail}\n"));
            return (vec![], reasoning_log);
        }
    };
    reasoning_log.push_str(&format!(
        "[vLLM] Response (excerpt): {}...\n",
        text.chars().take(800).collect::<String>()
    ));

    let raw = parse_json_payloads_from_response(&text);
    let before = raw.len();
    let payloads: Vec<Value> = raw
        .into_iter()
        .filter(|p| semantic_payload_wire_ok(p))
        .collect();
    if before > payloads.len() {
        reasoning_log.push_str(&format!(
            "[preflight] dropped {} malformed JSON/XML payload(s) before HTTP / follow-up LLM\n",
            before - payloads.len()
        ));
    }
    (payloads, reasoning_log)
}

fn curl_for_json_request(url: &str, method: &str, body: &str) -> String {
    let u = url.trim();
    let m = method.trim().to_uppercase();
    if m == "GET" || body.trim().is_empty() {
        format!("curl -sS -k -X {} '{}'", m, u.replace('\'', "'\\''"))
    } else {
        let b_esc = body.replace('\\', "\\\\").replace('\'', "'\\''");
        format!(
            "curl -sS -k -X {} '{}' -H 'Content-Type: application/json' -d '{}'",
            m,
            u.replace('\'', "'\\''"),
            b_esc
        )
    }
}

fn extract_curl_from_llm(text: &str) -> Option<String> {
    for line in text.lines() {
        let t = line.trim().trim_start_matches('`').trim_end_matches('`');
        if t.starts_with("curl ") {
            return Some(t.to_string());
        }
    }
    let t = text.trim().trim_start_matches('`').trim_end_matches('`');
    if t.starts_with("curl ") {
        return t.lines().next().map(|l| l.trim().to_string());
    }
    None
}

async fn synthesize_poc_curl_llm(
    llm_base_url: &str,
    llm_model_cfg: &str,
    full_url: &str,
    method: &str,
    body_json: &str,
    business_context: &str,
    http_status: u16,
    llm_tenant_id: Option<i64>,
) -> Option<String> {
    let client = llm_http_client(LLM_TIMEOUT_SECS);
    let model = resolve_llm_model(llm_model_cfg);
    let user = format!(
        r#"You are a security engineer documenting a safe proof-of-concept. An HTTP request was accepted by the server (HTTP {}) which may indicate a business-logic weakness.

Full URL: {}
Method: {}
JSON body used: {}
Endpoint / schema context:
{}

Output EXACTLY ONE shell line: a curl command that reproduces this request. Use: curl -sS -k -X METHOD 'URL' and if the body is non-empty add -H 'Content-Type: application/json' -d 'BODY' with proper quoting. No markdown fences, no explanation, no multiple lines."#,
        http_status,
        full_url,
        method,
        body_json.chars().take(8000).collect::<String>(),
        business_context.chars().take(2000).collect::<String>()
    );
    let text = chat_completion_text(
        &client,
        llm_base_url,
        model.as_str(),
        Some("You output only a single curl line for authorized security documentation."),
        &user,
        0.12,
        LLM_MAX_TOKENS_CURL,
        llm_tenant_id,
        "semantic_poc_curl",
        true,
    )
    .await
    .ok()?;
    extract_curl_from_llm(&text)
}

fn basic_xml_wire_ok(s: &str) -> bool {
    let t = s.trim();
    if !t.starts_with('<') {
        return false;
    }
    let mut r = Reader::from_str(t);
    r.trim_text(true);
    let mut saw_element = false;
    for _ in 0..8192 {
        match r.read_event() {
            Ok(Event::Start(_) | Event::Empty(_)) => saw_element = true,
            Ok(Event::Eof) => return saw_element,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    saw_element
}

/// Drop syntactically invalid probe bodies so workers do not burn HTTP + vLLM cycles on garbage.
fn semantic_payload_wire_ok(payload: &Value) -> bool {
    let body_val = payload
        .get("body")
        .cloned()
        .unwrap_or_else(|| payload.clone());
    let body_str = if body_val.is_object() || body_val.is_array() {
        serde_json::to_string(&body_val).unwrap_or_default()
    } else {
        body_val.as_str().unwrap_or("").to_string()
    };
    preflight_semantic_probe_body(&body_str, true).is_ok()
}

/// Validate JSON or XML wire shape before queueing outbound probes or secondary LLM calls (PoC curl).
#[must_use]
pub fn preflight_semantic_probe_body(body: &str, expect_json_wire: bool) -> Result<(), String> {
    let p = body.trim();
    if p.is_empty() {
        return Err("empty_body".into());
    }
    if p.starts_with('<') {
        return if basic_xml_wire_ok(p) {
            Ok(())
        } else {
            Err("xml_syntax:ill_formed_stream".into())
        };
    }
    if p.starts_with('{') || p.starts_with('[') {
        serde_json::from_str::<serde_json::Value>(p)
            .map_err(|e| format!("json_syntax:{e}"))?;
        return Ok(());
    }
    if expect_json_wire {
        return Err("expected_json_or_xml_wire".into());
    }
    Ok(())
}

fn parse_json_payloads_from_response(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let trimmed = text.trim();
    let start = trimmed.find('[').unwrap_or(0);
    let end = trimmed.rfind(']').map(|i| i + 1).unwrap_or(trimmed.len());
    let slice = trimmed.get(start..end).unwrap_or("");
    if let Ok(arr) = serde_json::from_str::<Vec<Value>>(slice) {
        for v in arr.into_iter().take(MAX_PAYLOADS_PER_ENDPOINT) {
            if v.get("body").is_some() || v.is_object() {
                out.push(v);
            }
        }
    }
    if out.is_empty() {
        for line in text.lines() {
            let line = line.trim().trim_start_matches('`');
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                if v.get("body").is_some() || v.as_object().map(|o| !o.is_empty()).unwrap_or(false)
                {
                    out.push(v);
                    if out.len() >= MAX_PAYLOADS_PER_ENDPOINT {
                        break;
                    }
                }
            }
        }
    }
    out
}

fn normalize_probe_path(path: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    Some(if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    })
}

/// Any response except total failure / explicit not-found is worth expanding (recursive crawl).
fn path_prefix_warrants_recursion(status: u16) -> bool {
    status != 0 && status != 404
}

/// Same invariant as `fingerprint_engine::regex_util::compile_never_matches`: static patterns include at least one valid regex.
fn semantic_never_match_regex() -> Regex {
    const PATTERNS: [&str; 3] = [r"[^\s\S]", "a^", r"(?m:^)\z"];
    for p in PATTERNS {
        match Regex::new(p) {
            Ok(r) => return r,
            Err(e) => tracing::error!(
                target: "semantic_fuzz",
                pattern = p,
                error = %e,
                "never-match pattern rejected"
            ),
        }
    }
    tracing::error!(target: "semantic_fuzz", "all static never-match patterns rejected");
    unreachable!("semantic_fuzz: NEVER_PATTERNS must include at least one valid regex")
}

static HREF_ACTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:href|action)\s*=\s*["']([^"']+)["']"#).unwrap_or_else(|e| {
        tracing::error!(target: "semantic_fuzz", error = %e, "href/action regex compile failed; link extraction disabled");
        semantic_never_match_regex()
    })
});

fn normalize_href_to_path(href: &str) -> Option<String> {
    let h = href.trim();
    if h.is_empty() || h.starts_with('#') || h.to_lowercase().starts_with("javascript:") {
        return None;
    }
    if h.to_lowercase().starts_with("mailto:") {
        return None;
    }
    let no_q = h.split('?').next().unwrap_or(h);
    if no_q.starts_with('/') {
        return normalize_probe_path(no_q);
    }
    if let Some(rest) = no_q.strip_prefix("http://").or_else(|| no_q.strip_prefix("https://")) {
        let path_start = rest.find('/')?;
        let path = rest.get(path_start..)?;
        return normalize_probe_path(path);
    }
    if !no_q.contains("://") {
        return normalize_probe_path(no_q);
    }
    None
}

fn html_extract_paths(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    for cap in HREF_ACTION_RE.captures_iter(html) {
        let Some(m) = cap.get(1) else {
            continue;
        };
        if let Some(p) = normalize_href_to_path(m.as_str()) {
            out.push(p);
        }
    }
    out.sort();
    out.dedup();
    out
}

async fn get_html_link_discovery_paths(
    base: &str,
    seed_paths: &[String],
    client: &reqwest::Client,
    st: Option<&stealth::StealthConfig>,
    probed: &std::collections::HashSet<String>,
    max_new: usize,
) -> Vec<String> {
    let mut discovered = std::collections::HashSet::<String>::new();
    let base = base.trim_end_matches('/');
    for path in seed_paths.iter().take(36) {
        if discovered.len() >= max_new {
            break;
        }
        let Some(path_norm) = normalize_probe_path(path) else {
            continue;
        };
        let url = format!("{base}{path_norm}");
        if let Some(s) = st {
            stealth::apply_jitter(s);
        }
        let req = apply_stealth_req(client.get(&url), st);
        let Ok(r) = req.send().await else {
            continue;
        };
        let status = r.status().as_u16();
        if !(200..400).contains(&status) {
            continue;
        }
        let ct = r
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        if !ct.contains("text/html") && !ct.is_empty() {
            continue;
        }
        let Ok(text) = r.text().await else {
            continue;
        };
        for p in html_extract_paths(&text) {
            if probed.contains(&p) {
                continue;
            }
            if discovered.insert(p.clone()) && discovered.len() >= max_new {
                break;
            }
        }
    }
    discovered.into_iter().collect()
}

async fn run_semantic_fallback_paths(
    base: &str,
    client: &reqwest::Client,
    st: Option<&stealth::StealthConfig>,
    paths: &[String],
    llm_base_url: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> Vec<serde_json::Value> {
    let payloads: Vec<Value> = vec![
        serde_json::json!({"body": {"price": -1}}),
        serde_json::json!({"body": {"quantity": 0}}),
        serde_json::json!({"body": {"amount": -1}}),
        serde_json::json!({"body": {"email": "a@b.com", "password": "x"}}),
        serde_json::json!({"body": {"id": 1}}),
    ];
    let mut findings = Vec::new();
    let base = base.trim_end_matches('/');
    let mut probed: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut recursion_seeds: std::collections::HashSet<String> = std::collections::HashSet::new();

    async fn post_probe_batch(
        base: &str,
        client: &reqwest::Client,
        st: Option<&stealth::StealthConfig>,
        llm_base_url: &str,
        llm_model: &str,
        llm_tid: Option<i64>,
        paths_batch: &[String],
        payloads: &[Value],
        probed: &mut std::collections::HashSet<String>,
        recursion_seeds: &mut std::collections::HashSet<String>,
        findings: &mut Vec<serde_json::Value>,
    ) {
        for path in paths_batch {
            let Some(path_norm) = normalize_probe_path(path) else {
                continue;
            };
            if !probed.insert(path_norm.clone()) {
                continue;
            }
            let url = format!("{}{}", base, path_norm);
            for payload in payloads {
                if let Some(s) = st {
                    stealth::apply_jitter(s);
                }
                let body_val = payload
                    .get("body")
                    .cloned()
                    .unwrap_or_else(|| payload.clone());
                let body_str =
                    serde_json::to_string(&body_val).unwrap_or_else(|_| "{}".to_string());
                let req = apply_stealth_req(
                    client
                        .post(&url)
                        .header("Content-Type", "application/json")
                        .body(body_str.clone()),
                    st,
                );
                if let Ok(r) = req.send().await {
                    let status = r.status().as_u16();
                    if path_prefix_warrants_recursion(status) {
                        recursion_seeds.insert(path_norm.clone());
                    }
                    if (200..300).contains(&status) {
                        let baseline = curl_for_json_request(&url, "POST", &body_str);
                        let llm_curl = synthesize_poc_curl_llm(
                            llm_base_url,
                            llm_model,
                            &url,
                            "POST",
                            &body_str,
                            "Fallback path list probe without OpenAPI; invalid business payload accepted.",
                            status,
                            llm_tid,
                        )
                        .await;
                        let poc = llm_curl
                            .filter(|c| c.len() > 12 && c.contains("curl"))
                            .unwrap_or(baseline);
                        findings.push(serde_json::json!({
                            "type": "semantic_ai_fuzz",
                            "subtype": "business_logic_flaw_fallback",
                            "path": path_norm,
                            "url": url,
                            "method": "POST",
                            "request_body": body_str,
                            "server_status": status,
                            "severity": "medium",
                            "title": "Endpoint accepted probe (no OpenAPI); verify business rules",
                            "payload_preview": body_str.chars().take(100).collect::<String>(),
                            "poc_exploit": poc,
                        }));
                    }
                }
            }
        }
    }

    let initial: Vec<String> = paths.iter().take(40).cloned().collect();
    post_probe_batch(
        base,
        client,
        st,
        llm_base_url,
        llm_model,
        llm_tenant_id,
        &initial,
        &payloads,
        &mut probed,
        &mut recursion_seeds,
        &mut findings,
    )
    .await;

    let seeds: Vec<String> = recursion_seeds.into_iter().collect();
    let expanded = expand_recursive_directory_paths(&seeds, 72);
    let second_wave: Vec<String> = expanded
        .into_iter()
        .filter(|p| !probed.contains(p))
        .take(48)
        .collect();

    post_probe_batch(
        base,
        client,
        st,
        llm_base_url,
        llm_model,
        llm_tenant_id,
        &second_wave,
        &payloads,
        &mut probed,
        &mut std::collections::HashSet::new(),
        &mut findings,
    )
    .await;

    let mut crawl_seeds: Vec<String> = initial
        .iter()
        .chain(second_wave.iter())
        .cloned()
        .collect();
    crawl_seeds.sort();
    crawl_seeds.dedup();
    let html_paths =
        get_html_link_discovery_paths(base, &crawl_seeds, client, st, &probed, 72).await;
    let third_wave: Vec<String> = html_paths
        .into_iter()
        .filter(|p| !probed.contains(p))
        .take(44)
        .collect();

    post_probe_batch(
        base,
        client,
        st,
        llm_base_url,
        llm_model,
        llm_tenant_id,
        &third_wave,
        &payloads,
        &mut probed,
        &mut std::collections::HashSet::new(),
        &mut findings,
    )
    .await;

    findings
}

async fn execute_payload(
    base: &str,
    path: &str,
    method: &str,
    payload: &Value,
    client: &reqwest::Client,
    st: Option<&stealth::StealthConfig>,
) -> (u16, bool) {
    if let Some(s) = st {
        stealth::apply_jitter(s);
    }
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let body_val = payload
        .get("body")
        .cloned()
        .unwrap_or_else(|| payload.clone());
    let body_str = if body_val.is_object() || body_val.is_array() {
        serde_json::to_string(&body_val).unwrap_or_else(|_| "{}".to_string())
    } else {
        body_val.as_str().unwrap_or("{}").to_string()
    };
    let m = method.to_uppercase();
    if matches!(m.as_str(), "POST" | "PUT" | "PATCH")
        && preflight_semantic_probe_body(&body_str, true).is_err()
    {
        return (0, false);
    }
    let req = match m.as_str() {
        "POST" => apply_stealth_req(
            client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body_str),
            st,
        ),
        "PUT" => apply_stealth_req(
            client
                .put(&url)
                .header("Content-Type", "application/json")
                .body(body_str),
            st,
        ),
        "PATCH" => apply_stealth_req(
            client
                .patch(&url)
                .header("Content-Type", "application/json")
                .body(body_str),
            st,
        ),
        _ => apply_stealth_req(client.get(&url), st),
    };
    match req.send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let accepted = (200..300).contains(&status);
            (status, accepted)
        }
        Err(_) => (0, false),
    }
}

pub async fn run_semantic_fuzz_result(
    target: &str,
    st: Option<&stealth::StealthConfig>,
    config: &SemanticConfig,
    discovered_paths: Option<&[String]>,
    llm_tenant_id: Option<i64>,
) -> SemanticFuzzResult {
    let config = config.clone();
    let st_owned: Option<stealth::StealthConfig> = st.cloned();
    let st_ref = st_owned.as_ref();
    let paths_opt: Option<Vec<String>> = discovered_paths.map(|p| p.to_vec());

    let base = normalize_base(target);
    if base.is_empty() {
        return SemanticFuzzResult {
            result: EngineResult::error("target required"),
            state_nodes: vec![],
            state_edges: vec![],
            reasoning_log: String::new(),
        };
    }

    let client = match st_ref {
        Some(s) => {
            stealth::apply_jitter(s);
            stealth::build_client(s, TARGET_TIMEOUT_SECS)
        }
        None => reqwest::Client::builder()
            .timeout(Duration::from_secs(TARGET_TIMEOUT_SECS))
            .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
    };

    let llm_base = if config.llm_base_url.is_empty() {
        DEFAULT_LLM_BASE_URL.to_string()
    } else {
        config.llm_base_url.trim().to_string()
    };

    let spec = match fetch_openapi(&base, &client, st_ref).await {
        Some(s) => s,
        None => {
            let paths: Vec<String> = paths_opt
                .clone()
                .unwrap_or_else(expanded_path_wordlist);
            let fallback_findings = run_semantic_fallback_paths(
                &base,
                &client,
                st_ref,
                &paths,
                llm_base.as_str(),
                config.llm_model.as_str(),
                llm_tenant_id,
            )
            .await;
            let msg = format!(
                "No OpenAPI; primary path list + recursive directory expansion, {} potential business-logic flaws",
                fallback_findings.len()
            );
            return SemanticFuzzResult {
                result: EngineResult::ok(fallback_findings, msg),
                state_nodes: vec![],
                state_edges: vec![],
                reasoning_log: "[Semantic] No OpenAPI spec; ran fallback wordlist, recursive path expansion, and HTML link/action discovery (third wave).\n"
                    .to_string(),
            };
        }
    };

    let (state_nodes, state_edges) = parse_state_machine(&spec);
    let temperature = config.llm_temperature.clamp(0.0, 2.0);
    let max_depth = config.max_sequence_depth.clamp(1, 20);
    let mut findings = Vec::new();
    let mut full_log = format!(
        "[Semantic] State machine: {} nodes, {} edges. Max depth: {}\n",
        state_nodes.len(),
        state_edges.len(),
        max_depth
    );

    let n_iter = state_nodes.len().min(max_depth);
    for ni in 0..n_iter {
        let node = &state_nodes[ni];
        let schema_text =
            schema_summary_for_endpoint(&spec, &node.path, &node.method.to_lowercase());
        if schema_text.is_empty() {
            continue;
        }
        let (payloads, log_frag) = vllm_generate_payloads(
            llm_base.as_str(),
            config.llm_model.as_str(),
            &schema_text,
            temperature,
            llm_tenant_id,
        )
        .await;
        full_log.push_str(&log_frag);

        for pi in 0..payloads.len() {
            let payload = &payloads[pi];
            let body_val = payload
                .get("body")
                .cloned()
                .unwrap_or_else(|| payload.clone());
            let body_str = if body_val.is_object() || body_val.is_array() {
                serde_json::to_string(&body_val).unwrap_or_else(|_| "{}".to_string())
            } else {
                body_val.as_str().unwrap_or("{}").to_string()
            };
            let full_url = format!("{}{}", base.trim_end_matches('/'), node.path);
            let (status, accepted) =
                execute_payload(&base, &node.path, &node.method, payload, &client, st_ref).await;
            if accepted && (node.method == "POST" || node.method == "PUT" || node.method == "PATCH")
            {
                let baseline = curl_for_json_request(&full_url, &node.method, &body_str);
                let llm_curl = synthesize_poc_curl_llm(
                    llm_base.as_str(),
                    config.llm_model.as_str(),
                    &full_url,
                    &node.method,
                    &body_str,
                    &schema_text,
                    status,
                    llm_tenant_id,
                )
                .await;
                let poc = llm_curl
                    .filter(|c| c.len() > 12 && c.contains("curl"))
                    .unwrap_or(baseline);
                findings.push(serde_json::json!({
                    "type": "semantic_ai_fuzz",
                    "subtype": "business_logic_flaw",
                    "path": node.path,
                    "url": full_url,
                    "method": node.method,
                    "request_body": body_str,
                    "summary": node.summary,
                    "payload_preview": serde_json::to_string(payload).unwrap_or_default().chars().take(200).collect::<String>(),
                    "server_status": status,
                    "severity": "critical",
                    "title": "Business logic flaw: server accepted invalid payload",
                    "poc_exploit": poc,
                    "remediation": "Validate business rules server-side: reject negative amounts, enforce state machine order, validate enums and ranges."
                }));
            }
        }
    }

    full_log.push_str(&format!("[Semantic] Findings: {}\n", findings.len()));
    let msg = format!(
        "Semantic Logic: {} endpoints analyzed, {} business logic flaws",
        state_nodes.len().min(max_depth),
        findings.len()
    );
    SemanticFuzzResult {
        result: EngineResult::ok(findings, msg),
        state_nodes,
        state_edges,
        reasoning_log: full_log,
    }
}

pub struct SemanticAiFuzzCyberEngine;

#[async_trait]
impl CyberEngine for SemanticAiFuzzCyberEngine {
    fn engine_id(&self) -> &'static str {
        "semantic_ai_fuzz"
    }

    fn display_label(&self) -> &'static str {
        "Semantic AI Fuzz"
    }

    async fn execute(&self, ctx: &ScanContext) -> EngineRunOutcome {
        let paths = (!ctx.discovered_paths.is_empty()).then_some(ctx.discovered_paths.as_slice());
        let sem = run_semantic_fuzz_result(
            &ctx.primary_target,
            ctx.stealth.as_ref(),
            &ctx.semantic,
            paths,
            ctx.llm_tenant_id,
        )
        .await;
        let log = if sem.reasoning_log.is_empty() {
            None
        } else {
            Some(sem.reasoning_log)
        };
        EngineRunOutcome {
            result: sem.result,
            semantic_reasoning_log: log,
        }
    }
}
