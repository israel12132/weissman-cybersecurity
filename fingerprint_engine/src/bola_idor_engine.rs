//! BOLA/IDOR — Shadow replay matrix, vLLM resource-ID harvest, concurrent probing,
//! JSON sensitive-field leak diff, and optional OAST blind callbacks.
//! Routes through `stealth_engine` for proxy, TLS policy, jitter, and header morphing.

use crate::autonomous_identity::IdentityBundle;
use crate::engine_result::{print_result, EngineResult};
use crate::fuzz_http_pool::FuzzHttpPool;
use crate::fuzz_oob;
use crate::identity_engine::AuthContext;
use crate::stealth_engine;
use futures::stream::{self, FuturesUnordered, StreamExt};
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};

const TIMEOUT_SECS: u64 = 6;
const SPEC_PATHS: [&str; 4] = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v2/api-docs",
];

const FALLBACK_BOLA_PATHS: [&str; 8] = [
    "/rest/user/login",
    "/rest/user/registration",
    "/api/Users",
    "/api/Users/1",
    "/api/Users/2",
    "/rest/products",
    "/api/Addresss",
    "/rest/basket/1",
];

const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "email", "phone", "ssn", "password", "secret", "token", "credit", "account", "iban",
    "address", "dob", "sin", "passport", "license", "apikey", "api_key", "private",
];

static UUID_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
static OBJECT_ID_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();

fn uuid_re() -> &'static Regex {
    UUID_RE.get_or_init(|| {
        Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
            .unwrap_or_else(|e| {
                tracing::error!(target: "bola_idor", error = %e, "UUID regex compile failed; ID harvest disabled for this pattern");
                crate::regex_util::never_matches()
            })
    })
}

fn object_id_re() -> &'static Regex {
    OBJECT_ID_RE.get_or_init(|| {
        Regex::new(r"\b[0-9a-fA-F]{24}\b").unwrap_or_else(|e| {
            tracing::error!(target: "bola_idor", error = %e, "ObjectId regex compile failed");
            crate::regex_util::never_matches()
        })
    })
}

fn bola_max_in_flight() -> usize {
    std::env::var("WEISSMAN_BOLA_MAX_IN_FLIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(96)
        .clamp(8, 256)
}

fn llm_max_parallel() -> usize {
    std::env::var("WEISSMAN_BOLA_LLM_PARALLEL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
        .clamp(1, 8)
}

async fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

async fn make_client_async(stealth: Option<&stealth_engine::StealthConfig>) -> reqwest::Client {
    if let Some(s) = stealth {
        stealth_engine::apply_jitter(s);
    }
    match stealth {
        Some(s) => stealth_engine::build_client(s, TIMEOUT_SECS),
        None => default_client().await,
    }
}

fn apply_stealth_headers(
    req: reqwest::RequestBuilder,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> reqwest::RequestBuilder {
    match stealth {
        Some(s) => req.headers(stealth_engine::random_morph_headers(s)),
        None => req,
    }
}

fn apply_auth(
    req: reqwest::RequestBuilder,
    ctx: Option<&AuthContext>,
) -> reqwest::RequestBuilder {
    match ctx {
        Some(c) => req.headers(c.headers()),
        None => req,
    }
}

fn is_id_param(name: &str) -> bool {
    let n = name.to_lowercase();
    n.contains("id") || n.contains("uuid") || n == "key"
}

fn path_param_names(params: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for p in params {
        if let Some(obj) = p.as_object() {
            let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let in_ = obj.get("in").and_then(|v| v.as_str()).unwrap_or("");
            if !name.is_empty() && (in_ == "path" || is_id_param(name)) {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn substitute_path_params(path_tpl: &str, param_names: &[String], value: &str) -> String {
    let mut s = path_tpl.to_string();
    for k in param_names {
        s = s.replace(&format!("{{{k}}}"), value);
    }
    s
}

fn regex_harvest_ids(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for cap in uuid_re().find_iter(text) {
        out.push(cap.as_str().to_string());
    }
    for cap in object_id_re().find_iter(text) {
        out.push(cap.as_str().to_string());
    }
    out
}

fn dedupe_cap(mut v: Vec<String>, cap: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    v.retain(|s| seen.insert(s.clone()));
    v.truncate(cap);
    v
}

fn parse_llm_ids_response(raw: &str) -> Vec<String> {
    let Ok(v) = weissman_engines::parse_value_from_llm(raw) else {
        return Vec::new();
    };
    let Some(arr) = v.get("ids").and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|x| x.as_str().map(str::trim).filter(|s| !s.is_empty()))
        .map(String::from)
        .take(32)
        .collect()
}

async fn llm_harvest_resource_ids(
    http: &reqwest::Client,
    body_snippet: &str,
    path_hint: &str,
    tenant_id: Option<i64>,
) -> Vec<String> {
    let base = std::env::var("WEISSMAN_LLM_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| weissman_engines::openai_chat::DEFAULT_LLM_BASE_URL.to_string());
    let base = weissman_engines::openai_chat::normalize_openai_base_url(&base);
    let model = weissman_engines::openai_chat::resolve_llm_model("");
    const SYS: &str = r#"You extract API resource identifiers from HTTP response data. Output ONLY JSON: {"ids":["..."]} with no markdown fences. Include UUIDs, 24-hex Mongo-style ObjectIds, Hashids-style opaque strings (mixed alnum, length 8–32), and numeric resource IDs that clearly identify a user or tenant. Max 24 entries. If none, {"ids":[]}."#;
    let excerpt: String = body_snippet.chars().take(6000).collect();
    let user = format!("Path/context: {path_hint}\n\nBody excerpt:\n{excerpt}");
    match weissman_engines::openai_chat::chat_completion_text(
        http,
        &base,
        &model,
        Some(SYS),
        &user,
        0.12,
        1200,
        tenant_id,
        "bola_id_harvest",
        true,
    )
    .await
    {
        Ok(t) => parse_llm_ids_response(&t),
        Err(e) => {
            tracing::debug!(target: "bola_idor", "LLM harvest skipped: {}", e);
            Vec::new()
        }
    }
}

fn looks_like_email(s: &str) -> bool {
    s.contains('@')
        && s.contains('.')
        && s.len() > 5
        && s.len() < 320
}

fn looks_like_high_entropy_token(s: &str) -> bool {
    s.len() >= 28
        && s.len() <= 512
        && s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .count() * 10
            >= s.len() * 7
}

fn collect_sensitive_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                let kl = k.to_lowercase();
                let key_sensitive = SENSITIVE_KEY_FRAGMENTS
                    .iter()
                    .any(|frag| kl.contains(frag));
                match val {
                    Value::String(s) if !s.is_empty() && s.len() <= 4096 => {
                        if key_sensitive
                            || looks_like_email(s)
                            || looks_like_high_entropy_token(s)
                        {
                            out.push(s.clone());
                        }
                    }
                    Value::Object(_) | Value::Array(_) => collect_sensitive_strings(val, out),
                    _ => {}
                }
            }
        }
        Value::Array(arr) => {
            for x in arr {
                collect_sensitive_strings(x, out);
            }
        }
        _ => {}
    }
}

/// Returns sensitive strings from `baseline` that also appear in `other` (cross-auth / IDOR leak).
fn sensitive_leak_overlap(baseline: &str, other: &str) -> Option<Vec<String>> {
    let mut leaks = Vec::new();
    if let Ok(bv) = serde_json::from_str::<Value>(baseline) {
        let mut sens = Vec::new();
        collect_sensitive_strings(&bv, &mut sens);
        for s in sens {
            if s.len() >= 4 && other.contains(&s) {
                leaks.push(s);
            }
        }
    } else if let Ok(email_re) =
        Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    {
        for cap in email_re.find_iter(baseline) {
            let e = cap.as_str();
            if other.contains(e) {
                leaks.push(e.to_string());
            }
        }
    }
    if leaks.is_empty() {
        None
    } else {
        Some(leaks)
    }
}

fn email_harvest_nonjson(text: &str) -> Vec<String> {
    let Some(re) = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").ok() else {
        return Vec::new();
    };
    re.find_iter(text)
        .map(|m| m.as_str().to_string())
        .take(16)
        .collect()
}

async fn request_with_context(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
    ctx: Option<&AuthContext>,
) -> Option<(u16, String)> {
    if let Some(s) = stealth {
        stealth_engine::apply_jitter(s);
    }
    let m = method.to_ascii_lowercase();
    let req_base = match m.as_str() {
        "post" => client.post(url),
        "put" => client.put(url),
        "patch" => client.patch(url),
        "delete" => client.delete(url),
        _ => client.get(url),
    };
    let req = apply_auth(apply_stealth_headers(req_base, stealth), ctx);
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Some((status, body))
}

/// Shadow / anonymous request with optional [`IdentityBundle`] and context index (0 = highest privilege).
async fn request_with_identity(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
    identity: Option<&Arc<IdentityBundle>>,
    context_idx: Option<usize>,
) -> Option<(u16, String)> {
    let ctx_owned: Option<AuthContext> = match (identity, context_idx) {
        (None, _) | (_, None) => None,
        (Some(b), Some(i)) => match b.as_ref() {
            IdentityBundle::Static(v) => v.get(i).cloned(),
            IdentityBundle::Live(m) => m.auth_context(i, client, stealth).await,
        },
    };
    let first = request_with_context(client, method, url, stealth, ctx_owned.as_ref()).await?;
    let (st, body) = first;
    if matches!(st, 401 | 403) {
        if let (Some(b), Some(i)) = (identity, context_idx) {
            if let IdentityBundle::Live(m) = b.as_ref() {
                if m.refresh_session(i, client, stealth).await {
                    let ctx2 = m.auth_context(i, client, stealth).await?;
                    return request_with_context(client, method, url, stealth, Some(&ctx2)).await;
                }
            }
        }
    }
    Some((st, body))
}

async fn extend_harvest_pool(
    body: &str,
    path_hint: &str,
    harvested: &Arc<Mutex<Vec<String>>>,
    llm_http: &Arc<reqwest::Client>,
    llm_sem: &Arc<Semaphore>,
    tenant_id: Option<i64>,
) {
    let mut add = regex_harvest_ids(body);
    add.extend(email_harvest_nonjson(body));
    add = dedupe_cap(add, 48);
    if !add.is_empty() {
        let mut g = harvested.lock().await;
        for x in add {
            if !g.contains(&x) {
                g.push(x);
            }
        }
        if g.len() > 128 {
            g.truncate(128);
        }
    }
    if tenant_id.is_none() || body.len() < 40 {
        return;
    }
    let _p = match llm_sem.acquire().await {
        Ok(p) => p,
        Err(_) => return,
    };
    let llm_ids = llm_harvest_resource_ids(llm_http.as_ref(), body, path_hint, tenant_id).await;
    drop(_p);
    if llm_ids.is_empty() {
        return;
    }
    let mut g = harvested.lock().await;
    for x in llm_ids {
        if !g.contains(&x) {
            g.push(x);
        }
    }
    if g.len() > 128 {
        g.truncate(128);
    }
}

fn id_candidates(harvested_snapshot: &[String]) -> Vec<String> {
    let mut v = vec!["1".to_string(), "2".to_string()];
    v.extend(harvested_snapshot.iter().cloned());
    dedupe_cap(v, 20)
}

fn finding_shadow_bola(
    path_label: &str,
    method: &str,
    url: &str,
    from_role: &str,
    to_role: &str,
    leaks: &[String],
    status: u16,
) -> Value {
    serde_json::json!({
        "type": "bola_idor",
        "subtype": "shadow_cross_auth",
        "path": path_label,
        "method": method,
        "url": url,
        "severity": "critical",
        "title": "BOLA/IDOR: lower-privilege context received same sensitive payload as higher-privilege baseline",
        "message": format!(
            "Authorization context '{}' received HTTP {} with sensitive field overlap vs baseline context '{}'. Overlapping values (redacted length): {:?}",
            to_role,
            status,
            from_role,
            leaks.iter().map(|s| s.len()).collect::<Vec<_>>()
        ),
        "from_context": from_role,
        "to_context": to_role,
        "response_status": status,
        "leak_value_lengths": leaks.iter().map(|s| s.len()).collect::<Vec<usize>>(),
    })
}

fn finding_horizontal_idor(
    path_label: &str,
    method: &str,
    url_a: &str,
    url_b: &str,
    leaks: &[String],
) -> Value {
    serde_json::json!({
        "type": "bola_idor",
        "subtype": "horizontal_idor",
        "path": path_label,
        "method": method,
        "severity": "high",
        "title": "Potential horizontal IDOR: distinct resource IDs return overlapping sensitive data",
        "url_a": url_a,
        "url_b": url_b,
        "leak_value_lengths": leaks.iter().map(|s| s.len()).collect::<Vec<usize>>(),
    })
}

fn finding_blind_oast(path_label: &str, token: &str) -> Value {
    serde_json::json!({
        "type": "bola_idor",
        "subtype": "blind_oast_callback",
        "path": path_label,
        "severity": "critical",
        "title": "Blind IDOR / SSRF: OAST interaction correlated for injected resource token",
        "oast_token": token,
        "message": "Server initiated callback to Weissman OAST listener using embedded probe token.",
    })
}

fn finding_reachable(
    path: &str,
    method: &str,
    status: u16,
    note: &str,
) -> Value {
    serde_json::json!({
        "type": "bola_idor",
        "path": path,
        "method": method,
        "status": status,
        "severity": "medium",
        "title": format!("Endpoint reachable: {}", path),
        "message": note,
    })
}

/// Parallel OAST correlation checks (capped; avoids serial stall on many tokens).
const OAST_VERIFY_CONCURRENCY: usize = 32;

async fn verify_oast_tokens(pool: &FuzzHttpPool, tokens: &[String]) -> Vec<(String, bool)> {
    stream::iter(tokens.iter().cloned())
        .map(|t| async move {
            let hit = fuzz_oob::verify_oob_token_seen(pool, t.trim()).await;
            (t, hit)
        })
        .buffer_unordered(OAST_VERIFY_CONCURRENCY)
        .collect()
        .await
}

/// Concurrent fallback path probes + optional shadow matrix.
async fn probe_fallback_bola_paths(
    client: Arc<reqwest::Client>,
    base: String,
    stealth: Option<stealth_engine::StealthConfig>,
    extra_paths: Vec<String>,
    identity: Option<Arc<IdentityBundle>>,
    harvested: Arc<Mutex<Vec<String>>>,
    llm_http: Arc<reqwest::Client>,
    llm_sem: Arc<Semaphore>,
    tenant_id: Option<i64>,
    sem: Arc<Semaphore>,
    oast_pending: Arc<Mutex<Vec<String>>>,
) -> Vec<Value> {
    let stealth_arc: Option<Arc<stealth_engine::StealthConfig>> = stealth.map(Arc::new);
    let mut path_set = HashSet::new();
    for p in FALLBACK_BOLA_PATHS {
        path_set.insert(p.to_string());
    }
    for p in extra_paths {
        let s = p.trim();
        if s.is_empty() {
            continue;
        }
        path_set.insert(if s.starts_with('/') {
            s.to_string()
        } else {
            format!("/{s}")
        });
    }
    let paths_to_probe: Vec<String> = path_set.into_iter().collect();

    let mut futs: FuturesUnordered<_> = FuturesUnordered::new();
    for path in paths_to_probe {
        let client = client.clone();
        let base = base.clone();
        let harvested = harvested.clone();
        let llm_http = llm_http.clone();
        let llm_sem = llm_sem.clone();
        let sem = sem.clone();
        let oast_pending = oast_pending.clone();
        let id_clone = identity.clone();
        let st_j = stealth_arc.clone();

        futs.push(async move {
            let _permit = sem.acquire().await.ok()?;
            let url = format!("{}{}", base.trim_end_matches('/'), path);
            let mut local_findings: Vec<Value> = Vec::new();

            if let Some(ref id_arc) = id_clone {
                if id_arc.as_ref().is_shadow_ready() {
                    let high_name = match id_arc.as_ref() {
                        IdentityBundle::Static(v) => v[0].role_name.clone(),
                        IdentityBundle::Live(m) => m
                            .auth_context(0, &client, st_j.as_deref())
                            .await
                            .map(|c| c.role_name)
                            .unwrap_or_else(|| "synthetic_high".to_string()),
                    };
                    if let Some((st_h, body_h)) = request_with_identity(
                        &client,
                        "GET",
                        &url,
                        st_j.as_deref(),
                        Some(id_arc),
                        Some(0),
                    )
                    .await
                    {
                        if (200..300).contains(&st_h) {
                            extend_harvest_pool(
                                &body_h,
                                &path,
                                &harvested,
                                &llm_http,
                                &llm_sem,
                                tenant_id,
                            )
                            .await;
                            let nctx = id_arc.as_ref().context_count();
                            for low_i in 1..nctx {
                                let low_name = match id_arc.as_ref() {
                                    IdentityBundle::Static(v) => v
                                        .get(low_i)
                                        .map(|c| c.role_name.clone())
                                        .unwrap_or_default(),
                                    IdentityBundle::Live(m) => m
                                        .auth_context(low_i, &client, st_j.as_deref())
                                        .await
                                        .map(|c| c.role_name)
                                        .unwrap_or_default(),
                                };
                                if let Some((st_l, body_l)) = request_with_identity(
                                    &client,
                                    "GET",
                                    &url,
                                    st_j.as_deref(),
                                    Some(id_arc),
                                    Some(low_i),
                                )
                                .await
                                {
                                    if (200..300).contains(&st_l) {
                                        if let Some(leaks) =
                                            sensitive_leak_overlap(&body_h, &body_l)
                                        {
                                            local_findings.push(finding_shadow_bola(
                                                &path,
                                                "GET",
                                                &url,
                                                &high_name,
                                                &low_name,
                                                &leaks,
                                                st_l,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if let Some((st, body)) =
                request_with_identity(&client, "GET", &url, st_j.as_deref(), None, None).await
            {
                if (200..300).contains(&st) {
                    extend_harvest_pool(
                        &body,
                        &path,
                        &harvested,
                        &llm_http,
                        &llm_sem,
                        tenant_id,
                    )
                    .await;
                    local_findings.push(finding_reachable(
                        &path,
                        "GET",
                        st,
                        "Fallback BOLA probe: 2xx without cross-auth contexts; verify authorization.",
                    ));
                }
            }

            if path.contains("Users") && path.ends_with("/1") {
                let prefix = path.trim_end_matches("/1").trim_end_matches('1');
                let url_b = format!("{}{}/2", base.trim_end_matches('/'), prefix);
                if let Some((s1, b1)) =
                    request_with_identity(&client, "GET", &url, st_j.as_deref(), None, None).await
                {
                    if let Some((s2, b2)) =
                        request_with_identity(&client, "GET", &url_b, st_j.as_deref(), None, None).await
                    {
                        if (200..300).contains(&s1) && (200..300).contains(&s2) {
                            if let Some(leaks) = sensitive_leak_overlap(&b1, &b2) {
                                local_findings.push(finding_horizontal_idor(
                                    &path,
                                    "GET",
                                    &url,
                                    &url_b,
                                    &leaks,
                                ));
                            }
                        }
                    }
                }
            }

            if fuzz_oob::oast_correlation_enabled() {
                let token = uuid::Uuid::new_v4().to_string();
                if let Some(embed) = fuzz_oob::oast_embed_url_for_token(&token) {
                    let enc = urlencoding::encode(&embed);
                    let probe_url = if url.contains('?') {
                        format!("{url}&weissman_oast_probe={enc}")
                    } else {
                        format!("{url}?weissman_oast_probe={enc}")
                    };
                    if request_with_identity(&client, "GET", &probe_url, st_j.as_deref(), None, None)
                        .await
                        .is_some()
                    {
                        oast_pending.lock().await.push(token);
                    }
                }
            }

            Some(local_findings)
        });
    }

    let mut findings = Vec::new();
    while let Some(batch) = futs.next().await {
        if let Some(mut fs) = batch {
            findings.append(&mut fs);
        }
    }

    let login_url = format!("{}/rest/user/login", base.trim_end_matches('/'));
    if let Some(s) = stealth_arc.as_deref() {
        stealth_engine::apply_jitter(s);
    }
    let post_req = apply_stealth_headers(
        client
            .post(&login_url)
            .json(&serde_json::json!({"email":"a@b.com","password":"x"})),
        stealth_arc.as_deref(),
    );
    if let Ok(r) = post_req.send().await {
        let s = r.status().as_u16();
        if matches!(s, 401 | 400 | 200) {
            findings.push(finding_reachable(
                "/rest/user/login",
                "POST",
                s,
                "Login endpoint reachable (Juice Shop style probe).",
            ));
        }
    }

    findings
}

/// OpenAPI-driven concurrent checks.
async fn openapi_bola_matrix(
    client: Arc<reqwest::Client>,
    base: String,
    spec: Value,
    stealth: Option<stealth_engine::StealthConfig>,
    identity: Option<Arc<IdentityBundle>>,
    harvested: Arc<Mutex<Vec<String>>>,
    llm_http: Arc<reqwest::Client>,
    llm_sem: Arc<Semaphore>,
    tenant_id: Option<i64>,
    sem: Arc<Semaphore>,
    oast_pending: Arc<Mutex<Vec<String>>>,
) -> Vec<Value> {
    let stealth_arc: Option<Arc<stealth_engine::StealthConfig>> = stealth.map(Arc::new);
    let empty_paths = serde_json::Map::new();
    let paths_obj = spec
        .get("paths")
        .and_then(|p| p.as_object())
        .unwrap_or(&empty_paths);

    let mut futs: FuturesUnordered<_> = FuturesUnordered::new();
    for (path_tpl, path_item) in paths_obj {
        let Some(path_item) = path_item.as_object() else {
            continue;
        };
        if !path_tpl.contains('{') {
            continue;
        }
        for method in ["get", "post"] {
            let Some(op) = path_item.get(method).and_then(|x| x.as_object()) else {
                continue;
            };
            let empty_params: Vec<Value> = vec![];
            let params = op
                .get("parameters")
                .and_then(|p| p.as_array())
                .unwrap_or(&empty_params);
            let param_names = path_param_names(params);
            if param_names.is_empty() {
                continue;
            }

            let path_tpl = path_tpl.to_string();
            let method = method.to_string();
            let client = client.clone();
            let base = base.clone();
            let harvested = harvested.clone();
            let llm_http = llm_http.clone();
            let llm_sem = llm_sem.clone();
            let sem = sem.clone();
            let id_clone = identity.clone();
            let oast_pending = oast_pending.clone();
            let st_j = stealth_arc.clone();

            futs.push(async move {
                let _permit = sem.acquire().await.ok()?;
                let snap = harvested.lock().await.clone();
                let ids = id_candidates(&snap);
                let mut local = Vec::new();
                let mut pair_bodies: Vec<(String, String, String)> = Vec::new();

                for id in ids {
                    let rel = substitute_path_params(&path_tpl, &param_names, &id);
                    let full = format!("{}{}", base.trim_end_matches('/'), rel);
                    if let Some(ref id_arc) = id_clone {
                        if id_arc.as_ref().is_shadow_ready() {
                            let hn = match id_arc.as_ref() {
                                IdentityBundle::Static(v) => v[0].role_name.clone(),
                                IdentityBundle::Live(m) => m
                                    .auth_context(0, &client, st_j.as_deref())
                                    .await
                                    .map(|c| c.role_name)
                                    .unwrap_or_else(|| "synthetic_high".to_string()),
                            };
                            if let Some((st_h, body_h)) = request_with_identity(
                                &client,
                                &method,
                                &full,
                                st_j.as_deref(),
                                Some(id_arc),
                                Some(0),
                            )
                            .await
                            {
                                if (200..300).contains(&st_h) {
                                    extend_harvest_pool(
                                        &body_h,
                                        &path_tpl,
                                        &harvested,
                                        &llm_http,
                                        &llm_sem,
                                        tenant_id,
                                    )
                                    .await;
                                    let nctx = id_arc.as_ref().context_count();
                                    for low_i in 1..nctx {
                                        let low_name = match id_arc.as_ref() {
                                            IdentityBundle::Static(v) => v
                                                .get(low_i)
                                                .map(|c| c.role_name.clone())
                                                .unwrap_or_default(),
                                            IdentityBundle::Live(m) => m
                                                .auth_context(low_i, &client, st_j.as_deref())
                                                .await
                                                .map(|c| c.role_name)
                                                .unwrap_or_default(),
                                        };
                                        if let Some((st_l, body_l)) = request_with_identity(
                                            &client,
                                            &method,
                                            &full,
                                            st_j.as_deref(),
                                            Some(id_arc),
                                            Some(low_i),
                                        )
                                        .await
                                        {
                                            if (200..300).contains(&st_l) {
                                                if let Some(leaks) =
                                                    sensitive_leak_overlap(&body_h, &body_l)
                                                {
                                                    local.push(finding_shadow_bola(
                                                        &path_tpl,
                                                        &method.to_uppercase(),
                                                        &full,
                                                        &hn,
                                                        &low_name,
                                                        &leaks,
                                                        st_l,
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            continue;
                        }
                    }
                    if let Some((st, body)) =
                        request_with_identity(&client, &method, &full, st_j.as_deref(), None, None)
                            .await
                    {
                        if (200..300).contains(&st) {
                            extend_harvest_pool(
                                &body,
                                &path_tpl,
                                &harvested,
                                &llm_http,
                                &llm_sem,
                                tenant_id,
                            )
                            .await;
                            pair_bodies.push((id.clone(), full, body));
                        }
                    }
                }

                for i in 0..pair_bodies.len() {
                    for j in (i + 1)..pair_bodies.len() {
                        let (id_a, url_a, b_a) = &pair_bodies[i];
                        let (id_b, url_b, b_b) = &pair_bodies[j];
                        if id_a == id_b {
                            continue;
                        }
                        if let Some(leaks) = sensitive_leak_overlap(b_a, b_b) {
                            local.push(finding_horizontal_idor(
                                &path_tpl,
                                &method.to_uppercase(),
                                url_a,
                                url_b,
                                &leaks,
                            ));
                        }
                    }
                }

                if fuzz_oob::oast_correlation_enabled() {
                    let token = uuid::Uuid::new_v4().to_string();
                    if let Some(embed) = fuzz_oob::oast_embed_url_for_token(&token) {
                        let rel = substitute_path_params(&path_tpl, &param_names, "1");
                        let full = format!("{}{}", base.trim_end_matches('/'), rel);
                        let enc = urlencoding::encode(&embed);
                        let probe_url = if full.contains('?') {
                            format!("{full}&weissman_oast_probe={enc}")
                        } else {
                            format!("{full}?weissman_oast_probe={enc}")
                        };
                        if request_with_identity(
                            &client,
                            &method,
                            &probe_url,
                            st_j.as_deref(),
                            None,
                            None,
                        )
                        .await
                        .is_some()
                        {
                            oast_pending.lock().await.push(token);
                        }
                    }
                }

                Some(local)
            });
        }
    }

    let mut findings = Vec::new();
    while let Some(item) = futs.next().await {
        if let Some(mut fs) = item {
            findings.append(&mut fs);
        }
    }
    findings
}

async fn run_bola_idor_result_with_paths_inner(
    target: &str,
    extra_paths: &[String],
    stealth: Option<stealth_engine::StealthConfig>,
    identity_contexts: Option<&[AuthContext]>,
    llm_tenant_id: Option<i64>,
) -> EngineResult {
    let base_raw = target.trim().trim_end_matches('/');
    if base_raw.is_empty() {
        return EngineResult::error("target required");
    }
    let base = if base_raw.starts_with("http") {
        base_raw.to_string()
    } else {
        format!("https://{}", base_raw)
    };

    let stealth_ref = stealth.as_ref();
    let client = Arc::new(make_client_async(stealth_ref).await);
    let llm_http = Arc::new(weissman_engines::openai_chat::llm_http_client(45));
    let harvested: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sem = Arc::new(Semaphore::new(bola_max_in_flight()));
    let llm_sem = Arc::new(Semaphore::new(llm_max_parallel()));

    let oast_pool = if fuzz_oob::oast_correlation_enabled() {
        FuzzHttpPool::from_env().await.ok().map(Arc::new)
    } else {
        None
    };
    let oast_pending: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let mut spec: Option<Value> = None;
    for path in SPEC_PATHS {
        if let Some(s) = stealth_ref {
            stealth_engine::apply_jitter(s);
        }
        let url = format!("{}{}", base, path);
        let req = apply_stealth_headers(client.get(&url), stealth_ref);
        if let Ok(r) = req.send().await {
            if r.status().is_success() {
                if let Ok(v) = r.json().await {
                    spec = Some(v);
                    break;
                }
            }
        }
    }

    let mut identity_bundle: Option<IdentityBundle> =
        if let Some(ctx) = identity_contexts {
            if ctx.len() >= 2 {
                Some(IdentityBundle::from_db_contexts(ctx.to_vec()))
            } else {
                None
            }
        } else {
            None
        };
    if identity_bundle.is_none() && crate::autonomous_identity::autonomous_identity_enabled() {
        identity_bundle = crate::autonomous_identity::try_provision_identity_matrix(
            client.as_ref(),
            &base,
            stealth_ref,
            spec.as_ref(),
        )
        .await
        .map(IdentityBundle::Live);
    }
    let identity_arc = identity_bundle.map(Arc::new);

    let extra_owned: Vec<String> = extra_paths.to_vec();

    let (mut findings, msg) = if spec.is_none() {
        let fb = probe_fallback_bola_paths(
            client.clone(),
            base.clone(),
            stealth,
            extra_owned,
            identity_arc.clone(),
            harvested.clone(),
            llm_http.clone(),
            llm_sem.clone(),
            llm_tenant_id,
            sem.clone(),
            oast_pending.clone(),
        )
        .await;
        let n_fb = fb.len();
        (
            fb,
            format!(
                "BOLA/IDOR: No OpenAPI/Swagger; concurrent fallback probes, {n_fb} signals",
            ),
        )
    } else {
        let Some(spec) = spec else {
            return EngineResult::error("OpenAPI spec unavailable");
        };
        let openapi_path_count = spec
            .get("paths")
            .and_then(|p| p.as_object())
            .map(|m| m.len())
            .unwrap_or(0);
        let matrix = openapi_bola_matrix(
            client,
            base,
            spec,
            stealth,
            identity_arc,
            harvested,
            llm_http,
            llm_sem,
            llm_tenant_id,
            sem,
            oast_pending.clone(),
        )
        .await;
        let n = matrix.len();
        (
            matrix,
            format!(
                "BOLA/IDOR: OpenAPI paths≈{openapi_path_count}, concurrent matrix, {n} signals"
            ),
        )
    };

    let all_oast_tokens: Vec<String> = oast_pending.lock().await.clone();

    if let Some(pool) = oast_pool.as_ref() {
        if !all_oast_tokens.is_empty() {
            let hits = verify_oast_tokens(pool, &all_oast_tokens).await;
            for (tok, hit) in hits {
                if hit {
                    findings.push(finding_blind_oast("fallback_query_oast", &tok));
                }
            }
        }
    }

    EngineResult::ok(findings, msg)
}

/// Multi-target, path-aware BOLA with optional shadow identity contexts and LLM ID harvest.
pub async fn run_bola_idor_result_multi(
    targets: &[String],
    paths: &[String],
    stealth: Option<&stealth_engine::StealthConfig>,
    identity_contexts: Option<&[AuthContext]>,
    llm_tenant_id: Option<i64>,
) -> EngineResult {
    if targets.is_empty() {
        return EngineResult::error("target required");
    }
    let paths_owned: Vec<String> = paths.to_vec();
    let mut all_findings = Vec::new();
    for t in targets.iter().cloned() {
        let r = run_bola_idor_result_with_paths_inner(
            &t,
            &paths_owned,
            stealth.cloned(),
            identity_contexts,
            llm_tenant_id,
        )
        .await;
        for f in r.findings {
            all_findings.push(f);
        }
    }
    let msg = format!(
        "BOLA/IDOR: {} targets, {} signals",
        targets.len(),
        all_findings.len()
    );
    EngineResult::ok(all_findings, msg)
}

pub async fn run_bola_idor_result(
    target: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> EngineResult {
    let targets = vec![target.to_string()];
    run_bola_idor_result_multi(&targets, &[], stealth, None, None).await
}

/// Single-target variant with explicit path list (CLI / worker).
pub async fn run_bola_idor_result_with_paths(
    target: &str,
    extra_paths: &[String],
    stealth: Option<&stealth_engine::StealthConfig>,
) -> EngineResult {
    run_bola_idor_result_with_paths_inner(target, extra_paths, stealth.cloned(), None, None).await
}

pub async fn run_bola_idor(target: &str) {
    print_result(run_bola_idor_result(target, None).await);
}
