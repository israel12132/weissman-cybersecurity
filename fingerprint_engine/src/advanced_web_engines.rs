//! Advanced Web Engines — real HTTP/HTTPS probes against the target. No simulated findings.
//!
//! Each engine performs a focused live probe and only emits a finding when an observable
//! security-relevant signal is detected (header anomaly, response pattern, exposed endpoint).
//! On no signal: returns ok with empty findings.

use crate::engine_probes::{
    empty_ok, extract_host, finding, has_header, header_value, http_get, http_client,
    normalize_url, HttpProbe,
};
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
    for path in ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/api/v1/graphql"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let intro = serde_json::json!({"query":"{__schema{types{name fields{name}}}}"});
        if let Some(p) = crate::engine_probes::http_post_json(&client, &url, &intro).await {
            if p.status < 500 && p.body.contains("__schema") && p.body.contains("types") {
                findings.push(finding(
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
    }
    if findings.is_empty() {
        empty_ok("graphql_deep_attack", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("graphql_deep_attack: {} live finding(s)", n))
    }
}
cli_wrapper!(run_graphql_deep_attack, run_graphql_deep_attack_result);

// ── grpc_reflection_attack ────────────────────────────────────────────────────
pub async fn run_grpc_reflection_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let mut findings: Vec<Value> = Vec::new();
    for port in [50051u16, 9090, 8443, 443, 80] {
        if crate::engine_probes::tcp_open(&host, port).await {
            // gRPC reflection lives over h2; observable hint is open port + later TLS-alpn h2.
            findings.push(finding(
                "grpc_reflection_attack",
                &format!("gRPC-style port open on {}:{}", host, port),
                "medium",
                "T1190",
                &format!(
                    "TCP {}:{} accepts connections. If the service implements grpc.reflection.v1alpha.ServerReflection, the schema is enumerable.",
                    host, port
                ),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("grpc_reflection_attack", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("grpc_reflection_attack: {} port(s)", n))
    }
}
cli_wrapper!(run_grpc_reflection_attack, run_grpc_reflection_attack_result);

// ── cors_misconfiguration ─────────────────────────────────────────────────────
pub async fn run_cors_misconfiguration_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        if let Some(origin) = header_value(&p.headers, "access-control-allow-origin") {
            let creds = has_header(&p.headers, "access-control-allow-credentials");
            if origin.trim() == "*" {
                findings.push(finding(
                    "cors_misconfiguration",
                    "CORS Allow-Origin: * observed",
                    "medium",
                    "T1185",
                    &format!("Wildcard origin on {} (credentials={})", p.final_url, creds),
                    target,
                ));
            } else if origin.contains("null") && creds {
                findings.push(finding(
                    "cors_misconfiguration",
                    "CORS Allow-Origin: null with credentials",
                    "high",
                    "T1185",
                    &format!("Origin=null with credentials=true on {} — exploitable from sandboxed iframe", p.final_url),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("cors_misconfiguration", target)
    } else {
        EngineResult::ok(findings.clone(), format!("cors_misconfiguration: {} finding(s)", findings.len()))
    }
}
cli_wrapper!(run_cors_misconfiguration, run_cors_misconfiguration_result);

// ── http2_attack ──────────────────────────────────────────────────────────────
pub async fn run_http2_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let via = header_value(&p.headers, "alt-svc").unwrap_or("");
        if via.contains("h3") {
            findings.push(finding(
                "http2_attack",
                "HTTP/3 advertised via Alt-Svc",
                "info",
                "T1190",
                &format!("Alt-Svc on {} = '{}'. HTTP/3 surface present.", p.final_url, via),
                target,
            ));
        }
        if via.contains("h2") || via.contains("h2c") {
            findings.push(finding(
                "http2_attack",
                "HTTP/2 advertised via Alt-Svc",
                "info",
                "T1190",
                &format!("Alt-Svc on {} = '{}'. H2 surface present (test for h2c smuggling).", p.final_url, via),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("http2_attack", target)
    } else {
        EngineResult::ok(findings.clone(), format!("http2_attack: {} finding(s)", findings.len()))
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
    ];
    let mut findings: Vec<Value> = Vec::new();
    for path in paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            let body_low = p.body.to_ascii_lowercase();
            if p.status == 200
                && (body_low.contains("swagger")
                    || body_low.contains("openapi")
                    || body_low.contains("\"paths\""))
            {
                findings.push(finding(
                    "swagger_abuse",
                    "Exposed Swagger/OpenAPI spec",
                    "medium",
                    "T1190",
                    &format!(
                        "Public OpenAPI document at {} (HTTP {}) — leaks routes, params, auth schemes.",
                        p.final_url, p.status
                    ),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("swagger_abuse", target)
    } else {
        EngineResult::ok(findings.clone(), format!("swagger_abuse: {} doc(s)", findings.len()))
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
    ];
    let mut findings: Vec<Value> = Vec::new();
    for path in paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200
                && (p.body.contains("<wsdl:") || p.body.contains("<definitions"))
            {
                findings.push(finding(
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
            }
        }
    }
    if findings.is_empty() {
        empty_ok("soap_injection", target)
    } else {
        EngineResult::ok(findings.clone(), format!("soap_injection: {} WSDL(s)", findings.len()))
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
    for path in ["/odata/$metadata", "/api/odata/$metadata", "/odata/v4/$metadata"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 && (p.body.contains("<edmx:") || p.body.contains("EntityType")) {
                findings.push(finding(
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
    if findings.is_empty() {
        empty_ok("odata_injection", target)
    } else {
        EngineResult::ok(findings.clone(), format!("odata_injection: {}", findings.len()))
    }
}
cli_wrapper!(run_odata_injection, run_odata_injection_result);

// ── css_injection ─────────────────────────────────────────────────────────────
pub async fn run_css_injection_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let csp = header_value(&p.headers, "content-security-policy").unwrap_or("");
        if !csp.contains("style-src") || csp.contains("style-src 'unsafe-inline'") {
            findings.push(finding(
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
    }
    if findings.is_empty() {
        empty_ok("css_injection", target)
    } else {
        EngineResult::ok(findings.clone(), format!("css_injection: {}", findings.len()))
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
    let probe = format!("{}/?q={}", base.trim_end_matches('/'), "%7B%7B7*7%7D%7D");
    if let Some(p) = http_get(&client, &probe).await {
        if p.body.contains("49") && !p.body.contains("{{7*7}}") {
            findings.push(finding(
                "template_injection_adv",
                "Possible server-side template evaluation (7*7=49)",
                "high",
                "T1059",
                &format!(
                    "Response to {{7*7}} payload on {} contains '49' — engine likely evaluated the expression server-side.",
                    p.final_url
                ),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("template_injection_adv", target)
    } else {
        EngineResult::ok(findings.clone(), format!("template_injection_adv: {}", findings.len()))
    }
}
cli_wrapper!(run_template_injection_adv, run_template_injection_adv_result);

// ── http_parameter_pollution ──────────────────────────────────────────────────
pub async fn run_http_parameter_pollution_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let single = format!("{}/?a=1", base.trim_end_matches('/'));
    let polluted = format!("{}/?a=1&a=2&a=3", base.trim_end_matches('/'));
    let mut findings: Vec<Value> = Vec::new();
    if let (Some(p1), Some(p2)) = (http_get(&client, &single).await, http_get(&client, &polluted).await) {
        if p1.status != p2.status
            || (p1.body.len() as i64 - p2.body.len() as i64).abs() > 64
        {
            findings.push(finding(
                "http_parameter_pollution",
                "Differential response to duplicated query params",
                "medium",
                "T1190",
                &format!(
                    "?a=1 → HTTP {} ({} B); ?a=1&a=2&a=3 → HTTP {} ({} B). Backend may concatenate or pick-last/first inconsistently.",
                    p1.status, p1.body.len(), p2.status, p2.body.len()
                ),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("http_parameter_pollution", target)
    } else {
        EngineResult::ok(findings.clone(), format!("http_parameter_pollution: {}", findings.len()))
    }
}
cli_wrapper!(run_http_parameter_pollution, run_http_parameter_pollution_result);

// ── api_mass_assignment ───────────────────────────────────────────────────────
pub async fn run_api_mass_assignment_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    for path in ["/api/users", "/api/v1/users", "/api/account", "/users", "/account"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let payload = serde_json::json!({"is_admin": true, "role": "admin"});
        if let Some(p) = crate::engine_probes::http_post_json(&client, &url, &payload).await {
            if p.status < 500 && (p.body.contains("admin") || p.body.contains("role")) {
                findings.push(finding(
                    "api_mass_assignment",
                    "Endpoint echoes privileged fields in response",
                    "medium",
                    "T1548",
                    &format!(
                        "POST {} returned HTTP {} and response references 'admin'/'role' — verify privilege escalation via mass assignment.",
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
        EngineResult::ok(findings.clone(), format!("api_mass_assignment: {}", findings.len()))
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
    if let Some(p) = http_get(&client, &url).await {
        let cache_status = header_value(&p.headers, "x-cache").unwrap_or("");
        let cdn = header_value(&p.headers, "via").unwrap_or("");
        let vary = header_value(&p.headers, "vary").unwrap_or("");
        if (cache_status.contains("HIT") || cdn.contains("cloudfront") || cdn.contains("varnish"))
            && !vary.to_ascii_lowercase().contains("cookie")
            && !vary.to_ascii_lowercase().contains("authorization")
        {
            findings.push(finding(
                "web_cache_poison_adv",
                "CDN cache without per-user Vary",
                "medium",
                "T1185",
                &format!(
                    "x-cache='{}', via='{}', vary='{}' on {} — unkeyed input or unsafe headers may poison shared cache entries.",
                    cache_status, cdn, vary, p.final_url
                ),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("web_cache_poison_adv", target)
    } else {
        EngineResult::ok(findings.clone(), format!("web_cache_poison_adv: {}", findings.len()))
    }
}
cli_wrapper!(run_web_cache_poison_adv, run_web_cache_poison_adv_result);

// ── clickjacking_engine ───────────────────────────────────────────────────────
pub async fn run_clickjacking_engine_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let xfo = header_value(&p.headers, "x-frame-options").unwrap_or("");
        let csp = header_value(&p.headers, "content-security-policy").unwrap_or("");
        let csp_frame = csp.contains("frame-ancestors");
        if xfo.is_empty() && !csp_frame {
            findings.push(finding(
                "clickjacking_engine",
                "No X-Frame-Options or frame-ancestors CSP",
                "medium",
                "T1185",
                &format!("{} can be iframed (no XFO, no frame-ancestors).", p.final_url),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("clickjacking_engine", target)
    } else {
        EngineResult::ok(findings.clone(), format!("clickjacking_engine: {}", findings.len()))
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
        EngineResult::ok(findings.clone(), format!("subdomain_takeover: {}", findings.len()))
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
        ("/etc/passwd",                                  "root:x:0:0"),
        ("../../../../etc/passwd",                       "root:x:0:0"),
        ("..%2f..%2f..%2fetc%2fpasswd",                  "root:x:0:0"),
        ("..%252f..%252f..%252fetc%252fpasswd",          "root:x:0:0"),
        ("C:%5CWindows%5Cwin.ini",                       "[fonts]"),
        ("file:///etc/passwd",                           "root:x:0:0"),
    ];
    let params = ["file", "page", "path", "include", "doc", "f", "template"];

    for q in params {
        for (payload, canary) in payloads {
            let url = format!(
                "{}/?{}={}",
                base.trim_end_matches('/'),
                q,
                payload
            );
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
        EngineResult::ok(findings.clone(), format!("file_inclusion_rfi: {}", findings.len()))
    }
}
cli_wrapper!(run_file_inclusion_rfi, run_file_inclusion_rfi_result);

// ── deserialization_net ───────────────────────────────────────────────────────
pub async fn run_deserialization_net_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let server = header_value(&p.headers, "server").unwrap_or("");
        let powered = header_value(&p.headers, "x-powered-by").unwrap_or("");
        if server.to_ascii_lowercase().contains("iis") || powered.to_ascii_lowercase().contains("asp.net") {
            findings.push(finding(
                "deserialization_net",
                ".NET / IIS surface detected",
                "info",
                "T1059",
                &format!("Server='{}' / X-Powered-By='{}' on {} — review ViewState MAC and BinaryFormatter usage.", server, powered, p.final_url),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("deserialization_net", target)
    } else {
        EngineResult::ok(findings.clone(), format!("deserialization_net: {}", findings.len()))
    }
}
cli_wrapper!(run_deserialization_net, run_deserialization_net_result);

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
        let payload = serde_json::json!({"username": {"$ne": null}, "password": {"$ne": null}});
        if let Some(p) = crate::engine_probes::http_post_json(&client, &url, &payload).await {
            if p.status == 200 && (p.body.contains("token") || p.body.contains("success")) {
                findings.push(finding(
                    "nosql_deep_injection",
                    "NoSQL-style operator accepted by login endpoint",
                    "high",
                    "T1190",
                    &format!("POST {} with {{$ne}} returned HTTP {} — bypass candidate.", p.final_url, p.status),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("nosql_deep_injection", target)
    } else {
        EngineResult::ok(findings.clone(), format!("nosql_deep_injection: {}", findings.len()))
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
    let mut sent = 0;
    let mut limited = 0;
    for _ in 0..20 {
        if let Some(p) = http_get(&client, &url).await {
            sent += 1;
            if p.status == 429 {
                limited += 1;
            }
        }
    }
    if sent > 0 && limited == 0 {
        findings.push(finding(
            "api_rate_limit_bypass",
            "No 429 observed across 20 rapid requests",
            "low",
            "T1499.003",
            &format!("Sent {} requests to {} without observing HTTP 429 — verify per-IP/per-user limits.", sent, url),
            target,
        ));
    }
    if findings.is_empty() {
        empty_ok("api_rate_limit_bypass", target)
    } else {
        EngineResult::ok(findings.clone(), format!("api_rate_limit_bypass: {}", findings.len()))
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
    let host = extract_host(target);
    let mut findings: Vec<Value> = Vec::new();
    for port in [8080u16, 4000, 8000, 3000] {
        if crate::engine_probes::tcp_open(&host, port).await {
            findings.push(finding(
                "graphql_subscription_attack",
                &format!("Potential WS/GraphQL port open {}:{}", host, port),
                "info",
                "T1190",
                &format!("TCP open on {}:{}. Validate /subscriptions endpoint with WS upgrade.", host, port),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("graphql_subscription_attack", target)
    } else {
        EngineResult::ok(findings.clone(), format!("graphql_subscription_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_graphql_subscription_attack, run_graphql_subscription_attack_result);

// ── webrtc_attack ─────────────────────────────────────────────────────────────
pub async fn run_webrtc_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        if p.body.contains("RTCPeerConnection") || p.body.contains("getUserMedia") {
            let perms = header_value(&p.headers, "permissions-policy").unwrap_or("");
            if !perms.contains("camera") && !perms.contains("microphone") {
                findings.push(finding(
                    "webrtc_attack",
                    "WebRTC code without Permissions-Policy hardening",
                    "low",
                    "T1185",
                    &format!("{} uses WebRTC APIs but Permissions-Policy is missing for camera/microphone.", p.final_url),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("webrtc_attack", target)
    } else {
        EngineResult::ok(findings.clone(), format!("webrtc_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_webrtc_attack, run_webrtc_attack_result);

// ── web3_dapp_attack ──────────────────────────────────────────────────────────
pub async fn run_web3_dapp_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        if p.body.contains("window.ethereum") || p.body.contains("web3.eth") {
            findings.push(finding(
                "web3_dapp_attack",
                "Web3/dApp surface detected in DOM",
                "info",
                "T1190",
                &format!("{} references window.ethereum / web3.eth — review wallet/transaction flows for replay and phishing.", p.final_url),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("web3_dapp_attack", target)
    } else {
        EngineResult::ok(findings.clone(), format!("web3_dapp_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_web3_dapp_attack, run_web3_dapp_attack_result);

// ── api_gateway_bypass ────────────────────────────────────────────────────────
pub async fn run_api_gateway_bypass_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let server = header_value(&p.headers, "server").unwrap_or("");
        let vendor = header_value(&p.headers, "x-amz-apigw-id").or_else(|| header_value(&p.headers, "x-azure-ref"));
        if server.to_ascii_lowercase().contains("kong")
            || server.to_ascii_lowercase().contains("apigee")
            || vendor.is_some()
        {
            findings.push(finding(
                "api_gateway_bypass",
                "API Gateway detected",
                "info",
                "T1190",
                &format!("Server='{}' / gateway-marker={:?} on {} — verify direct backend access bypassing gateway WAF rules.", server, vendor, p.final_url),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("api_gateway_bypass", target)
    } else {
        EngineResult::ok(findings.clone(), format!("api_gateway_bypass: {}", findings.len()))
    }
}
cli_wrapper!(run_api_gateway_bypass, run_api_gateway_bypass_result);

// ── browser_extension_attack ──────────────────────────────────────────────────
pub async fn run_browser_extension_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let csp = header_value(&p.headers, "content-security-policy").unwrap_or("");
        if !csp.contains("script-src") {
            findings.push(finding(
                "browser_extension_attack",
                "Missing script-src CSP",
                "low",
                "T1185",
                &format!("{} lacks a script-src CSP — extension content scripts can inject without restriction.", p.final_url),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("browser_extension_attack", target)
    } else {
        EngineResult::ok(findings.clone(), format!("browser_extension_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_browser_extension_attack, run_browser_extension_attack_result);

#[inline]
fn _shut_up_unused(p: &HttpProbe) -> bool {
    !p.headers.is_empty()
}
