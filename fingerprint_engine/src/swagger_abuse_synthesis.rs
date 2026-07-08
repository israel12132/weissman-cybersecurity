//! Swagger / OpenAPI abuse synthesis — full discovery catalog + deep spec abuse.
//!
//! Hunts exposed specs/UI, parses operations + servers live, probes documented endpoints
//! (including auth-bypass and write verbs), and synthesizes zero-day paths from intel bus.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    http_get, http_get_with_headers, http_method_with_headers, http_post_json, normalize_url,
    HttpProbe,
};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde_json::json;
use std::collections::HashSet;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const PROBE_CONCURRENCY: usize = 24;
pub const MAX_VECTORS_PER_BASE: usize = 280;
const MAX_FOLLOWUP_PATHS: usize = 16;
const MAX_OPERATION_PROBES: usize = 14;
const MAX_SERVER_PROBES: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwaggerProbeTransport {
    Get,
    Head,
    Options,
    Post,
}

#[derive(Clone, Debug)]
pub struct SwaggerProbeVector {
    pub category: &'static str,
    pub transport: SwaggerProbeTransport,
    pub path: String,
    pub accept: Option<String>,
    pub extra_headers: Vec<(String, String)>,
    pub synthetic: bool,
    pub canary: String,
}

#[derive(Default, Debug)]
pub struct SwaggerSynthesisStats {
    pub vectors_generated: usize,
    pub synthetic_generated: usize,
}

#[derive(Clone, Debug, Default)]
pub struct OpenApiSignal {
    pub is_spec: bool,
    pub is_ui: bool,
    pub is_yaml: bool,
    pub is_postman: bool,
    pub has_auth_schemes: bool,
    pub has_oauth: bool,
    pub has_bearer: bool,
    pub has_api_key: bool,
    pub has_write_ops: bool,
    pub sensitive_hints: bool,
    pub pii_hints: bool,
    pub path_estimate: usize,
    pub operation_count: usize,
    pub write_op_count: usize,
    pub version: Option<String>,
}

#[derive(Clone, Debug)]
pub struct OpenApiOperation {
    pub path: String,
    pub method: &'static str,
    pub requires_auth_hint: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SpecExtraction {
    pub paths: Vec<String>,
    pub operations: Vec<OpenApiOperation>,
    pub servers: Vec<String>,
    pub ui_spec_urls: Vec<String>,
    pub spring_groups: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SwaggerProbeHit {
    pub vector: SwaggerProbeVector,
    pub status: u16,
    pub body_len: usize,
    pub signal: OpenApiSignal,
    pub final_url: String,
    pub extraction: SpecExtraction,
}

#[derive(Clone, Debug)]
pub struct OperationProbeHit {
    pub operation: OpenApiOperation,
    pub status: u16,
    pub body_len: usize,
    pub final_url: String,
    pub without_auth: bool,
}

fn synthesis_nonce() -> String {
    let nano = Instant::now().elapsed().as_nanos();
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("wsw{unix:x}{nano:x}")
}

fn push_vector(
    out: &mut Vec<SwaggerProbeVector>,
    category: &'static str,
    transport: SwaggerProbeTransport,
    path: &str,
    accept: Option<&str>,
    headers: Vec<(String, String)>,
    canary: &str,
    synthetic: bool,
) {
    out.push(SwaggerProbeVector {
        category,
        transport,
        path: path.to_string(),
        accept: accept.map(str::to_string),
        extra_headers: headers,
        synthetic,
        canary: canary.to_string(),
    });
}

fn static_spec_paths() -> Vec<(&'static str, &'static str)> {
    vec![
        ("/swagger.json", "swagger_json_root"),
        ("/swagger/v1/swagger.json", "swagger_v1"),
        ("/swagger/v2/swagger.json", "swagger_v2"),
        ("/swagger/v3/swagger.json", "swagger_v3"),
        ("/v2/api-docs", "spring_v2"),
        ("/v3/api-docs", "spring_v3"),
        ("/v3/api-docs/swagger-config", "spring_swagger_config"),
        ("/v3/api-docs.yaml", "spring_v3_yaml"),
        ("/v3/api-docs/swagger.yaml", "spring_v3_swagger_yaml"),
        ("/v3/api-docs/default", "spring_group_default"),
        ("/v3/api-docs/admin", "spring_group_admin"),
        ("/v3/api-docs/public", "spring_group_public"),
        ("/v3/api-docs/internal", "spring_group_internal"),
        ("/v3/api-docs/management", "spring_group_management"),
        ("/openapi.json", "openapi_root"),
        ("/openapi.yaml", "openapi_yaml"),
        ("/openapi.yml", "openapi_yml"),
        ("/api-docs", "api_docs_root"),
        ("/api-docs/swagger.json", "api_docs_swagger"),
        ("/api-docs/openapi.json", "api_docs_openapi"),
        ("/swagger-ui.html", "swagger_ui_html"),
        ("/swagger-ui/index.html", "swagger_ui_index"),
        ("/swagger-ui/", "swagger_ui_dir"),
        ("/swagger/index.html", "swagger_index"),
        ("/api/swagger.json", "api_swagger"),
        ("/api/openapi.json", "api_openapi"),
        ("/api/openapi.yaml", "api_openapi_yaml"),
        ("/api/v1/swagger.json", "api_v1_swagger"),
        ("/api/v1/openapi.json", "api_v1_openapi"),
        ("/api/v2/swagger.json", "api_v2_swagger"),
        ("/api/v2/openapi.json", "api_v2_openapi"),
        ("/api/v3/swagger.json", "api_v3_swagger"),
        ("/api/v3/openapi.json", "api_v3_openapi"),
        ("/docs", "docs_root"),
        ("/docs/openapi.json", "docs_openapi"),
        ("/docs/swagger.json", "docs_swagger"),
        ("/redoc", "redoc_ui"),
        ("/api/swagger-ui/", "api_swagger_ui"),
        ("/api/swagger-ui.html", "api_swagger_ui_html"),
        ("/webjars/swagger-ui/index.html", "webjars_swagger"),
        ("/swagger-resources", "swagger_resources"),
        ("/swagger-resources/configuration/ui", "swagger_resources_ui"),
        ("/swagger-resources/configuration/security", "swagger_resources_sec"),
        ("/configuration/ui", "config_ui"),
        ("/configuration/security", "config_security"),
        ("/api/swagger-resources", "api_swagger_resources"),
        ("/actuator/openapi", "actuator_openapi"),
        ("/management/openapi", "management_openapi"),
        ("/.well-known/openapi", "wellknown_openapi"),
        ("/openapi", "openapi_short"),
        ("/openapi/v1", "openapi_v1"),
        ("/openapi/v2", "openapi_v2"),
        ("/openapi/v3", "openapi_v3"),
        ("/public/openapi.json", "public_openapi"),
        ("/internal/openapi.json", "internal_openapi"),
        ("/dev/openapi.json", "dev_openapi"),
        ("/staging/openapi.json", "staging_openapi"),
        ("/api/docs", "api_docs"),
        ("/api/documentation", "api_documentation"),
        ("/api/reference", "api_reference"),
        ("/api/schema", "api_schema"),
        ("/api/spec", "api_spec"),
        ("/api/specs/openapi.json", "api_specs"),
        ("/graphql/openapi.json", "graphql_openapi"),
        ("/gateway/swagger.json", "gateway_swagger"),
        ("/gateway/openapi.json", "gateway_openapi"),
        ("/swagger-ui/swagger-ui-bundle.js", "swagger_bundle_js"),
        ("/swagger-ui/swagger-ui-standalone-preset.js", "swagger_preset_js"),
        ("/api-json", "fastapi_json"),
        ("/api-yaml", "fastapi_yaml"),
        ("/swagger/doc.json", "swagger_doc_json"),
        ("/api/swagger/doc.json", "api_swagger_doc"),
        ("/rest/openapi.json", "rest_openapi"),
        ("/services/swagger.json", "services_swagger"),
        ("/admin/swagger.json", "admin_swagger"),
        ("/internal/swagger.json", "internal_swagger"),
        ("/debug/openapi.json", "debug_openapi"),
        ("/metadata/openapi.json", "metadata_openapi"),
        ("/catalog/openapi.json", "catalog_openapi"),
        ("/platform/openapi.json", "platform_openapi"),
        ("/console/openapi.json", "console_openapi"),
        ("/doc.html", "knife4j_ui"),
        ("/swagger-ui.html/v2/api-docs", "knife4j_docs"),
        ("/v2/api-docs?group=default", "spring_group_query"),
        ("/v3/api-docs?group=admin", "spring_v3_group_query"),
        ("/scalar", "scalar_ui"),
        ("/api/scalar", "scalar_api"),
        ("/elements", "stoplight_elements"),
        ("/api/elements", "stoplight_api"),
        ("/postman_collection.json", "postman_export"),
        ("/api/postman_collection.json", "postman_api"),
        ("/collections/api.json", "postman_collections"),
        ("/wadl", "wadl_descriptor"),
        ("/api/wadl", "wadl_api"),
        ("/application.wadl", "wadl_app"),
        ("/api/application.wadl", "wadl_api_app"),
        ("/api.raml", "raml_spec"),
        ("/api/api.raml", "raml_api"),
        ("/api-blueprint.txt", "api_blueprint"),
        ("/swagger/v1/swagger.yaml", "swagger_yaml_v1"),
        ("/export/openapi.json", "export_openapi"),
        ("/download/openapi.json", "download_openapi"),
        ("/static/openapi.json", "static_openapi"),
        ("/assets/openapi.json", "assets_openapi"),
        ("/spec/openapi.json", "spec_dir"),
        ("/specs/v1/openapi.json", "specs_v1"),
        ("/aws/swagger.json", "aws_gateway"),
        ("/kong/openapi.json", "kong_openapi"),
        ("/apispec.json", "apispec_json"),
        ("/api/apispec.json", "api_apispec"),
        ("/..%2fopenapi.json", "path_traversal_spec"),
        ("/%2e%2e/openapi.json", "encoding_traversal_spec"),
    ]
}

fn spring_group_names() -> [&'static str; 12] {
    [
        "default", "admin", "public", "internal", "management", "private", "external", "v1", "v2",
        "main", "core", "api",
    ]
}

fn accept_variants() -> Vec<(&'static str, &'static str)> {
    vec![
        ("application/json", "accept_json"),
        ("application/yaml", "accept_yaml"),
        ("application/vnd.oai.openapi+json", "accept_oai_json"),
        ("application/vnd.postman.collection+json", "accept_postman"),
        ("text/yaml", "accept_text_yaml"),
        ("text/plain", "accept_text_plain"),
        ("*/*", "accept_any"),
    ]
}

fn static_catalog(canary: &str) -> Vec<SwaggerProbeVector> {
    let mut out = Vec::new();
    for (path, cat) in static_spec_paths() {
        push_vector(
            &mut out,
            cat,
            SwaggerProbeTransport::Get,
            path,
            None,
            Vec::new(),
            canary,
            false,
        );
        if path.ends_with(".json") || path.contains("api-docs") || path.contains("openapi") {
            push_vector(
                &mut out,
                "content_negotiation",
                SwaggerProbeTransport::Get,
                path,
                Some("application/yaml"),
                Vec::new(),
                canary,
                false,
            );
            push_vector(
                &mut out,
                "post_fetch",
                SwaggerProbeTransport::Post,
                path,
                Some("application/json"),
                vec![("Content-Type".into(), "application/json".into())],
                canary,
                false,
            );
        }
    }

    for group in spring_group_names() {
        let path = format!("/v3/api-docs/{group}");
        push_vector(
            &mut out,
            "spring_doc_group",
            SwaggerProbeTransport::Get,
            &path,
            None,
            Vec::new(),
            canary,
            false,
        );
    }

    for (path, _) in static_spec_paths().iter().take(16) {
        push_vector(
            &mut out,
            "head_transport",
            SwaggerProbeTransport::Head,
            path,
            None,
            Vec::new(),
            canary,
            false,
        );
        push_vector(
            &mut out,
            "options_transport",
            SwaggerProbeTransport::Options,
            path,
            None,
            Vec::new(),
            canary,
            false,
        );
    }

    for (accept, cat) in accept_variants() {
        for path in ["/openapi.json", "/v3/api-docs", "/swagger.json"] {
            push_vector(
                &mut out,
                cat,
                SwaggerProbeTransport::Get,
                path,
                Some(accept),
                vec![("X-Weissman-Swagger-Canary".into(), canary.to_string())],
                canary,
                false,
            );
        }
    }

    out
}

fn synthetic_paths(host: &str, nonce: &str, ctx: &EngineRunContext) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    let slug = host.replace('.', "_");
    let labels: [&str; 6] = ["admin", "internal", "private", "mgmt", "public", "core"];
    for label in labels {
        out.push((
            format!("/v3/api-docs/{label}"),
            "synthetic_spring_group",
        ));
        out.push((
            format!("/api/{label}/openapi.json"),
            "synthetic_spring_group",
        ));
    }
    out.push((format!("/api/{slug}/openapi.json"), "synthetic_host_slug"));
    out.push((format!("/{slug}/v1/openapi.json"), "synthetic_host_slug"));
    out.push((format!("/weissman-{nonce}/openapi.json"), "synthetic_nonce_path"));

    for p in ctx.discovered_paths.iter().take(24) {
        let base = p.trim_end_matches('/');
        if base.is_empty() {
            continue;
        }
        for suffix in [
            "/openapi.json",
            "/swagger.json",
            "/v3/api-docs",
            "/api-docs",
            "/swagger-ui/index.html",
        ] {
            out.push((format!("{base}{suffix}"), "synthetic_intel_path"));
        }
        if let Some(parent) = base.rsplit_once('/') {
            out.push((
                format!("{}/openapi.json", parent.0),
                "synthetic_intel_parent",
            ));
        }
        for label in labels {
            out.push((
                format!("{base}/v3/api-docs/{label}"),
                "synthetic_intel_group",
            ));
        }
    }

    if let Some(bus) = ctx.intelligence_bus.as_ref() {
        for art in bus.snapshot().iter().take(16) {
            if let Ok(u) = url::Url::parse(&art.source_url) {
                let mut path = u.path().trim_end_matches('/').to_string();
                if path.is_empty() {
                    path = "/api".into();
                }
                for suffix in ["/openapi.json", "/swagger.json", "/v3/api-docs"] {
                    out.push((
                        format!("{path}{suffix}"),
                        "synthetic_bus_artifact",
                    ));
                }
                if art.proof.contains("graphql") {
                    out.push((
                        format!("{path}/graphql/openapi.json"),
                        "synthetic_bus_graphql",
                    ));
                }
                if art.proof.contains("gateway") || art.kind.contains("gateway") {
                    out.push((
                        format!("{path}/gateway/openapi.json"),
                        "synthetic_bus_gateway",
                    ));
                }
                if art.proof.contains("grpc") {
                    out.push((
                        format!("{path}/grpc/openapi.json"),
                        "synthetic_bus_grpc",
                    ));
                }
            }
        }
    }

    for payload in ctx.memory_payloads.iter().take(6) {
        let safe: String = payload
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .take(32)
            .collect();
        if !safe.is_empty() {
            out.push((
                format!("/api/{safe}/openapi.json"),
                "synthetic_memory_payload",
            ));
            out.push((
                format!("/v3/api-docs/{safe}"),
                "synthetic_memory_payload",
            ));
        }
    }

    out.sort();
    out.dedup();
    out
}

fn auth_header_pairs(params: &serde_json::Value) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    if let Some(token) = params
        .get("bearer_token")
        .or_else(|| params.get("options").and_then(|o| o.get("bearer_token")))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        pairs.push((
            "Authorization".into(),
            if token.starts_with("Bearer ") {
                token.to_string()
            } else {
                format!("Bearer {token}")
            },
        ));
    }
    crate::ws_intelligence_bus::apply_intelligence_artifacts_to_headers(params, &mut pairs);
    pairs
}

fn synthetic_vectors(
    host: &str,
    ctx: &EngineRunContext,
    nonce: &str,
    canary: &str,
) -> Vec<SwaggerProbeVector> {
    let mut out = Vec::new();
    let auth = auth_header_pairs(&ctx.job_params);

    for (path, cat) in synthetic_paths(host, nonce, ctx) {
        for transport in [
            SwaggerProbeTransport::Get,
            SwaggerProbeTransport::Head,
            SwaggerProbeTransport::Post,
        ] {
            let mut hdrs = vec![("X-Weissman-Swagger-Canary".into(), canary.to_string())];
            for (k, v) in &auth {
                hdrs.push((k.clone(), v.clone()));
            }
            push_vector(
                &mut out,
                cat,
                transport,
                &path,
                Some("application/json"),
                hdrs,
                canary,
                true,
            );
        }
    }

    for i in 0..12u8 {
        let path = format!("/openapi.json?wsw={nonce}&v={i}");
        push_vector(
            &mut out,
            "synthetic_encoding",
            SwaggerProbeTransport::Get,
            &path,
            None,
            Vec::new(),
            canary,
            true,
        );
    }

    out
}

#[must_use]
pub fn synthesize_swagger_abuse_vectors(
    host: &str,
    ctx: &EngineRunContext,
) -> (Vec<SwaggerProbeVector>, SwaggerSynthesisStats) {
    let nonce = synthesis_nonce();
    let canary = format!("canary-{nonce}");
    let synthetic = synthetic_vectors(host, ctx, &nonce, &canary);
    let syn_count = synthetic.len();
    let mut static_v = static_catalog(&canary);
    let mut all = synthetic;
    all.append(&mut static_v);

    let mut seen = HashSet::new();
    all.retain(|v| {
        let k = format!("{:?}|{}|{:?}", v.transport, v.path, v.accept);
        seen.insert(k)
    });
    all.truncate(MAX_VECTORS_PER_BASE);
    let generated = all.len();

    (
        all,
        SwaggerSynthesisStats {
            vectors_generated: generated,
            synthetic_generated: syn_count.min(generated),
        },
    )
}

#[must_use]
pub fn analyze_openapi_body(body: &str, path: &str) -> OpenApiSignal {
    let low = body.to_ascii_lowercase();
    let mut sig = OpenApiSignal::default();
    sig.is_ui = path.contains("swagger-ui")
        || path.contains("redoc")
        || path.contains("webjars")
        || path.contains("knife4j")
        || path.contains("scalar")
        || path.contains("elements")
        || low.contains("swagger-ui")
        || low.contains("redoc")
        || low.contains("scalar");
    sig.is_yaml = body.trim_start().starts_with("openapi:")
        || body.trim_start().starts_with("swagger:")
        || low.contains("openapi: 3")
        || low.contains("swagger: '2");
    sig.is_postman = low.contains("\"info\"")
        && low.contains("\"item\"")
        && (low.contains("postman") || path.contains("postman"));
    sig.is_spec = sig.is_yaml
        || sig.is_postman
        || low.contains("\"openapi\"")
        || low.contains("\"swagger\"")
        || low.contains("\"paths\"")
        || (low.contains("swagger") && low.contains("paths"));
    sig.has_auth_schemes = low.contains("securityschemes")
        || low.contains("securitydefinitions")
        || low.contains("\"security\"");
    sig.has_oauth = low.contains("oauth2") || low.contains("authorizationurl");
    sig.has_bearer = low.contains("bearer") || low.contains("jwt");
    sig.has_api_key = low.contains("apikey") || low.contains("x-api-key");
    sig.write_op_count = low.matches("\"post\"").count()
        + low.matches("\"put\"").count()
        + low.matches("\"delete\"").count()
        + low.matches("\"patch\"").count();
    sig.has_write_ops = sig.write_op_count > 0;
    sig.sensitive_hints = [
        "admin", "internal", "token", "secret", "password", "credential", "delete",
        "privileged", "root", "sudo", "impersonate", "escalate", "export", "dump",
    ]
    .iter()
    .any(|k| low.contains(k));
    sig.pii_hints = [
        "email", "ssn", "phone", "address", "dob", "passport", "credit", "iban",
    ]
    .iter()
    .any(|k| low.contains(k));
    sig.path_estimate = body.matches("\"/").count().min(2000);
    sig.operation_count = body.matches("\"get\"").count() + sig.write_op_count
        + body.matches("\"head\"").count()
        + body.matches("\"options\"").count();
    sig.version = if low.contains("\"openapi\": \"3") || low.contains("openapi: 3") {
        Some("3.x".into())
    } else if low.contains("\"swagger\": \"2") || low.contains("swagger: '2") {
        Some("2.x".into())
    } else {
        None
    };
    sig
}

#[must_use]
pub fn materialize_path_template(p: &str) -> String {
    let mut out = String::new();
    let mut in_brace = false;
    for c in p.chars() {
        if c == '{' {
            in_brace = true;
            out.push_str("1");
        } else if c == '}' {
            in_brace = false;
        } else if !in_brace {
            out.push(c);
        }
    }
    out
}

#[must_use]
pub fn extract_quoted_urls(body: &str, keys: &[&str]) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = HashSet::new();
    for key in keys {
        for marker in [*key, &key.replace(':', "")] {
            for cap in body.match_indices(marker) {
                let rest = &body[cap.0 + marker.len()..];
                let rest = rest.trim_start_matches([' ', ':', '=']);
                let url = if rest.starts_with('"') {
                    rest.trim_start_matches('"')
                        .split('"')
                        .next()
                        .unwrap_or_default()
                } else if rest.starts_with('\'') {
                    rest.trim_start_matches('\'')
                        .split('\'')
                        .next()
                        .unwrap_or_default()
                } else {
                    continue;
                };
                if (url.starts_with('/') || url.starts_with("http"))
                    && url.len() > 1
                    && seen.insert(url.to_string())
                {
                    urls.push(url.to_string());
                }
            }
        }
    }
    urls
}

#[must_use]
pub fn extract_sample_paths(body: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    for cap in body.match_indices("\"/") {
        let start = cap.0 + 1;
        if let Some(end) = body[start..].find('"') {
            let p = &body[start..start + end];
            if p.len() > 1
                && p.starts_with('/')
                && !p.contains("swagger")
                && !p.contains("openapi")
                && seen.insert(p.to_string())
            {
                paths.push(materialize_path_template(p));
                if paths.len() >= MAX_FOLLOWUP_PATHS {
                    break;
                }
            }
        }
    }
    paths
}

#[must_use]
pub fn extract_operations(body: &str) -> Vec<OpenApiOperation> {
    let paths = extract_sample_paths(body);
    let low = body.to_ascii_lowercase();
    let mut ops = Vec::new();
    for path in paths {
        let needle = format!("\"{path}\"");
        let idx = body.find(&needle).or_else(|| low.find(&needle.to_ascii_lowercase()));
        let snippet = idx
            .map(|i| {
                low[i..i.saturating_add(1200).min(low.len())]
                    .to_string()
            })
            .unwrap_or_default();
        let requires_auth = snippet.contains("\"security\"")
            || snippet.contains("security:")
            || snippet.contains("bearer")
            || snippet.contains("oauth");
        for (m, name) in [
            ("GET", "get"),
            ("POST", "post"),
            ("PUT", "put"),
            ("DELETE", "delete"),
            ("PATCH", "patch"),
        ] {
            if snippet.contains(&format!("\"{name}\"")) {
                ops.push(OpenApiOperation {
                    path: path.clone(),
                    method: m,
                    requires_auth_hint: requires_auth,
                });
            }
        }
        if ops.len() >= MAX_OPERATION_PROBES {
            break;
        }
    }
    ops
}

#[must_use]
pub fn extract_spring_groups(body: &str) -> Vec<String> {
    let mut groups = Vec::new();
    let mut seen = HashSet::new();
    for marker in ["\"name\"", "\"group\"", "\"groupName\""] {
        for cap in body.match_indices(marker) {
            let rest = &body[cap.0..cap.0.saturating_add(120).min(body.len())];
            if let Some(q) = rest.split('"').nth(3) {
                if !q.is_empty() && q.len() < 48 && seen.insert(q.to_string()) {
                    groups.push(q.to_string());
                }
            }
        }
    }
    groups
}

#[must_use]
pub fn extract_full_spec(body: &str, path: &str) -> SpecExtraction {
    let mut extraction = SpecExtraction::default();
    extraction.paths = extract_sample_paths(body);
    extraction.operations = extract_operations(body);
    extraction.servers = extract_quoted_urls(
        body,
        &["\"url\"", "url:", "basePath", "host", "servers"],
    );
    extraction.ui_spec_urls = extract_quoted_urls(
        body,
        &["configUrl", "url:", "urls:", "spec:", "openapi:"],
    );
    extraction.spring_groups = extract_spring_groups(body);
    if path.contains("swagger-config") && extraction.spring_groups.is_empty() {
        extraction.spring_groups = spring_group_names().iter().map(|s| (*s).to_string()).collect();
    }
    extraction
}

pub fn evaluate_swagger_hit(vector: &SwaggerProbeVector, probe: &HttpProbe) -> Option<SwaggerProbeHit> {
    if probe.status == 404 || (probe.status == 401 && probe.body.len() < 64) {
        return None;
    }
    let signal = analyze_openapi_body(&probe.body, &vector.path);
    let ui_hit = signal.is_ui && probe.status < 400 && probe.body.len() > 128;
    let spec_hit = signal.is_spec && probe.status == 200 && probe.body.len() > 48;
    let resources_hit = vector.path.contains("swagger-resources")
        && probe.status == 200
        && (probe.body.contains("location") || probe.body.contains("swaggerVersion"));
    let config_hit = vector.path.contains("swagger-config") && probe.status == 200;
    if !spec_hit && !ui_hit && !resources_hit && !config_hit {
        return None;
    }
    let extraction = extract_full_spec(&probe.body, &vector.path);
    Some(SwaggerProbeHit {
        vector: vector.clone(),
        status: probe.status,
        body_len: probe.body.len(),
        signal,
        final_url: probe.final_url.clone(),
        extraction,
    })
}

async fn execute_vector(
    client: &Client,
    base: &str,
    vector: &SwaggerProbeVector,
) -> Option<(SwaggerProbeVector, HttpProbe)> {
    let url = if vector.path.starts_with("http") {
        vector.path.clone()
    } else {
        format!("{}{}", base.trim_end_matches('/'), vector.path)
    };
    let mut hdrs: Vec<(&str, &str)> = vector
        .extra_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let accept_owned;
    if let Some(ref a) = vector.accept {
        accept_owned = a.clone();
        hdrs.push(("Accept", accept_owned.as_str()));
    }
    let probe = match vector.transport {
        SwaggerProbeTransport::Get => http_get_with_headers(client, &url, &hdrs).await,
        SwaggerProbeTransport::Head => {
            http_method_with_headers(client, "HEAD", &url, None, &hdrs).await
        }
        SwaggerProbeTransport::Options => {
            http_method_with_headers(client, "OPTIONS", &url, None, &hdrs).await
        }
        SwaggerProbeTransport::Post => {
            http_post_json(client, &url, &json!({})).await
        }
    };
    probe.map(|p| (vector.clone(), p))
}

pub async fn probe_swagger_vectors_concurrent(
    client: &Client,
    base: &str,
    vectors: Vec<SwaggerProbeVector>,
) -> Vec<SwaggerProbeHit> {
    stream::iter(vectors)
        .map(|v| {
            let c = client.clone();
            let b = base.to_string();
            async move { execute_vector(&c, &b, &v).await }
        })
        .buffer_unordered(PROBE_CONCURRENCY)
        .filter_map(|x| async move { x })
        .filter_map(|(vector, probe)| async move { evaluate_swagger_hit(&vector, &probe) })
        .collect()
        .await
}

pub async fn probe_openapi_followup_paths(
    client: &Client,
    base: &str,
    paths: &[String],
) -> Vec<(String, HttpProbe)> {
    let mut out = Vec::new();
    for p in paths.iter().take(MAX_FOLLOWUP_PATHS) {
        let url = if p.starts_with("http") {
            p.clone()
        } else {
            format!("{}{}", base.trim_end_matches('/'), p)
        };
        if let Some(probe) = http_get(client, &url).await {
            if probe.status < 500 {
                out.push((p.clone(), probe));
            }
        }
    }
    out
}

pub async fn probe_openapi_operations(
    client: &Client,
    base: &str,
    operations: &[OpenApiOperation],
    auth_headers: &[(&str, &str)],
) -> Vec<OperationProbeHit> {
    let mut hits = Vec::new();
    for op in operations.iter().take(MAX_OPERATION_PROBES) {
        let path = materialize_path_template(&op.path);
        let url = if path.starts_with("http") {
            path.clone()
        } else {
            format!("{}{}", base.trim_end_matches('/'), path)
        };
        let without = http_method_with_headers(client, op.method, &url, None, &[]).await;
        if let Some(p) = without {
            if p.status < 500 && p.status != 404 {
                hits.push(OperationProbeHit {
                    operation: op.clone(),
                    status: p.status,
                    body_len: p.body.len(),
                    final_url: p.final_url,
                    without_auth: true,
                });
            }
        }
        if !auth_headers.is_empty() {
            if let Some(p) = http_method_with_headers(client, op.method, &url, None, auth_headers).await
            {
                if p.status < 500 && p.status != 404 {
                    hits.push(OperationProbeHit {
                        operation: op.clone(),
                        status: p.status,
                        body_len: p.body.len(),
                        final_url: p.final_url,
                        without_auth: false,
                    });
                }
            }
        }
    }
    hits
}

pub async fn probe_ui_spec_urls(
    client: &Client,
    base: &str,
    urls: &[String],
) -> Vec<SwaggerProbeHit> {
    let mut hits = Vec::new();
    for u in urls.iter().take(8) {
        let full = if u.starts_with("http") {
            u.clone()
        } else {
            format!("{}{}", base.trim_end_matches('/'), u)
        };
        if let Some(p) = http_get(client, &full).await {
            let vector = SwaggerProbeVector {
                category: "ui_embedded_spec",
                transport: SwaggerProbeTransport::Get,
                path: u.clone(),
                accept: None,
                extra_headers: Vec::new(),
                synthetic: true,
                canary: "ui-embed".into(),
            };
            if let Some(hit) = evaluate_swagger_hit(&vector, &p) {
                hits.push(hit);
            }
        }
    }
    hits
}

pub async fn probe_alternate_servers(
    client: &Client,
    servers: &[String],
    path: &str,
) -> Vec<(String, HttpProbe)> {
    let mut out = Vec::new();
    for s in servers.iter().take(MAX_SERVER_PROBES) {
        let base = if s.starts_with("http") {
            s.trim_end_matches('/').to_string()
        } else if s.starts_with('/') {
            continue;
        } else {
            format!("https://{s}")
        };
        let url = format!("{base}{path}");
        if let Some(p) = http_get(client, &url).await {
            if p.status < 500 {
                out.push((url, p));
            }
        }
    }
    out
}

pub fn swagger_probe_bases(target: &str, ctx: &EngineRunContext) -> Vec<String> {
    let root = target.trim();
    let normalized = if root.starts_with("http://") || root.starts_with("https://") {
        root.to_string()
    } else {
        format!("https://{root}")
    };
    let mut bases = vec![normalize_url(&normalized)];
    if normalized.starts_with("https://") {
        bases.push(normalized.replacen("https://", "http://", 1));
    }
    for p in &ctx.discovered_paths {
        if p.starts_with("http") {
            bases.push(normalize_url(p));
        }
    }
    if let Some(bus) = ctx.intelligence_bus.as_ref() {
        for art in bus.snapshot() {
            if art.source_url.starts_with("http") {
                bases.push(normalize_url(&art.source_url));
            }
        }
    }
    bases.sort();
    bases.dedup();
    bases
}
