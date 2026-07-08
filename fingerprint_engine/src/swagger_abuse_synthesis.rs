//! Swagger / OpenAPI abuse synthesis — full discovery catalog + runtime path generation.
//!
//! Live probes hunt exposed specs (JSON/YAML), UI bundles, swagger-resources, and follow-up
//! abuse of enumerated endpoints from discovered documents.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    http_get, http_get_with_headers, http_method_with_headers, normalize_url, HttpProbe,
};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use std::collections::HashSet;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const PROBE_CONCURRENCY: usize = 20;
const MAX_VECTORS_PER_BASE: usize = 180;
const MAX_FOLLOWUP_PATHS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwaggerProbeTransport {
    Get,
    Head,
    Options,
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
    pub has_auth_schemes: bool,
    pub has_oauth: bool,
    pub has_bearer: bool,
    pub has_api_key: bool,
    pub sensitive_hints: bool,
    pub path_estimate: usize,
    pub operation_count: usize,
    pub version: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SwaggerProbeHit {
    pub vector: SwaggerProbeVector,
    pub status: u16,
    pub body_len: usize,
    pub signal: OpenApiSignal,
    pub final_url: String,
    pub sample_paths: Vec<String>,
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
    ]
}

fn accept_variants() -> Vec<(&'static str, &'static str)> {
    vec![
        ("application/json", "accept_json"),
        ("application/yaml", "accept_yaml"),
        ("application/vnd.oai.openapi+json", "accept_oai_json"),
        ("text/yaml", "accept_text_yaml"),
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
        }
    }

    for (path, _) in static_spec_paths().iter().take(12) {
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
    }

    for (accept, cat) in accept_variants() {
        push_vector(
            &mut out,
            cat,
            SwaggerProbeTransport::Get,
            "/openapi.json",
            Some(accept),
            vec![("X-Weissman-Swagger-Canary".into(), canary.to_string())],
            canary,
            false,
        );
        push_vector(
            &mut out,
            cat,
            SwaggerProbeTransport::Get,
            "/v3/api-docs",
            Some(accept),
            vec![("X-Weissman-Swagger-Canary".into(), canary.to_string())],
            canary,
            false,
        );
    }

    out
}

fn synthetic_paths(host: &str, nonce: &str, ctx: &EngineRunContext) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    let slug = host.replace('.', "_");
    out.push((
        format!("/api/{slug}/openapi.json"),
        "synthetic_host_slug",
    ));
    out.push((
        format!("/{slug}/v1/openapi.json"),
        "synthetic_host_slug",
    ));
    out.push((
        format!("/weissman-{nonce}/openapi.json"),
        "synthetic_nonce_path",
    ));

    for p in ctx.discovered_paths.iter().take(20) {
        let base = p.trim_end_matches('/');
        if base.is_empty() {
            continue;
        }
        out.push((format!("{base}/openapi.json"), "synthetic_intel_path"));
        out.push((format!("{base}/swagger.json"), "synthetic_intel_path"));
        out.push((format!("{base}/v3/api-docs"), "synthetic_intel_path"));
        if let Some(parent) = base.rsplit_once('/') {
            out.push((
                format!("{}/openapi.json", parent.0),
                "synthetic_intel_parent",
            ));
        }
    }

    if let Some(bus) = ctx.intelligence_bus.as_ref() {
        for art in bus.snapshot().iter().take(14) {
            if let Ok(u) = url::Url::parse(&art.source_url) {
                let mut path = u.path().trim_end_matches('/').to_string();
                if path.is_empty() {
                    path = "/api".into();
                }
                out.push((
                    format!("{path}/openapi.json"),
                    "synthetic_bus_artifact",
                ));
                out.push((
                    format!("{path}/swagger.json"),
                    "synthetic_bus_artifact",
                ));
                if art.proof.contains("graphql") {
                    out.push((
                        format!("{path}/graphql/openapi.json"),
                        "synthetic_bus_graphql",
                    ));
                }
                if art.proof.contains("gateway") {
                    out.push((
                        format!("{path}/gateway/openapi.json"),
                        "synthetic_bus_gateway",
                    ));
                }
            }
        }
    }

    for payload in ctx.memory_payloads.iter().take(4) {
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

    for i in 0..8u8 {
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
        || low.contains("swagger-ui")
        || low.contains("redoc");
    sig.is_yaml = body.trim_start().starts_with("openapi:")
        || body.trim_start().starts_with("swagger:")
        || low.contains("openapi: 3")
        || low.contains("swagger: '2");
    sig.is_spec = sig.is_yaml
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
    sig.sensitive_hints = [
        "admin", "internal", "token", "secret", "password", "credential", "delete",
        "privileged", "root", "sudo", "impersonate", "escalate",
    ]
    .iter()
    .any(|k| low.contains(k));
    sig.path_estimate = body.matches("\"/").count().min(2000);
    sig.operation_count = body.matches("\"get\"").count()
        + body.matches("\"post\"").count()
        + body.matches("\"put\"").count()
        + body.matches("\"delete\"").count()
        + body.matches("\"patch\"").count();
    sig.version = if low.contains("\"openapi\": \"3") {
        Some("3.x".into())
    } else if low.contains("\"swagger\": \"2") {
        Some("2.x".into())
    } else {
        None
    };
    sig
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
                && !p.contains('{')
                && !seen.contains(p)
                && !p.contains("swagger")
                && !p.contains("openapi")
            {
                seen.insert(p.to_string());
                paths.push(p.to_string());
                if paths.len() >= MAX_FOLLOWUP_PATHS {
                    break;
                }
            }
        }
    }
    paths
}

pub fn evaluate_swagger_hit(vector: &SwaggerProbeVector, probe: &HttpProbe) -> Option<SwaggerProbeHit> {
    if probe.status == 404 || probe.status == 401 && probe.body.len() < 64 {
        return None;
    }
    let signal = analyze_openapi_body(&probe.body, &vector.path);
    let ui_hit = signal.is_ui && probe.status < 400 && probe.body.len() > 128;
    let spec_hit = signal.is_spec && probe.status == 200 && probe.body.len() > 48;
    let resources_hit = vector.path.contains("swagger-resources")
        && probe.status == 200
        && (probe.body.contains("location") || probe.body.contains("swaggerVersion"));
    if !spec_hit && !ui_hit && !resources_hit {
        return None;
    }
    let sample_paths = if spec_hit {
        extract_sample_paths(&probe.body)
    } else {
        Vec::new()
    };
    Some(SwaggerProbeHit {
        vector: vector.clone(),
        status: probe.status,
        body_len: probe.body.len(),
        signal,
        final_url: probe.final_url.clone(),
        sample_paths,
    })
}

async fn execute_vector(client: &Client, base: &str, vector: &SwaggerProbeVector) -> Option<(SwaggerProbeVector, HttpProbe)> {
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
        SwaggerProbeTransport::Head => http_method_with_headers(client, "HEAD", &url, None, &hdrs).await,
        SwaggerProbeTransport::Options => http_method_with_headers(client, "OPTIONS", &url, None, &hdrs).await,
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
