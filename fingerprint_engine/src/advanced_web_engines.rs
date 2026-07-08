//! Advanced Web Engines — real HTTP/HTTPS probes against the target. No simulated findings.
//!
//! Each engine performs a focused live probe and only emits a finding when an observable
//! security-relevant signal is detected (header anomaly, response pattern, exposed endpoint).
//! On no signal: returns ok with empty findings.

use crate::engine_dispatch::EngineRunContext;
use crate::swagger_abuse_synthesis::{
    probe_openapi_followup_paths, probe_swagger_vectors_concurrent,
    synthesize_swagger_abuse_vectors, swagger_probe_bases,
};
use crate::grpc_reflection_synthesis::{
    grpc_probe_bases, probe_grpc_vectors_concurrent, synthesize_grpc_reflection_vectors,
    GrpcProbeTransport,
};
use crate::web_cache_poison_synthesis::{
    probe_cache_poison_vectors_concurrent, synthesize_cache_poison_vectors,
    CachePoisonTransport,
};
use crate::engine_probes::{
    empty_ok, extract_host, finding, finding_with_probe_depth, has_header, header_value,
    http1_client, http2_client, http_client, http_get, http_get_with_headers,
    http_method_with_headers, http_post_json, http_post_json_with_headers, join_url,
    normalize_url, probe_paths_concurrent, DEFAULT_PROBE_CONCURRENCY, HttpProbe,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::time::Instant;

const WEB_PROBE_DEPTH: &str = "web_app_surface";
const ENGINE_GRAPHQL_DEEP: &str = "graphql_deep_attack";
const ENGINE_CORS: &str = "cors_misconfiguration";
const ENGINE_GATEWAY: &str = "api_gateway_bypass";
const ENGINE_RATE_LIMIT: &str = "api_rate_limit_bypass";
const ENGINE_CACHE_POISON: &str = "web_cache_poison_adv";
const ENGINE_GRPC_REFLECTION: &str = "grpc_reflection_attack";
const ENGINE_SWAGGER: &str = "swagger_abuse";

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

fn web_finding_sync(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    correlation_hints: &[&str],
    feeds_engines: &[&str],
    metadata: Value,
) -> Value {
    let mut f = web_finding(engine_id, title, severity, mitre, description, target);
    if let Some(obj) = f.as_object_mut() {
        obj.insert(
            "correlation_hints".into(),
            Value::Array(correlation_hints.iter().map(|s| json!(*s)).collect()),
        );
        obj.insert(
            "feeds_engines".into(),
            Value::Array(feeds_engines.iter().map(|s| json!(*s)).collect()),
        );
        if !metadata.is_null() {
            obj.insert("sync_metadata".into(), metadata);
        }
    }
    f
}

fn jp_lookup<'a>(p: &'a Value, key: &str) -> Option<&'a Value> {
    p.get(key)
        .or_else(|| p.get("options").and_then(|o| o.get(key)))
}

fn jp_str(params: &Value, key: &str) -> Option<String> {
    jp_lookup(params, key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn graphql_auth_header_pairs(params: &Value) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    if let Some(token) = jp_str(params, "bearer_token") {
        pairs.push((
            "Authorization".into(),
            if token.starts_with("Bearer ") {
                token
            } else {
                format!("Bearer {token}")
            },
        ));
    }
    if let Some(cookie) = jp_str(params, "cookie") {
        pairs.push(("Cookie".into(), cookie));
    }
    if let Some(key) = jp_str(params, "api_key") {
        let hdr = jp_str(params, "api_key_header").unwrap_or_else(|| "X-API-Key".into());
        pairs.push((hdr, key));
    }
    crate::ws_intelligence_bus::apply_intelligence_artifacts_to_headers(params, &mut pairs);
    pairs
}

fn auth_pairs_as_refs(pairs: &[(String, String)]) -> Vec<(&str, &str)> {
    pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

fn introspection_enabled(body: &str) -> bool {
    body.contains("__schema") && body.contains("types")
}

fn count_schema_types(body: &str) -> usize {
    body.matches("\"name\"").count().min(5000)
}

fn graphql_endpoint_paths(ctx: &EngineRunContext) -> Vec<String> {
    let mut paths = vec![
        "/graphql".into(),
        "/api/graphql".into(),
        "/v1/graphql".into(),
        "/query".into(),
        "/api/v1/graphql".into(),
        "/gql".into(),
        "/api/gql".into(),
    ];
    for p in &ctx.discovered_paths {
        let pl = p.to_ascii_lowercase();
        if pl.contains("graphql") && !paths.iter().any(|x| x == p) {
            paths.push(p.clone());
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

// ── graphql_deep_attack ───────────────────────────────────────────────────────
pub async fn run_graphql_deep_attack_result(target: &str) -> EngineResult {
    run_graphql_deep_attack_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_graphql_deep_attack_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_url(target);
    let client = http_client().await;
    let params = &ctx.job_params;
    let auth_pairs = graphql_auth_header_pairs(params);
    let auth_refs = auth_pairs_as_refs(&auth_pairs);
    let has_auth = !auth_pairs.is_empty();
    let mut findings: Vec<Value> = Vec::new();
    let mut flags = GraphqlProbeFlags::default();

    let intro = json!({"query":"{__schema{types{name fields{name}}}}"});
    let mutation_intro = json!({"query":"{__schema{mutationType{name}}}"});
    let batch = json!([{"query":"{__typename}"},{"query":"{__typename}"}]);
    let depth_bomb = json!({"query":"{a{a{a{a{a{__typename}}}}}}"});
    let alias_bomb = json!({"query":"{q1:__typename q2:__typename q3:__typename q4:__typename q5:__typename q6:__typename q7:__typename q8:__typename}"});
    let apq = json!({
        "extensions": {
            "persistedQuery": {
                "version": 1,
                "sha256Hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        },
        "query": "{__typename}"
    });
    let defer_q = json!({"query":"query { __typename @defer }"});

    let path_strings = graphql_endpoint_paths(ctx);
    let path_refs: Vec<&str> = path_strings.iter().map(String::as_str).collect();

    let path_probes =
        probe_paths_concurrent(&client, &base, &path_refs, DEFAULT_PROBE_CONCURRENCY).await;
    for p in path_probes {
        if (p.status == 405 || p.status == 200)
            && p.body.to_ascii_lowercase().contains("graphql")
        {
            if let Some(bus) = ctx.intelligence_bus.as_ref() {
                bus.publish_http_surface(
                    "graphql_endpoint",
                    &p.final_url,
                    &p.final_url,
                    ENGINE_GRAPHQL_DEEP,
                    "graphql_endpoint_discovered",
                );
            }
            findings.push(web_finding_sync(
                ENGINE_GRAPHQL_DEEP,
                "GraphQL endpoint surface discovered",
                "info",
                "T1190",
                &format!(
                    "{} ({}) advertises GraphQL — introspection, batching, and auth differential probed.",
                    p.final_url, p.status
                ),
                target,
                &["graphql_subscription_attack", "api_gateway_bypass"],
                &["risk_superposition_collapse", "external_exposure_supreme"],
                json!({"endpoint": p.final_url, "status": p.status}),
            ));
        }
    }

    for path in &path_strings {
        let url = format!("{}{}", base.trim_end_matches('/'), path);

        let t0 = Instant::now();
        let anon_intro = http_post_json(&client, &url, &intro).await;
        let anon_intro_ms = t0.elapsed().as_millis() as u64;

        let auth_intro = if has_auth {
            http_post_json_with_headers(&client, &url, &intro, &auth_refs).await
        } else {
            None
        };

        if let Some(p) = anon_intro.as_ref() {
            if p.status < 500 && introspection_enabled(&p.body) {
                flags.introspection_anon = true;
                let types = count_schema_types(&p.body);
                if let Some(bus) = ctx.intelligence_bus.as_ref() {
                    bus.publish_http_surface(
                        "graphql_introspection_url",
                        &p.final_url,
                        &p.final_url,
                        ENGINE_GRAPHQL_DEEP,
                        "graphql_introspection_anon",
                    );
                }
                findings.push(web_finding_sync(
                    ENGINE_GRAPHQL_DEEP,
                    "GraphQL introspection enabled (unauthenticated)",
                    "high",
                    "T1190",
                    &format!(
                        "POST {} returns __schema with ~{types} type markers (HTTP {}, {anon_intro_ms}ms).",
                        p.final_url, p.status
                    ),
                    target,
                    &["cors_misconfiguration", "idor_advanced", "api_mass_assignment"],
                    &["graphql_subscription_attack", "graphql_attack", "risk_superposition_collapse"],
                    json!({"types_estimate": types, "latency_ms": anon_intro_ms, "endpoint": p.final_url}),
                ));
            }
        }

        if let (Some(anon), Some(auth)) = (anon_intro.as_ref(), auth_intro.as_ref()) {
            let anon_has = introspection_enabled(&anon.body);
            let auth_has = introspection_enabled(&auth.body);
            if anon_has != auth_has || (anon_has && anon.body.len() > auth.body.len() + 256) {
                flags.auth_differential = true;
                findings.push(web_finding_sync(
                    ENGINE_GRAPHQL_DEEP,
                    "Auth differential on GraphQL introspection",
                    "high",
                    "T1078",
                    &format!(
                        "Anon introspection={anon_has} (HTTP {}) vs authenticated={auth_has} (HTTP {}) on {} — schema exposure differs by credential.",
                        anon.status, auth.status, url
                    ),
                    target,
                    &["jwt_advanced_attack", "mfa_bypass_engine"],
                    &["identity_attack_chain"],
                    json!({
                        "anon_status": anon.status,
                        "auth_status": auth.status,
                        "anon_schema": anon_has,
                        "auth_schema": auth_has
                    }),
                ));
            }
        }

        let get_intro = format!(
            "{url}?query={}",
            urlencoding::encode("{__schema{queryType{name}}}")
        );
        if let Some(p) = http_get(&client, &get_intro).await {
            if p.status < 500 && p.body.contains("__schema") {
                flags.get_introspection = true;
                findings.push(web_finding_sync(
                    ENGINE_GRAPHQL_DEEP,
                    "GraphQL introspection over GET",
                    "high",
                    "T1190",
                    &format!(
                        "GET introspection at {} (HTTP {}) — CSRF/log-based exfiltration risk.",
                        p.final_url, p.status
                    ),
                    target,
                    &["cors_misconfiguration", "clickjacking_engine"],
                    &["external_exposure_supreme"],
                    json!({"transport": "GET", "endpoint": p.final_url}),
                ));
            }
        }

        if let Some(p) = http_post_json(&client, &url, &mutation_intro).await {
            if p.status < 500 && p.body.contains("mutationType") {
                flags.mutations = true;
                findings.push(web_finding_sync(
                    ENGINE_GRAPHQL_DEEP,
                    "GraphQL mutation schema enumerable",
                    "medium",
                    "T1190",
                    &format!("Mutation root exposed at {} (HTTP {}).", p.final_url, p.status),
                    target,
                    &["api_mass_assignment"],
                    &["pipeline_to_runtime_risk"],
                    json!({"endpoint": p.final_url}),
                ));
            }
        }

        if let Some(p) = http_post_json(&client, &url, &batch).await {
            if p.status >= 200 && p.status < 300 && p.body.trim_start().starts_with('[') {
                flags.batching = true;
                findings.push(web_finding_sync(
                    ENGINE_GRAPHQL_DEEP,
                    "GraphQL batching accepted",
                    "medium",
                    "T1190",
                    &format!(
                        "{} returned batched JSON — pairs with api_rate_limit_bypass amplification.",
                        p.final_url
                    ),
                    target,
                    &["api_rate_limit_bypass"],
                    &["risk_superposition_collapse"],
                    json!({"endpoint": p.final_url}),
                ));
            }
        }

        let t_light = Instant::now();
        let _ = http_post_json(&client, &url, &json!({"query":"{__typename}"})).await;
        let light_ms = t_light.elapsed().as_millis() as u64;
        if anon_intro_ms > 0 && light_ms > 0 && anon_intro_ms > light_ms.saturating_mul(8) {
            flags.cost_amplification = true;
            findings.push(web_finding_sync(
                ENGINE_GRAPHQL_DEEP,
                "Query cost amplification (introspection >> typename)",
                "medium",
                "T1499",
                &format!(
                    "__typename {light_ms}ms vs introspection {anon_intro_ms}ms on {url} — DoS/cost bypass surface."
                ),
                target,
                &["api_rate_limit_bypass"],
                &[],
                json!({"light_ms": light_ms, "intro_ms": anon_intro_ms}),
            ));
        }

        if let Some(p) = http_post_json(&client, &url, &depth_bomb).await {
            let body_low = p.body.to_ascii_lowercase();
            if p.status < 500
                && !body_low.contains("max depth")
                && !body_low.contains("depth limit")
                && !body_low.contains("too complex")
                && p.body.contains("__typename")
            {
                flags.no_depth_limit = true;
                findings.push(web_finding_sync(
                    ENGINE_GRAPHQL_DEEP,
                    "Deep nested query accepted (no depth limit)",
                    "medium",
                    "T1499",
                    &format!("Nested depth bomb accepted at {} (HTTP {}).", p.final_url, p.status),
                    target,
                    &["api_rate_limit_bypass"],
                    &[],
                    json!({"endpoint": p.final_url}),
                ));
            }
        }

        if let Some(p) = http_post_json(&client, &url, &alias_bomb).await {
            if p.status < 500 && p.body.matches("__typename").count() >= 4 {
                flags.alias_fanout = true;
                findings.push(web_finding_sync(
                    ENGINE_GRAPHQL_DEEP,
                    "Alias-heavy query accepted",
                    "low",
                    "T1499",
                    &format!("Alias fan-out accepted at {}.", p.final_url),
                    target,
                    &["api_rate_limit_bypass"],
                    &[],
                    json!({}),
                ));
            }
        }

        if let Some(p) = http_post_json(&client, &url, &apq).await {
            if p.status < 500
                && (p.body.contains("__typename")
                    || p.body.to_ascii_lowercase().contains("persistedquery"))
            {
                flags.apq = true;
                findings.push(web_finding_sync(
                    ENGINE_GRAPHQL_DEEP,
                    "APQ / persisted-query surface responds",
                    "medium",
                    "T1190",
                    &format!(
                        "APQ probe at {} (HTTP {}) — verify allowlist on sha256Hash.",
                        p.final_url, p.status
                    ),
                    target,
                    &["web_cache_poison_adv"],
                    &[],
                    json!({"endpoint": p.final_url}),
                ));
            }
        }

        if let Some(p) = http_post_json(&client, &url, &defer_q).await {
            let bl = p.body.to_ascii_lowercase();
            if p.status < 500 && (bl.contains("@defer") || bl.contains("defer")) {
                flags.defer = true;
                findings.push(web_finding_sync(
                    ENGINE_GRAPHQL_DEEP,
                    "@defer / incremental delivery referenced",
                    "medium",
                    "T1190",
                    &format!("@defer probe at {} — incremental delivery may leak data.", p.final_url),
                    target,
                    &["graphql_subscription_attack"],
                    &[],
                    json!({}),
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
                ("Sec-WebSocket-Protocol", "graphql-transport-ws"),
            ],
        )
        .await
        {
            if p.status == 101
                || header_value(&p.headers, "upgrade")
                    .map(|u| u.to_ascii_lowercase().contains("websocket"))
                    .unwrap_or(false)
            {
                flags.ws_upgrade = true;
                findings.push(web_finding_sync(
                    ENGINE_GRAPHQL_DEEP,
                    "GraphQL WebSocket upgrade accepted",
                    "high",
                    "T1190",
                    &format!(
                        "GET {} → HTTP {} with Upgrade:websocket — sync with graphql_subscription_attack.",
                        p.final_url, p.status
                    ),
                    target,
                    &["graphql_subscription_attack", "websocket_attack"],
                    &["risk_superposition_collapse"],
                    json!({"endpoint": p.final_url}),
                ));
            }
        }
    }

    if flags.introspection_anon && flags.batching && flags.no_depth_limit {
        findings.push(web_finding_sync(
            ENGINE_GRAPHQL_DEEP,
            "Toxic chain: anon introspection + batching + no depth limit",
            "critical",
            "T1190",
            "Live GraphQL fusion: schema enumerable without auth, batched queries accepted, depth unlimited — brute-force and DoS amplification chain.",
            target,
            &["api_rate_limit_bypass", "cors_misconfiguration"],
            &["risk_superposition_collapse", "external_exposure_supreme"],
            json!({"toxic_chain": true}),
        ));
    }

    if findings.is_empty() {
        empty_ok(ENGINE_GRAPHQL_DEEP, target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!(
                "{ENGINE_GRAPHQL_DEEP}: {n} live finding(s) (auth_diff={} ws={} apq={})",
                flags.auth_differential,
                flags.ws_upgrade,
                flags.apq
            ),
        )
    }
}

#[derive(Default)]
struct GraphqlProbeFlags {
    introspection_anon: bool,
    auth_differential: bool,
    get_introspection: bool,
    mutations: bool,
    batching: bool,
    no_depth_limit: bool,
    alias_fanout: bool,
    cost_amplification: bool,
    apq: bool,
    defer: bool,
    ws_upgrade: bool,
}

cli_wrapper!(run_graphql_deep_attack, run_graphql_deep_attack_result);

// ── grpc_reflection_attack ────────────────────────────────────────────────────
pub async fn run_grpc_reflection_attack_result(target: &str) -> EngineResult {
    run_grpc_reflection_attack_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_grpc_reflection_attack_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let h2 = http2_client().await;
    let h1 = http_client().await;
    let bases = grpc_probe_bases(target, ctx);
    let mut findings: Vec<Value> = Vec::new();
    let mut flags = GrpcReflectionFlags::default();
    let mut total_vectors = 0usize;
    let mut total_synthetic = 0usize;
    let mut categories_hit: Vec<String> = Vec::new();

    for base in &bases {
        let (vectors, stats) = synthesize_grpc_reflection_vectors(&host, ctx);
        total_vectors += stats.vectors_generated;
        total_synthetic += stats.synthetic_generated;

        let hits = probe_grpc_vectors_concurrent(&h2, &h1, base, vectors).await;
        for hit in hits {
            if hit.reflection_likely {
                flags.reflection_exposed = true;
            }
            if hit.grpc_web {
                flags.grpc_web = true;
            }
            if hit.connect_rpc {
                flags.connect_rpc = true;
            }
            if hit.services_hint {
                flags.services_enumerated = true;
            }
            if hit.vector.synthetic {
                flags.synthetic_hit = true;
            }
            if hit.vector.transport == GrpcProbeTransport::GatewayGet {
                flags.gateway_surface = true;
            }
            if !categories_hit.iter().any(|c| c == hit.vector.category) {
                categories_hit.push(hit.vector.category.to_string());
            }

            if let Some(bus) = ctx.intelligence_bus.as_ref() {
                bus.publish_http_surface(
                    "grpc_reflection_surface",
                    &hit.vector.path,
                    &hit.final_url,
                    ENGINE_GRPC_REFLECTION,
                    if hit.vector.synthetic {
                        "http_surface_grpc_reflection_synthetic"
                    } else if hit.reflection_likely {
                        "http_surface_grpc_reflection_live"
                    } else {
                        "http_surface_grpc_detected"
                    },
                );
            }

            let severity = if hit.reflection_likely && !hit.vector.synthetic {
                "critical"
            } else if hit.reflection_likely {
                "high"
            } else if hit.grpc_web || hit.connect_rpc {
                "high"
            } else {
                "medium"
            };

            findings.push(web_finding_sync(
                ENGINE_GRPC_REFLECTION,
                &format!(
                    "gRPC surface [{}] {} on {}",
                    hit.vector.category,
                    if hit.reflection_likely {
                        "reflection exposed"
                    } else if hit.grpc_web {
                        "grpc-web transport"
                    } else if hit.connect_rpc {
                        "Connect-RPC transport"
                    } else {
                        "service responded"
                    },
                    hit.vector.path
                ),
                severity,
                "T1190",
                &format!(
                    "POST/GET {} → HTTP {} (grpc-status={:?}, {}B, synthetic={}, transport={:?}) — protobuf service enumeration surface.",
                    hit.final_url,
                    hit.status,
                    hit.grpc_status,
                    hit.body_len,
                    hit.vector.synthetic,
                    hit.vector.transport
                ),
                target,
                &[
                    "api_gateway_bypass",
                    "mtls_grpc",
                    "api_rate_limit_bypass",
                    "graphql_deep_attack",
                ],
                &[
                    "risk_superposition_collapse",
                    "external_exposure_supreme",
                    "threat_surface_intelligence_fusion",
                ],
                json!({
                    "category": hit.vector.category,
                    "synthetic": hit.vector.synthetic,
                    "reflection": hit.reflection_likely,
                    "grpc_web": hit.grpc_web,
                    "connect_rpc": hit.connect_rpc,
                    "content_type": hit.vector.content_type,
                    "endpoint": hit.final_url,
                    "grpc_status": hit.grpc_status
                }),
            ));
        }
    }

    if flags.reflection_exposed && flags.grpc_web {
        findings.push(web_finding_sync(
            ENGINE_GRPC_REFLECTION,
            "Toxic chain: gRPC reflection + grpc-web browser plane",
            "critical",
            "T1190",
            &format!(
                "Live gRPC fusion: server reflection reachable AND grpc-web/Connect transport active — browser-exploitable protobuf enumeration ({} vectors, {} synthetic).",
                total_vectors, total_synthetic
            ),
            target,
            &["cors_misconfiguration", "api_gateway_bypass"],
            &["risk_superposition_collapse", "identity_attack_chain"],
            json!({"toxic_chain": true, "reflection_web": true}),
        ));
    }

    if flags.reflection_exposed && flags.gateway_surface {
        findings.push(web_finding_sync(
            ENGINE_GRPC_REFLECTION,
            "Toxic chain: reflection behind API gateway surface",
            "critical",
            "T1190",
            "Gateway-exposed gRPC reflection — edge ACL may not cover /grpc paths; full RPC map leak chain.",
            target,
            &["api_gateway_bypass", "zero_trust_bypass"],
            &["external_exposure_supreme"],
            json!({"toxic_chain": true, "gateway_reflection": true}),
        ));
    }

    if flags.synthetic_hit && flags.reflection_exposed {
        findings.push(web_finding_sync(
            ENGINE_GRPC_REFLECTION,
            "Toxic chain: runtime-synthesized reflection path confirmed",
            "critical",
            "T1190",
            &format!(
                "Zero-day synthesis: dynamically computed service path returned reflection frame — novel RPC surface (categories={:?}).",
                categories_hit
            ),
            target,
            &["mtls_grpc", "api_mass_assignment"],
            &["threat_surface_intelligence_fusion"],
            json!({"toxic_chain": true, "synthetic_reflection": true}),
        ));
    }

    if findings.is_empty() {
        empty_ok(ENGINE_GRPC_REFLECTION, target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!(
                "{ENGINE_GRPC_REFLECTION}: {n} signal(s) vectors={total_vectors} synthetic={total_synthetic} reflect={}",
                flags.reflection_exposed
            ),
        )
    }
}

#[derive(Default)]
struct GrpcReflectionFlags {
    reflection_exposed: bool,
    grpc_web: bool,
    connect_rpc: bool,
    services_enumerated: bool,
    synthetic_hit: bool,
    gateway_surface: bool,
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
fn cors_probe_urls(base: &str, ctx: &EngineRunContext) -> Vec<String> {
    let root = normalize_url(base);
    let mut urls = vec![root.clone()];
    for p in &ctx.discovered_paths {
        urls.push(join_url(&root, p));
    }
    if let Some(bus) = ctx.intelligence_bus.as_ref() {
        for art in bus.snapshot() {
            let kind = art.kind.to_ascii_lowercase();
            if kind.contains("graphql")
                || art.source_url.to_ascii_lowercase().contains("graphql")
                || art.proof.starts_with("graphql_")
            {
                urls.push(art.source_url.clone());
            }
        }
    }
    urls.sort();
    urls.dedup();
    urls
}

fn cors_test_origins(host: &str) -> Vec<(Option<String>, &'static str)> {
    vec![
        (None, "baseline"),
        (
            Some(format!("https://weissman-cors-probe.{host}")),
            "evil_reflection",
        ),
        (Some("null".into()), "null_origin"),
        (
            Some(format!("https://{host}.evil.weissman-cors-probe.test")),
            "subdomain_suffix",
        ),
        (
            Some(format!("https://evil-{host}")),
            "prefix_host",
        ),
    ]
}

pub async fn run_cors_misconfiguration_result(target: &str) -> EngineResult {
    run_cors_misconfiguration_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_cors_misconfiguration_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let host = extract_host(target);
    let auth_pairs = graphql_auth_header_pairs(&ctx.job_params);
    let auth_refs = auth_pairs_as_refs(&auth_pairs);
    let has_auth = !auth_pairs.is_empty();
    let mut findings: Vec<Value> = Vec::new();
    let mut flags = CorsProbeFlags::default();

    for url in cors_probe_urls(target, ctx) {
        for (origin_opt, origin_tag) in cors_test_origins(&host) {
            let probe = if let Some(ref o) = origin_opt {
                if has_auth {
                    let mut hdrs = vec![("Origin", o.as_str())];
                    for (k, v) in &auth_refs {
                        hdrs.push((k, v));
                    }
                    http_get_with_headers(&client, &url, &hdrs).await
                } else {
                    http_get_with_headers(&client, &url, &[("Origin", o.as_str())]).await
                }
            } else if has_auth {
                http_get_with_headers(&client, &url, &auth_refs).await
            } else {
                http_get(&client, &url).await
            };
            let Some(p) = probe else { continue };
            let Some(acao) = header_value(&p.headers, "access-control-allow-origin") else {
                continue;
            };
            let creds = has_header(&p.headers, "access-control-allow-credentials");
            let sent_ref = origin_opt.as_deref();
            if let Some((title, severity, detail)) =
                cors_misconfiguration_signal(sent_ref, acao, creds)
            {
                if sent_ref.is_some() {
                    flags.reflected = true;
                }
                if creds {
                    flags.credentials = true;
                }
                if acao.trim() == "*" {
                    flags.wildcard = true;
                }
                if origin_tag == "null_origin" {
                    flags.null_origin = true;
                }
                if url.to_ascii_lowercase().contains("graphql") {
                    flags.graphql_surface = true;
                }
                if let Some(bus) = ctx.intelligence_bus.as_ref() {
                    bus.publish_http_surface(
                        "cors_misconfiguration_url",
                        &p.final_url,
                        &p.final_url,
                        ENGINE_CORS,
                        "http_surface_cors_reflection",
                    );
                }
                findings.push(web_finding_sync(
                    ENGINE_CORS,
                    title,
                    severity,
                    "T1185",
                    &format!(
                        "{detail} on {} (ACAO='{acao}', credentials={creds}, origin_probe={origin_tag}, auth={has_auth}).",
                        p.final_url
                    ),
                    target,
                    &["graphql_deep_attack", "clickjacking_engine", "idor_advanced"],
                    &["external_exposure_supreme", "identity_attack_chain"],
                    json!({
                        "endpoint": p.final_url,
                        "acao": acao,
                        "credentials": creds,
                        "origin_probe": origin_tag,
                        "authenticated": has_auth
                    }),
                ));
            }
        }

        let evil = format!("https://weissman-cors-probe.{host}");
        if let Some(p) = http_method_with_headers(
            &client,
            "OPTIONS",
            &url,
            None,
            &[
                ("Origin", evil.as_str()),
                ("Access-Control-Request-Method", "POST"),
                ("Access-Control-Request-Headers", "Authorization, Content-Type, X-Api-Key"),
            ],
        )
        .await
        {
            let acao = header_value(&p.headers, "access-control-allow-origin").unwrap_or_default();
            let acam = header_value(&p.headers, "access-control-allow-methods").unwrap_or_default();
            let acah = header_value(&p.headers, "access-control-allow-headers")
                .unwrap_or_default()
                .to_ascii_lowercase();
            if !acao.is_empty() && acam.to_ascii_uppercase().contains("POST") {
                flags.preflight_post = true;
                if acah.contains("authorization") {
                    flags.preflight_auth_header = true;
                }
                findings.push(web_finding_sync(
                    ENGINE_CORS,
                    "Preflight allows cross-origin POST",
                    if has_header(&p.headers, "access-control-allow-credentials") {
                        "critical"
                    } else {
                        "high"
                    },
                    "T1185",
                    &format!(
                        "OPTIONS {} → ACAO='{acao}' ACAM='{acam}' ACAAH='{acah}' — pairs with graphql_deep_attack GET introspection exfil.",
                        p.final_url
                    ),
                    target,
                    &["graphql_deep_attack", "api_mass_assignment"],
                    &["risk_superposition_collapse"],
                    json!({"endpoint": p.final_url, "acam": acam, "acah": acah}),
                ));
            }
        }
    }

    if flags.reflected && flags.credentials && flags.preflight_post {
        findings.push(web_finding_sync(
            ENGINE_CORS,
            "Toxic chain: reflected ACAO + credentials + preflight POST",
            "critical",
            "T1185",
            "Live CORS fusion: arbitrary origin reflected with credentials and POST preflight — authenticated cross-site read/write against API/GraphQL surfaces.",
            target,
            &["graphql_deep_attack", "websocket_attack"],
            &["risk_superposition_collapse", "identity_attack_chain"],
            json!({"toxic_chain": true, "graphql_surface": flags.graphql_surface}),
        ));
    }

    if findings.is_empty() {
        empty_ok(ENGINE_CORS, target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!(
                "{ENGINE_CORS}: {n} live finding(s) (reflect={} creds={} graphql={})",
                flags.reflected, flags.credentials, flags.graphql_surface
            ),
        )
    }
}

#[derive(Default)]
struct CorsProbeFlags {
    reflected: bool,
    credentials: bool,
    wildcard: bool,
    null_origin: bool,
    preflight_post: bool,
    preflight_auth_header: bool,
    graphql_surface: bool,
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
    run_swagger_abuse_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_swagger_abuse_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let client = http_client().await;
    let bases = swagger_probe_bases(target, ctx);
    let mut findings: Vec<Value> = Vec::new();
    let mut flags = SwaggerAbuseFlags::default();
    let mut total_vectors = 0usize;
    let mut total_synthetic = 0usize;
    let mut categories_hit: Vec<String> = Vec::new();
    let mut followup_probed = 0usize;

    for base in &bases {
        let (vectors, stats) = synthesize_swagger_abuse_vectors(&host, ctx);
        total_vectors += stats.vectors_generated;
        total_synthetic += stats.synthetic_generated;

        let hits = probe_swagger_vectors_concurrent(&client, base, vectors).await;
        for hit in hits {
            if hit.signal.is_spec {
                flags.spec_exposed = true;
            }
            if hit.signal.is_ui {
                flags.ui_exposed = true;
            }
            if hit.signal.has_auth_schemes {
                flags.auth_schemes_leaked = true;
            }
            if !hit.signal.has_auth_schemes && hit.signal.is_spec {
                flags.unauthenticated_spec = true;
            }
            if hit.signal.sensitive_hints {
                flags.sensitive_operations = true;
            }
            if hit.vector.synthetic {
                flags.synthetic_hit = true;
            }
            if hit.signal.operation_count > 10 {
                flags.large_surface = true;
            }
            if !categories_hit.iter().any(|c| c == hit.vector.category) {
                categories_hit.push(hit.vector.category.to_string());
            }

            if let Some(bus) = ctx.intelligence_bus.as_ref() {
                bus.publish_http_surface(
                    "openapi_spec_url",
                    &hit.final_url,
                    &hit.final_url,
                    ENGINE_SWAGGER,
                    if hit.vector.synthetic {
                        "http_surface_openapi_synthetic"
                    } else {
                        "http_surface_openapi_catalog"
                    },
                );
            }

            let severity = if hit.signal.sensitive_hints && !hit.signal.has_auth_schemes {
                "critical"
            } else if hit.signal.is_spec && hit.signal.has_oauth {
                "high"
            } else if hit.vector.synthetic {
                "high"
            } else {
                "medium"
            };

            findings.push(web_finding_sync(
                ENGINE_SWAGGER,
                &format!(
                    "OpenAPI surface [{}] {}",
                    hit.vector.category,
                    if hit.signal.is_ui {
                        "Swagger UI exposed"
                    } else {
                        "spec document exposed"
                    }
                ),
                severity,
                "T1190",
                &format!(
                    "{} → HTTP {} ({}B, ops~{}, paths~{}, auth={}, synthetic={}, version={:?}) — API map abuse surface.",
                    hit.final_url,
                    hit.status,
                    hit.body_len,
                    hit.signal.operation_count,
                    hit.signal.path_estimate,
                    hit.signal.has_auth_schemes,
                    hit.vector.synthetic,
                    hit.signal.version
                ),
                target,
                &[
                    "api_mass_assignment",
                    "api_gateway_bypass",
                    "idor_advanced",
                    "graphql_deep_attack",
                ],
                &[
                    "external_exposure_supreme",
                    "risk_superposition_collapse",
                    "threat_surface_intelligence_fusion",
                ],
                json!({
                    "category": hit.vector.category,
                    "synthetic": hit.vector.synthetic,
                    "endpoint": hit.final_url,
                    "operations": hit.signal.operation_count,
                    "oauth": hit.signal.has_oauth,
                    "bearer": hit.signal.has_bearer,
                    "sensitive": hit.signal.sensitive_hints
                }),
            ));

            if !hit.sample_paths.is_empty() {
                let followups = probe_openapi_followup_paths(&client, base, &hit.sample_paths).await;
                for (path, probe) in followups {
                    followup_probed += 1;
                    if probe.status >= 200 && probe.status < 300 {
                        flags.followup_live = true;
                        findings.push(web_finding_sync(
                            ENGINE_SWAGGER,
                            "OpenAPI-derived endpoint live (spec abuse)",
                            "high",
                            "T1190",
                            &format!(
                                "Spec at {} enumerated {} → live HTTP {} ({}B) — documented attack surface confirmed.",
                                hit.final_url, path, probe.status, probe.body.len()
                            ),
                            target,
                            &["api_mass_assignment", "idor_advanced"],
                            &["pipeline_to_runtime_risk"],
                            json!({"spec_url": hit.final_url, "abused_path": path, "status": probe.status}),
                        ));
                    }
                }
            }
        }
    }

    if flags.spec_exposed && flags.unauthenticated_spec && flags.sensitive_operations {
        findings.push(web_finding_sync(
            ENGINE_SWAGGER,
            "Toxic chain: unauth OpenAPI + sensitive operations",
            "critical",
            "T1190",
            &format!(
                "Live OpenAPI fusion: spec public without securitySchemes and documents admin/token/delete operations ({} vectors, {} synthetic).",
                total_vectors, total_synthetic
            ),
            target,
            &["api_gateway_bypass", "cors_misconfiguration"],
            &["risk_superposition_collapse", "identity_attack_chain"],
            json!({"toxic_chain": true, "categories": categories_hit}),
        ));
    }

    if flags.spec_exposed && flags.ui_exposed {
        findings.push(web_finding_sync(
            ENGINE_SWAGGER,
            "Toxic chain: spec + Swagger UI interactive abuse",
            "critical",
            "T1190",
            "OpenAPI document and Swagger UI both reachable — interactive API execution from browser.",
            target,
            &["cors_misconfiguration", "clickjacking_engine"],
            &["external_exposure_supreme"],
            json!({"toxic_chain": true, "ui_spec": true}),
        ));
    }

    if flags.synthetic_hit && flags.followup_live {
        findings.push(web_finding_sync(
            ENGINE_SWAGGER,
            "Toxic chain: synthetic spec path → live endpoint abuse",
            "critical",
            "T1190",
            &format!(
                "Zero-day synthesis: runtime-generated OpenAPI path yielded spec and {followup_probed} follow-up probes confirmed live routes.",
            ),
            target,
            &["graphql_deep_attack", "api_rate_limit_bypass"],
            &["threat_surface_intelligence_fusion"],
            json!({"toxic_chain": true, "synthetic_abuse": true}),
        ));
    }

    if findings.is_empty() {
        empty_ok(ENGINE_SWAGGER, target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!(
                "{ENGINE_SWAGGER}: {n} finding(s) vectors={total_vectors} synthetic={total_synthetic} followups={followup_probed}"
            ),
        )
    }
}

#[derive(Default)]
struct SwaggerAbuseFlags {
    spec_exposed: bool,
    ui_exposed: bool,
    auth_schemes_leaked: bool,
    unauthenticated_spec: bool,
    sensitive_operations: bool,
    synthetic_hit: bool,
    large_surface: bool,
    followup_live: bool,
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
fn cache_path_normalization_urls(base: &str) -> Vec<String> {
    let root = base.trim_end_matches('/');
    vec![
        format!("{root}/..;/"),
        format!("{root}/%2e%2e/"),
        format!("{root}/..%2f"),
        format!("{root}/.;/"),
        format!("{root}//admin"),
        format!("{root}/api;/admin"),
        format!("{root}/static/..%2fadmin"),
        format!("{root}/%252e%252e/admin"),
    ]
}

fn cache_probe_urls(target: &str, ctx: &EngineRunContext) -> Vec<String> {
    let root = normalize_url(target);
    let mut urls = vec![root.clone()];
    for p in &ctx.discovered_paths {
        if !p.contains('?') {
            urls.push(join_url(&root, p));
        }
    }
    if let Some(bus) = ctx.intelligence_bus.as_ref() {
        for art in bus.snapshot() {
            if art.proof.starts_with("http_surface_") || art.proof.starts_with("graphql_") {
                urls.push(art.source_url.clone());
            }
        }
    }
    for norm in cache_path_normalization_urls(&root) {
        urls.push(norm);
    }
    urls.sort();
    urls.dedup();
    urls
}

pub async fn run_web_cache_poison_adv_result(target: &str) -> EngineResult {
    run_web_cache_poison_adv_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_web_cache_poison_adv_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let host = extract_host(target);
    let urls = cache_probe_urls(target, ctx);
    let mut findings: Vec<Value> = Vec::new();
    let mut flags = CachePoisonFlags::default();
    let mut total_vectors = 0usize;
    let mut total_synthetic = 0usize;
    let mut categories_hit: Vec<String> = Vec::new();

    for url in &urls {
        let baseline = http_get(&client, url).await;
        let base_body_len = baseline.as_ref().map(|p| p.body.len()).unwrap_or(0);
        let base_status = baseline.as_ref().map(|p| p.status).unwrap_or(0);

        if let Some(p) = baseline.as_ref() {
            let cache_status = header_value(&p.headers, "x-cache").unwrap_or_default();
            let cdn = header_value(&p.headers, "via").unwrap_or_default();
            let age = header_value(&p.headers, "age").unwrap_or_default();
            let cf_cache = header_value(&p.headers, "cf-cache-status").unwrap_or_default();
            let x_served = header_value(&p.headers, "x-served-by").unwrap_or_default();
            let vary = header_value(&p.headers, "vary").unwrap_or_default();
            let vary_low = vary.to_ascii_lowercase();
            if (cache_status.contains("HIT")
                || !age.is_empty()
                || !cf_cache.is_empty()
                || !x_served.is_empty()
                || cdn.contains("cloudfront")
                || cdn.contains("varnish")
                || cdn.contains("akamai")
                || cdn.contains("fastly")
                || cdn.contains("cloudflare"))
                && !vary_low.contains("cookie")
                && !vary_low.contains("authorization")
                && !vary_low.contains("origin")
            {
                flags.cdn_weak_vary = true;
                findings.push(web_finding_sync(
                    ENGINE_CACHE_POISON,
                    "CDN cache without per-user Vary",
                    "medium",
                    "T1185",
                    &format!(
                        "x-cache='{cache_status}', cf-cache='{cf_cache}', age='{age}', via='{cdn}', vary='{vary}' on {} — unkeyed input may poison shared cache.",
                        p.final_url
                    ),
                    target,
                    &["api_gateway_bypass", "cors_misconfiguration"],
                    &["external_exposure_supreme"],
                    json!({"endpoint": p.final_url, "via": cdn, "vary": vary}),
                ));
            }
        }

        let (vectors, mut stats) = synthesize_cache_poison_vectors(&host, url, ctx);
        total_vectors += stats.vectors_generated;
        total_synthetic += stats.synthetic_generated;
        stats.vectors_probed = vectors.len();

        let hits = probe_cache_poison_vectors_concurrent(
            &client,
            url,
            vectors,
            base_status,
            base_body_len,
        )
        .await;

        for hit in hits {
            flags.header_poison = true;
            if hit.vector.synthetic {
                flags.synthetic_zero_day = true;
            }
            match hit.vector.transport {
                CachePoisonTransport::ParamGet => flags.param_unkeyed = true,
                CachePoisonTransport::DualHeaderGet | CachePoisonTransport::TripleHeaderGet => {
                    flags.dual_stack_poison = true
                }
                CachePoisonTransport::MethodOverridePost => flags.method_poison = true,
                CachePoisonTransport::HeaderHead => flags.head_poison = true,
                _ => {}
            }
            if hit.vector.category == "accept_unkeyed" {
                flags.accept_unkeyed = true;
            }
            if hit.vector.category == "fat_get_truncation" {
                flags.fat_get_poison = true;
            }
            if !categories_hit.iter().any(|c| c == hit.vector.category) {
                categories_hit.push(hit.vector.category.to_string());
            }
            stats.categories_hit.insert(hit.vector.category);

            if let Some(bus) = ctx.intelligence_bus.as_ref() {
                bus.publish_http_surface(
                    "cache_poison_vector",
                    &hit.vector.key,
                    &hit.final_url,
                    ENGINE_CACHE_POISON,
                    if hit.vector.synthetic {
                        "http_surface_cache_poison_synthetic"
                    } else {
                        "http_surface_cache_poison_catalog"
                    },
                );
            }

            let severity = if hit.vector.synthetic && hit.reflected {
                "critical"
            } else if hit.reflected {
                "high"
            } else {
                "medium"
            };

            findings.push(web_finding_sync(
                ENGINE_CACHE_POISON,
                &format!(
                    "Cache poison [{}] {} → {}",
                    hit.vector.category,
                    if hit.vector.synthetic {
                        "synthetic zero-day vector"
                    } else {
                        "catalog vector"
                    },
                    hit.vector.key
                ),
                severity,
                "T1185",
                &format!(
                    "Baseline HTTP {base_status}({base_body_len}B) vs {} (synthetic={}) → HTTP {}({}B) reflected={} delta={}B on {}.",
                    hit.vector.key,
                    hit.vector.synthetic,
                    hit.status,
                    hit.body_len,
                    hit.reflected,
                    hit.size_delta,
                    hit.final_url
                ),
                target,
                &["api_gateway_bypass", "graphql_deep_attack", "http_parameter_pollution"],
                &["risk_superposition_collapse", "external_exposure_supreme"],
                json!({
                    "category": hit.vector.category,
                    "synthetic": hit.vector.synthetic,
                    "transport": format!("{:?}", hit.vector.transport),
                    "key": hit.vector.key,
                    "canary": hit.vector.canary,
                    "endpoint": hit.final_url,
                    "reflected": hit.reflected
                }),
            ));
        }
    }

    if flags.cdn_weak_vary && flags.header_poison {
        findings.push(web_finding_sync(
            ENGINE_CACHE_POISON,
            "Toxic chain: CDN weak Vary + live cache poison hit",
            "critical",
            "T1185",
            &format!(
                "Live cache fusion: shared CDN without auth/cookie Vary + {} poison vectors probed ({} synthetic) across {} categories — mass user poisoning chain.",
                total_vectors, total_synthetic, categories_hit.len()
            ),
            target,
            &["cors_misconfiguration", "api_gateway_bypass", "api_rate_limit_bypass"],
            &["risk_superposition_collapse", "external_exposure_supreme"],
            json!({
                "toxic_chain": true,
                "vectors_probed": total_vectors,
                "synthetic_vectors": total_synthetic,
                "categories": categories_hit
            }),
        ));
    }

    if flags.synthetic_zero_day && flags.dual_stack_poison {
        findings.push(web_finding_sync(
            ENGINE_CACHE_POISON,
            "Toxic chain: runtime dual-stack synthetic cache poison",
            "critical",
            "T1185",
            "Zero-day synthesis: dual/triple header stacks computed from target host + intel bus altered cacheable responses — novel unkeyed input family.",
            target,
            &["api_gateway_bypass", "web_cache_poison_adv"],
            &["threat_surface_intelligence_fusion"],
            json!({"toxic_chain": true, "synthetic_dual_stack": true}),
        ));
    }

    if findings.is_empty() {
        empty_ok(ENGINE_CACHE_POISON, target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!(
                "{ENGINE_CACHE_POISON}: {n} finding(s) vectors={total_vectors} synthetic={total_synthetic} categories={}",
                categories_hit.len()
            ),
        )
    }
}

#[derive(Default)]
struct CachePoisonFlags {
    cdn_weak_vary: bool,
    header_poison: bool,
    param_unkeyed: bool,
    accept_unkeyed: bool,
    dual_stack_poison: bool,
    fat_get_poison: bool,
    synthetic_zero_day: bool,
    method_poison: bool,
    head_poison: bool,
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
fn rate_limit_probe_urls(target: &str, ctx: &EngineRunContext) -> Vec<String> {
    let root = normalize_url(target);
    let mut urls = vec![root.clone()];
    for p in &ctx.discovered_paths {
        urls.push(join_url(&root, p));
    }
    if let Some(bus) = ctx.intelligence_bus.as_ref() {
        for art in bus.snapshot() {
            if art.proof.starts_with("graphql_")
                || art.proof.starts_with("http_surface_")
                || art.kind.contains("gateway")
            {
                urls.push(art.source_url.clone());
            }
        }
    }
    urls.sort();
    urls.dedup();
    urls
}

fn rate_limit_spoof_ips() -> [&'static str; 9] {
    [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
        "10.0.0.4",
        "10.0.0.5",
        "192.168.1.10",
        "172.16.0.8",
        "203.0.113.7",
        "198.51.100.42",
    ]
}

async fn rate_limit_burst_429(
    client: &reqwest::Client,
    url: &str,
    headers: &[(&str, &str)],
    count: u32,
) -> (u32, u32) {
    let mut sent = 0u32;
    let mut limited = 0u32;
    for _ in 0..count {
        let probe = if headers.is_empty() {
            http_get(client, url).await
        } else {
            http_get_with_headers(client, url, headers).await
        };
        if let Some(p) = probe {
            sent += 1;
            if p.status == 429 {
                limited += 1;
            }
        }
    }
    (sent, limited)
}

pub async fn run_api_rate_limit_bypass_result(target: &str) -> EngineResult {
    run_api_rate_limit_bypass_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_api_rate_limit_bypass_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let urls = rate_limit_probe_urls(target, ctx);
    let auth_pairs = graphql_auth_header_pairs(&ctx.job_params);
    let auth_refs = auth_pairs_as_refs(&auth_pairs);
    let has_auth = !auth_pairs.is_empty();
    let mut findings: Vec<Value> = Vec::new();
    let mut flags = RateLimitProbeFlags::default();

    for url in &urls {
        let (baseline_sent, baseline_limited) = rate_limit_burst_429(&client, url, &[], 12).await;
        if baseline_limited > 0 {
            flags.baseline_429 = true;
        }

        for (i, ip) in rate_limit_spoof_ips().iter().enumerate() {
            let spoof_hdrs = [
                ("X-Forwarded-For", *ip),
                ("X-Real-IP", *ip),
                ("Client-IP", *ip),
                ("X-Originating-IP", *ip),
                ("True-Client-IP", *ip),
                ("CF-Connecting-IP", *ip),
            ];
            if let Some(p) = http_get_with_headers(&client, url, &spoof_hdrs).await {
                if p.status == 429 {
                    flags.spoof_still_limited = true;
                }
                if i > 3 && p.status == 200 && baseline_limited > 0 {
                    flags.ip_spoof_bypass = true;
                    if let Some(bus) = ctx.intelligence_bus.as_ref() {
                        bus.publish_http_surface(
                            "rate_limit_ip_spoof_bypass",
                            ip,
                            &p.final_url,
                            ENGINE_RATE_LIMIT,
                            "http_surface_rate_limit_ip_spoof",
                        );
                    }
                    findings.push(web_finding_sync(
                        ENGINE_RATE_LIMIT,
                        "Rate limit bypass via X-Forwarded-For rotation",
                        "high",
                        "T1499.003",
                        &format!(
                            "Baseline burst hit {baseline_limited}×429 but rotating X-Forwarded-For ({ip}) returns HTTP 200 on {} — per-IP limits are spoofable.",
                            p.final_url
                        ),
                        target,
                        &["api_gateway_bypass", "zero_trust_bypass"],
                        &["risk_superposition_collapse"],
                        json!({"endpoint": p.final_url, "spoof_ip": ip, "baseline_429": baseline_limited}),
                    ));
                    break;
                }
            }
        }

        if baseline_sent > 0 && baseline_limited == 0 {
            flags.no_limit_observed = true;
            findings.push(web_finding_sync(
                ENGINE_RATE_LIMIT,
                "No 429 across baseline burst",
                "medium",
                "T1499.003",
                &format!(
                    "Sent {baseline_sent} baseline requests to {url} without HTTP 429 — verify per-user/API-key throttles."
                ),
                target,
                &["graphql_deep_attack"],
                &["external_exposure_supreme"],
                json!({"endpoint": url, "baseline_sent": baseline_sent}),
            ));
        }

        if has_auth {
            let (auth_sent, auth_limited) =
                rate_limit_burst_429(&client, url, &auth_refs, 8).await;
            if baseline_limited > 0 && auth_limited == 0 && auth_sent > 0 {
                flags.auth_differential = true;
                findings.push(web_finding_sync(
                    ENGINE_RATE_LIMIT,
                    "Auth differential: credentialed burst evades rate limit",
                    "high",
                    "T1499.003",
                    &format!(
                        "Unauthenticated burst hit {baseline_limited}×429 but authenticated burst on {url} returned 0×429 — throttle keys on session/API-key only."
                    ),
                    target,
                    &["jwt_advanced_attack", "mfa_bypass_engine"],
                    &["identity_attack_chain"],
                    json!({"endpoint": url, "auth_sent": auth_sent}),
                ));
            }
        }

        let case_url = if url.contains("/api/") {
            url.replace("/api/", "/API/")
        } else {
            format!("{url}?_={}", Instant::now().elapsed().as_nanos())
        };
        if case_url != *url {
            if let (Some(base_p), Some(alt_p)) = (
                http_get(&client, url).await,
                http_get(&client, &case_url).await,
            ) {
                if base_p.status == 429 && alt_p.status < 400 {
                    flags.case_path_bypass = true;
                    findings.push(web_finding_sync(
                        ENGINE_RATE_LIMIT,
                        "Rate limit bypass via path/query normalization",
                        "high",
                        "T1499.003",
                        &format!(
                            "{url} → HTTP 429 but variant {case_url} → HTTP {} — ACL normalizes differently.",
                            alt_p.status
                        ),
                        target,
                        &["api_gateway_bypass"],
                        &[],
                        json!({"base": url, "variant": case_url}),
                    ));
                }
            }
        }

        if url.to_ascii_lowercase().contains("graphql") {
            let batch = json!([
                {"query": "{__typename}"},
                {"query": "{__typename}"},
                {"query": "{__typename}"},
                {"query": "{__typename}"},
                {"query": "{__typename}"}
            ]);
            let mut batch_limited = 0u32;
            for _ in 0..6 {
                if let Some(p) = http_post_json(&client, url, &batch).await {
                    if p.status == 429 {
                        batch_limited += 1;
                    } else if p.status >= 200 && p.status < 300 && baseline_limited > 0 {
                        flags.graphql_batch_bypass = true;
                        findings.push(web_finding_sync(
                            ENGINE_RATE_LIMIT,
                            "GraphQL batching evades per-request rate limit",
                            "high",
                            "T1499.003",
                            &format!(
                                "Single-query burst hit {baseline_limited}×429 but batched POST on {url} still returns HTTP {} — pairs with graphql_deep_attack.",
                                p.status
                            ),
                            target,
                            &["graphql_deep_attack"],
                            &["risk_superposition_collapse"],
                            json!({"endpoint": url, "batch_size": 5}),
                        ));
                        break;
                    }
                }
            }
            if batch_limited == 0 && flags.graphql_batch_bypass {
                if let Some(bus) = ctx.intelligence_bus.as_ref() {
                    bus.publish_http_surface(
                        "rate_limit_graphql_batch",
                        url,
                        url,
                        ENGINE_RATE_LIMIT,
                        "http_surface_rate_limit_graphql_batch",
                    );
                }
            }
        }

        let header_bypass_hdrs = [
            ("X-Original-URL", "/"),
            ("X-Forwarded-Host", "127.0.0.1"),
            ("X-Request-Id", "bypass-probe"),
        ];
        if baseline_limited > 0 {
            if let Some(p) = http_get_with_headers(&client, url, &header_bypass_hdrs).await {
                if p.status < 400 && p.status != 429 {
                    flags.header_bypass = true;
                    findings.push(web_finding_sync(
                        ENGINE_RATE_LIMIT,
                        "Rate limit bypass via gateway header override",
                        "high",
                        "T1499.003",
                        &format!(
                            "Baseline 429 on {url} but X-Original-URL/X-Forwarded-Host probe → HTTP {} — edge throttle bypass.",
                            p.status
                        ),
                        target,
                        &["api_gateway_bypass"],
                        &["risk_superposition_collapse"],
                        json!({"endpoint": p.final_url}),
                    ));
                }
            }
        }
    }

    if flags.baseline_429 && (flags.ip_spoof_bypass || flags.graphql_batch_bypass) {
        findings.push(web_finding_sync(
            ENGINE_RATE_LIMIT,
            "Toxic chain: rate limit present but bypass vectors live",
            "critical",
            "T1499.003",
            &format!(
                "Live throttle fusion: baseline 429, ip_spoof={} graphql_batch={} header={} — DoS/brute-force amplification chain with graphql_deep_attack.",
                flags.ip_spoof_bypass, flags.graphql_batch_bypass, flags.header_bypass
            ),
            target,
            &["graphql_deep_attack", "api_gateway_bypass", "cors_misconfiguration"],
            &["risk_superposition_collapse", "external_exposure_supreme"],
            json!({"toxic_chain": true}),
        ));
    }

    if findings.is_empty() {
        empty_ok(ENGINE_RATE_LIMIT, target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!(
                "{ENGINE_RATE_LIMIT}: {n} live finding(s) (spoof={} batch={} auth_diff={})",
                flags.ip_spoof_bypass, flags.graphql_batch_bypass, flags.auth_differential
            ),
        )
    }
}

#[derive(Default)]
struct RateLimitProbeFlags {
    baseline_429: bool,
    ip_spoof_bypass: bool,
    spoof_still_limited: bool,
    no_limit_observed: bool,
    auth_differential: bool,
    case_path_bypass: bool,
    graphql_batch_bypass: bool,
    header_bypass: bool,
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
fn gateway_bypass_paths() -> Vec<&'static str> {
    vec![
        "/api/../admin",
        "/api/v1/../internal",
        "/%2e%2e/admin",
        "/api/..;/admin",
        "/v1/api/../../admin",
        "/api/internal",
        "/backend/api",
        "/_gateway_bypass_probe",
        "/api/v2/users/../admin",
        "/api;/admin",
        "/api%2f..%2fadmin",
    ]
}

fn gateway_dynamic_paths(ctx: &EngineRunContext) -> Vec<String> {
    let mut out = Vec::new();
    for p in &ctx.discovered_paths {
        let pl = p.to_ascii_lowercase();
        if pl.contains("api") || pl.contains("admin") || pl.contains("internal") {
            out.push(format!("{p}/../admin"));
            out.push(format!("{p}/..;/internal"));
        }
    }
    if let Some(bus) = ctx.intelligence_bus.as_ref() {
        for art in bus.snapshot() {
            if art.kind.contains("graphql") || art.source_url.contains("/api") {
                let u = art.source_url.trim_end_matches('/');
                out.push(format!("{u}/../admin"));
                out.push(format!("{u}/..;/internal"));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn gateway_vendor_signal(headers: &[(String, String)]) -> Option<&'static str> {
    let server = header_value(headers, "server")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if server.contains("kong") {
        return Some("kong");
    }
    if server.contains("apigee") {
        return Some("apigee");
    }
    if server.contains("envoy") {
        return Some("envoy");
    }
    if header_value(headers, "x-amz-apigw-id").is_some() {
        return Some("aws_api_gateway");
    }
    if header_value(headers, "x-azure-ref").is_some() {
        return Some("azure_api_management");
    }
    if header_value(headers, "x-envoy-upstream-service-time").is_some() {
        return Some("envoy_mesh");
    }
    if header_value(headers, "x-kong-upstream-latency").is_some() {
        return Some("kong");
    }
    None
}

pub async fn run_api_gateway_bypass_result(target: &str) -> EngineResult {
    run_api_gateway_bypass_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_api_gateway_bypass_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let auth_pairs = graphql_auth_header_pairs(&ctx.job_params);
    let auth_refs = auth_pairs_as_refs(&auth_pairs);
    let has_auth = !auth_pairs.is_empty();
    let mut findings: Vec<Value> = Vec::new();
    let mut flags = GatewayProbeFlags::default();

    if let Some(p) = http_get(&client, &base).await {
        if let Some(vendor) = gateway_vendor_signal(&p.headers) {
            flags.gateway_detected = true;
            flags.vendor = Some(vendor);
            if let Some(bus) = ctx.intelligence_bus.as_ref() {
                bus.publish_http_surface(
                    "api_gateway_vendor",
                    vendor,
                    &p.final_url,
                    ENGINE_GATEWAY,
                    "http_surface_gateway_vendor",
                );
            }
            findings.push(web_finding_sync(
                ENGINE_GATEWAY,
                "API gateway / mesh detected",
                "info",
                "T1190",
                &format!(
                    "Vendor={vendor} on {} (HTTP {}) — path normalization and header override probes executed.",
                    p.final_url, p.status
                ),
                target,
                &["api_rate_limit_bypass", "zero_trust_bypass"],
                &["external_exposure_supreme"],
                json!({"vendor": vendor, "endpoint": p.final_url}),
            ));
        }
    }

    let static_paths = gateway_bypass_paths();
    let probes =
        probe_paths_concurrent(&client, &base, &static_paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        let body_low = p.body.to_ascii_lowercase();
        if p.status == 200
            && !p.body.is_empty()
            && (body_low.contains("admin")
                || body_low.contains("dashboard")
                || body_low.contains("internal"))
        {
            flags.path_bypass = true;
            if let Some(bus) = ctx.intelligence_bus.as_ref() {
                bus.publish_http_surface(
                    "gateway_path_bypass",
                    &p.final_url,
                    &p.final_url,
                    ENGINE_GATEWAY,
                    "http_surface_gateway_path_bypass",
                );
            }
            findings.push(web_finding_sync(
                ENGINE_GATEWAY,
                "Path normalization may bypass gateway ACL",
                "high",
                "T1190",
                &format!(
                    "{} returned HTTP 200 with privileged keywords — gateway path normalization bypass.",
                    p.final_url
                ),
                target,
                &["idor_advanced", "api_mass_assignment", "graphql_deep_attack"],
                &["risk_superposition_collapse", "pipeline_to_runtime_risk"],
                json!({"endpoint": p.final_url, "status": p.status}),
            ));
            break;
        }
    }

    let dynamic = gateway_dynamic_paths(ctx);
    if !dynamic.is_empty() {
        let drefs: Vec<&str> = dynamic.iter().map(String::as_str).collect();
        let dprobes =
            probe_paths_concurrent(&client, &base, &drefs, DEFAULT_PROBE_CONCURRENCY).await;
        for p in dprobes {
            if p.status >= 200 && p.status < 300 && !p.body.is_empty() {
                flags.discovered_path_bypass = true;
                findings.push(web_finding_sync(
                    ENGINE_GATEWAY,
                    "Discovered-path gateway bypass candidate",
                    "high",
                    "T1190",
                    &format!(
                        "Bus/discovered path variant {} → HTTP {} — ACL may not cover intel-derived routes.",
                        p.final_url, p.status
                    ),
                    target,
                    &["graphql_deep_attack", "cors_misconfiguration"],
                    &["threat_surface_intelligence_fusion"],
                    json!({"endpoint": p.final_url, "intel_derived": true}),
                ));
                break;
            }
        }
    }

    let header_overrides: [(&str, &str); 6] = [
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/internal/config"),
        ("X-Forwarded-Prefix", "/api"),
        ("X-Forwarded-Path", "/admin"),
        ("X-Original-Host", "internal.local"),
        ("Forwarded", "for=127.0.0.1;host=internal.local"),
    ];
    for (hdr, val) in header_overrides {
        let probe = if has_auth {
            let mut hdrs = vec![(hdr, val)];
            for (k, v) in &auth_refs {
                hdrs.push((k, v));
            }
            http_get_with_headers(&client, &base, &hdrs).await
        } else {
            http_get_with_headers(&client, &base, &[(hdr, val)]).await
        };
        let Some(p) = probe else { continue };
        let bl = p.body.to_ascii_lowercase();
        if p.status < 500
            && (bl.contains("admin")
                || bl.contains("config")
                || bl.contains("internal")
                || bl.contains("dashboard"))
        {
            flags.header_override = true;
            if let Some(bus) = ctx.intelligence_bus.as_ref() {
                bus.publish_http_surface(
                    "gateway_header_override",
                    hdr,
                    &p.final_url,
                    ENGINE_GATEWAY,
                    "http_surface_gateway_header_override",
                );
            }
            findings.push(web_finding_sync(
                ENGINE_GATEWAY,
                "Gateway routing override via request header",
                "high",
                "T1190",
                &format!(
                    "Header {hdr}={val} altered routing on {} (HTTP {}, auth={has_auth}) — reverse-proxy/gateway bypass.",
                    p.final_url, p.status
                ),
                target,
                &["api_rate_limit_bypass", "zero_trust_bypass"],
                &["risk_superposition_collapse"],
                json!({"header": hdr, "value": val, "endpoint": p.final_url}),
            ));
        }
    }

    if let Some(p) = http_method_with_headers(
        &client,
        "POST",
        &base,
        None,
        &[
            ("X-HTTP-Method-Override", "DELETE"),
            ("Content-Type", "application/json"),
        ],
    )
    .await
    {
        if p.status < 500 && p.status != 405 && p.status != 404 {
            flags.method_override = true;
            findings.push(web_finding_sync(
                ENGINE_GATEWAY,
                "HTTP method override accepted at gateway edge",
                "medium",
                "T1190",
                &format!(
                    "X-HTTP-Method-Override DELETE on {} → HTTP {} — ACL may key only on outer verb.",
                    p.final_url, p.status
                ),
                target,
                &["api_mass_assignment"],
                &[],
                json!({"endpoint": p.final_url, "status": p.status}),
            ));
        }
    }

    if flags.gateway_detected && flags.path_bypass && flags.header_override {
        findings.push(web_finding_sync(
            ENGINE_GATEWAY,
            "Toxic chain: gateway detected + path bypass + header override",
            "critical",
            "T1190",
            "Live gateway fusion: vendor identified, path normalization reaches privileged surface, header override reroutes — full edge-to-backend bypass chain.",
            target,
            &["api_rate_limit_bypass", "graphql_deep_attack", "cors_misconfiguration"],
            &["risk_superposition_collapse", "external_exposure_supreme"],
            json!({"toxic_chain": true, "vendor": flags.vendor}),
        ));
    }

    if findings.is_empty() {
        empty_ok(ENGINE_GATEWAY, target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!(
                "{ENGINE_GATEWAY}: {n} live finding(s) (vendor={:?} path={} header={})",
                flags.vendor, flags.path_bypass, flags.header_override
            ),
        )
    }
}

#[derive(Default)]
struct GatewayProbeFlags {
    gateway_detected: bool,
    vendor: Option<&'static str>,
    path_bypass: bool,
    discovered_path_bypass: bool,
    header_override: bool,
    method_override: bool,
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
