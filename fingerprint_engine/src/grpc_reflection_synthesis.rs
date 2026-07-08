//! gRPC / gRPC-Web / Connect-RPC reflection synthesis — full catalog + live zero-day vectors.
//!
//! Probes use real gRPC length-prefixed frames (including reflection ListServices protobuf)
//! and unique runtime-generated service paths from target shape + intelligence bus.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{http_get_with_headers, http_post_bytes_with_headers, HttpProbe};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use std::collections::HashSet;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const GRPC_EMPTY_FRAME: &[u8] = &[0, 0, 0, 0, 0];
const PROBE_CONCURRENCY: usize = 18;
const MAX_VECTORS_PER_BASE: usize = 200;

/// Reflection: `list_services=""` (oneof field 5, length 0).
const REFLECTION_LIST_SERVICES: &[u8] = &[0x2a, 0x00];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrpcProbeTransport {
    NativeH2,
    GrpcWeb,
    ConnectRpc,
    GatewayGet,
}

#[derive(Clone, Debug)]
pub struct GrpcProbeVector {
    pub category: &'static str,
    pub transport: GrpcProbeTransport,
    pub path: String,
    pub content_type: String,
    pub frame: Vec<u8>,
    pub extra_headers: Vec<(String, String)>,
    pub synthetic: bool,
    pub canary: String,
}

#[derive(Default, Debug)]
pub struct GrpcSynthesisStats {
    pub vectors_generated: usize,
    pub synthetic_generated: usize,
}

#[derive(Clone, Debug)]
pub struct GrpcProbeHit {
    pub vector: GrpcProbeVector,
    pub status: u16,
    pub body_len: usize,
    pub grpc_status: Option<String>,
    pub reflection_likely: bool,
    pub grpc_web: bool,
    pub connect_rpc: bool,
    pub services_hint: bool,
    pub final_url: String,
}

fn synthesis_nonce() -> String {
    let nano = Instant::now().elapsed().as_nanos();
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("wgr{unix:x}{nano:x}")
}

fn wrap_grpc_frame(message: &[u8], compressed: bool) -> Vec<u8> {
    let len = message.len();
    let mut frame = vec![
        if compressed { 1 } else { 0 },
        ((len >> 24) & 0xff) as u8,
        ((len >> 16) & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        (len & 0xff) as u8,
    ];
    frame.extend_from_slice(message);
    frame
}

fn protobuf_string_field(field_num: u32, value: &str) -> Vec<u8> {
    let tag = ((field_num << 3) | 2) as u8;
    let bytes = value.as_bytes();
    let mut out = vec![tag, bytes.len() as u8];
    out.extend_from_slice(bytes);
    out
}

fn reflection_list_services_frame(host: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    if !host.is_empty() {
        msg.extend(protobuf_string_field(1, host));
    }
    msg.extend_from_slice(REFLECTION_LIST_SERVICES);
    wrap_grpc_frame(&msg, false)
}

fn reflection_file_symbol_frame(symbol: &str) -> Vec<u8> {
    let msg = protobuf_string_field(2, symbol);
    wrap_grpc_frame(&msg, false)
}

fn push_vector(
    out: &mut Vec<GrpcProbeVector>,
    category: &'static str,
    transport: GrpcProbeTransport,
    path: &str,
    content_type: &str,
    frame: Vec<u8>,
    headers: Vec<(String, String)>,
    canary: &str,
    synthetic: bool,
) {
    out.push(GrpcProbeVector {
        category,
        transport,
        path: path.to_string(),
        content_type: content_type.to_string(),
        frame,
        extra_headers: headers,
        synthetic,
        canary: canary.to_string(),
    });
}

fn static_grpc_paths() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
            "reflection_v1alpha",
        ),
        (
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
            "reflection_v1",
        ),
        ("/grpc.health.v1.Health/Check", "health_check"),
        ("/grpc.health.v1.Health/Watch", "health_watch"),
        ("/grpc.health.v1.Health/List", "health_list"),
        (
            "/envoy.service.auth.v3.Authorization/Check",
            "envoy_auth",
        ),
        (
            "/envoy.service.ratelimit.v3.RateLimitService/ShouldRateLimit",
            "envoy_ratelimit",
        ),
        (
            "/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources",
            "envoy_adsv3",
        ),
        (
            "/istio.v1.auth.IstioCertificateService/CreateCertificate",
            "istio_cert",
        ),
        (
            "/xds.service.orca.v3.OpenRcaService/StreamCoreMetrics",
            "xds_orca",
        ),
        ("/grpc.channelz.v1.Channelz/GetTopChannels", "channelz"),
        ("/grpc.binlog.v1.Binlog/Query", "binlog"),
        ("/google.bytestream.ByteStream/Read", "bytestream"),
        (
            "/google.longrunning.Operations/GetOperation",
            "longrunning",
        ),
        ("/grpc.testing.TestService/UnaryCall", "grpc_testing"),
        ("/etcdserverpb.KV/Range", "etcd_kv"),
        ("/etcdserverpb.Watch/Watch", "etcd_watch"),
        (
            "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
            "otel_metrics",
        ),
        (
            "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
            "otel_trace",
        ),
        ("/prometheus.Remote/Write", "prometheus_remote"),
        ("/connectrpc.health.v1.Health/Check", "connect_health"),
        (
            "/connectrpc.reflection.v1.ServerReflection/ServerReflectionInfo",
            "connect_reflection",
        ),
        ("/buf.validate.ValidateService/Validate", "buf_validate"),
        ("/kubernetes.Kubernetes/Watch", "k8s_watch"),
        ("/api.v1.CoreService/Status", "generic_api"),
    ]
}

fn static_content_types() -> Vec<(&'static str, &'static str)> {
    vec![
        ("application/grpc", "grpc_native"),
        ("application/grpc+proto", "grpc_proto"),
        ("application/grpc-web", "grpc_web"),
        ("application/grpc-web+proto", "grpc_web_proto"),
        ("application/grpc-web-text", "grpc_web_text"),
        ("application/connect+proto", "connect_proto"),
        ("application/connect+json", "connect_json"),
    ]
}

fn static_gateway_paths() -> Vec<(&'static str, &'static str)> {
    vec![
        ("/grpc", "gateway_root"),
        ("/api/grpc", "gateway_api"),
        ("/grpc-web", "gateway_web"),
        ("/rpc", "gateway_rpc"),
        ("/api/rpc", "gateway_api_rpc"),
        ("/v1/grpc", "gateway_v1"),
        ("/services", "gateway_services"),
        ("/twirp", "twirp_root"),
    ]
}

fn base_grpc_headers(content_type: &str, canary: &str) -> Vec<(String, String)> {
    let mut h = vec![
        ("TE".into(), "trailers".into()),
        ("X-Weissman-Grpc-Canary".into(), canary.to_string()),
        ("User-Agent".into(), "weissman-grpc-probe/1.0".into()),
    ];
    if !content_type.is_empty() {
        h.insert(0, ("Content-Type".into(), content_type.to_string()));
    }
    h
}

fn static_catalog(host: &str, canary: &str) -> Vec<GrpcProbeVector> {
    let mut out = Vec::new();
    let frames: [(&str, Vec<u8>); 4] = [
        ("empty", GRPC_EMPTY_FRAME.to_vec()),
        ("list_services", reflection_list_services_frame("")),
        ("list_services_host", reflection_list_services_frame(host)),
        (
            "file_symbol",
            reflection_file_symbol_frame("grpc.reflection.v1.ServerReflection"),
        ),
    ];

    for (path, cat) in static_grpc_paths() {
        for (frame_name, frame) in &frames {
            if cat.contains("health") && *frame_name == "file_symbol" {
                continue;
            }
            if !cat.contains("reflection") && !cat.contains("connect_reflection") {
                if *frame_name == "list_services" || *frame_name == "list_services_host" {
                    continue;
                }
            }
            let ct = if cat.contains("connect") {
                "application/connect+proto"
            } else {
                "application/grpc"
            };
            let transport = if ct.contains("connect") {
                GrpcProbeTransport::ConnectRpc
            } else {
                GrpcProbeTransport::NativeH2
            };
            let mut hdrs = base_grpc_headers(ct, canary);
            if transport == GrpcProbeTransport::ConnectRpc {
                hdrs.push(("Connect-Protocol-Version".into(), "1".into()));
            }
            push_vector(
                &mut out,
                cat,
                transport,
                path,
                ct,
                frame.clone(),
                hdrs,
                canary,
                false,
            );
        }
    }

    let reflection_only = [
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    ];
    for path in reflection_only {
        for (ct, ct_cat) in static_content_types() {
            let transport = if ct.contains("connect") {
                GrpcProbeTransport::ConnectRpc
            } else if ct.contains("grpc-web") {
                GrpcProbeTransport::GrpcWeb
            } else {
                GrpcProbeTransport::NativeH2
            };
            let mut hdrs = base_grpc_headers(ct, canary);
            if transport == GrpcProbeTransport::ConnectRpc {
                hdrs.push(("Connect-Protocol-Version".into(), "1".into()));
            }
            push_vector(
                &mut out,
                ct_cat,
                transport,
                path,
                ct,
                reflection_list_services_frame(host),
                hdrs,
                canary,
                false,
            );
        }
    }

    for (path, cat) in static_gateway_paths() {
        push_vector(
            &mut out,
            cat,
            GrpcProbeTransport::GatewayGet,
            path,
            "",
            Vec::new(),
            vec![("Accept".into(), "application/grpc-web".into())],
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
        format!("/com.weissman.{slug}.synth.v1.Synth{nonce}/Ping"),
        "synthetic_service",
    ));
    out.push((format!("/{slug}.v1.API/Check"), "synthetic_service"));
    out.push((
        format!("/weissman.{nonce}.v1.ProbeService/Reflect"),
        "synthetic_service",
    ));

    for p in ctx.discovered_paths.iter().take(16) {
        let pl = p.trim().trim_start_matches('/');
        if pl.is_empty() {
            continue;
        }
        let seg = pl.split('/').next().unwrap_or("api");
        out.push((
            format!("/{seg}.v1.DiscoveredService/Check"),
            "synthetic_intel_path",
        ));
        out.push((
            format!("{p}/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"),
            "synthetic_intel_path",
        ));
        if pl.contains("grpc") {
            out.push((p.clone(), "synthetic_intel_path"));
        }
    }

    if let Some(bus) = ctx.intelligence_bus.as_ref() {
        for art in bus.snapshot().iter().take(12) {
            let marker = art
                .source_url
                .split('/')
                .filter(|s| !s.is_empty())
                .next_back()
                .unwrap_or("api")
                .chars()
                .take(20)
                .collect::<String>();
            out.push((
                format!("/{}.v1.BusSurface/Check", marker.replace('-', "_")),
                "synthetic_bus_artifact",
            ));
            if let Ok(u) = url::Url::parse(&art.source_url) {
                let path = u.path();
                if path.len() > 1 {
                    out.push((
                        format!(
                            "{path}/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
                        ),
                        "synthetic_bus_artifact",
                    ));
                }
            }
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
            "authorization".into(),
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
) -> Vec<GrpcProbeVector> {
    let mut out = Vec::new();
    let auth = auth_header_pairs(&ctx.job_params);

    for (path, cat) in synthetic_paths(host, nonce, ctx) {
        for (ct, transport) in [
            ("application/grpc", GrpcProbeTransport::NativeH2),
            ("application/grpc-web+proto", GrpcProbeTransport::GrpcWeb),
            ("application/connect+proto", GrpcProbeTransport::ConnectRpc),
        ] {
            let mut hdrs = base_grpc_headers(ct, canary);
            if transport == GrpcProbeTransport::ConnectRpc {
                hdrs.push(("Connect-Protocol-Version".into(), "1".into()));
            }
            for (k, v) in &auth {
                hdrs.push((k.clone(), v.clone()));
            }
            push_vector(
                &mut out,
                cat,
                transport,
                &path,
                ct,
                reflection_list_services_frame(host),
                hdrs,
                canary,
                true,
            );
        }
    }

    for payload in ctx.memory_payloads.iter().take(5) {
        if payload.trim().is_empty() {
            continue;
        }
        let path = "/weissman.memory.v1.Replay/Exec".to_string();
        let mut hdrs = base_grpc_headers("application/grpc", canary);
        hdrs.push(("X-Weissman-Memory-Replay".into(), payload.clone()));
        push_vector(
            &mut out,
            "synthetic_memory_payload",
            GrpcProbeTransport::NativeH2,
            &path,
            "application/grpc",
            wrap_grpc_frame(payload.as_bytes(), false),
            hdrs,
            canary,
            true,
        );
    }

    for i in 0..6u8 {
        let path = format!(
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo?wgr={nonce}&n={i}"
        );
        push_vector(
            &mut out,
            "synthetic_encoding",
            GrpcProbeTransport::NativeH2,
            &path,
            "application/grpc",
            reflection_list_services_frame(&format!("{host}-{i}")),
            base_grpc_headers("application/grpc", canary),
            canary,
            true,
        );
    }

    out
}

#[must_use]
pub fn synthesize_grpc_reflection_vectors(
    host: &str,
    ctx: &EngineRunContext,
) -> (Vec<GrpcProbeVector>, GrpcSynthesisStats) {
    let nonce = synthesis_nonce();
    let canary = format!("canary-{nonce}");
    let synthetic = synthetic_vectors(host, ctx, &nonce, &canary);
    let syn_count = synthetic.len();
    let mut static_v = static_catalog(host, &canary);
    let mut all = synthetic;
    all.append(&mut static_v);

    let mut seen = HashSet::new();
    all.retain(|v| {
        let k = format!(
            "{}|{}|{}|{:?}",
            v.path, v.content_type, v.canary, v.transport
        );
        seen.insert(k)
    });
    all.truncate(MAX_VECTORS_PER_BASE);
    let generated = all.len();

    (
        all,
        GrpcSynthesisStats {
            vectors_generated: generated,
            synthetic_generated: syn_count.min(generated),
        },
    )
}

#[must_use]
pub fn grpc_response_indicates_service(
    status: u16,
    body: &[u8],
    headers: &[(String, String)],
) -> bool {
    if status == 404 {
        return false;
    }
    if body.len() >= 5 && (body[0] == 0 || body[0] == 1) {
        return true;
    }
    headers.iter().any(|(k, v)| {
        let k = k.to_ascii_lowercase();
        (k == "grpc-status" || k == "content-type")
            && (v.contains("grpc") || v.contains("connect") || k == "grpc-status")
    }) || (200..500).contains(&status) && status != 404
}

#[must_use]
pub fn grpc_reflection_likely(status: u16, body: &[u8], path: &str) -> bool {
    path.contains("ServerReflection")
        && status == 200
        && body.len() > 5
        && (body[0] == 0 || body[0] == 1)
}

#[must_use]
pub fn grpc_services_hint(body: &str) -> bool {
    let bl = body.to_ascii_lowercase();
    bl.contains("servicedescriptor")
        || bl.contains("filedescriptor")
        || bl.contains(".proto")
        || bl.contains("grpc.reflection")
        || bl.contains("list_services")
}

fn grpc_status_header(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("grpc-status"))
        .map(|(_, v)| v.clone())
}

async fn execute_vector(
    h2: &Client,
    h1: &Client,
    base: &str,
    vector: &GrpcProbeVector,
) -> Option<(GrpcProbeVector, HttpProbe)> {
    let url = format!("{}{}", base.trim_end_matches('/'), vector.path);
    let hdrs: Vec<(&str, &str)> = vector
        .extra_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let probe = match vector.transport {
        GrpcProbeTransport::GatewayGet => http_get_with_headers(h1, &url, &hdrs).await,
        GrpcProbeTransport::NativeH2 | GrpcProbeTransport::GrpcWeb | GrpcProbeTransport::ConnectRpc => {
            let client = if vector.transport == GrpcProbeTransport::NativeH2 {
                h2
            } else {
                h1
            };
            http_post_bytes_with_headers(client, &url, &vector.frame, &hdrs).await
        }
    };
    probe.map(|p| (vector.clone(), p))
}

pub fn evaluate_grpc_hit(vector: &GrpcProbeVector, probe: &HttpProbe) -> Option<GrpcProbeHit> {
    let body_bytes = probe.body.as_bytes();
    if !grpc_response_indicates_service(probe.status, body_bytes, &probe.headers) {
        return None;
    }
    let reflection = grpc_reflection_likely(probe.status, body_bytes, &vector.path);
    let ct = vector.content_type.to_ascii_lowercase();
    let grpc_web = ct.contains("grpc-web") || vector.transport == GrpcProbeTransport::GrpcWeb;
    let connect_rpc = ct.contains("connect") || vector.transport == GrpcProbeTransport::ConnectRpc;
    let services_hint = grpc_services_hint(&probe.body) || reflection;
    Some(GrpcProbeHit {
        vector: vector.clone(),
        status: probe.status,
        body_len: probe.body.len(),
        grpc_status: grpc_status_header(&probe.headers),
        reflection_likely: reflection,
        grpc_web,
        connect_rpc,
        services_hint,
        final_url: probe.final_url.clone(),
    })
}

pub async fn probe_grpc_vectors_concurrent(
    h2: &Client,
    h1: &Client,
    base: &str,
    vectors: Vec<GrpcProbeVector>,
) -> Vec<GrpcProbeHit> {
    stream::iter(vectors)
        .map(|v| {
            let h2c = h2.clone();
            let h1c = h1.clone();
            let b = base.to_string();
            async move { execute_vector(&h2c, &h1c, &b, &v).await }
        })
        .buffer_unordered(PROBE_CONCURRENCY)
        .filter_map(|x| async move { x })
        .filter_map(|(vector, probe)| async move { evaluate_grpc_hit(&vector, &probe) })
        .collect()
        .await
}

pub fn grpc_probe_bases(target: &str, ctx: &EngineRunContext) -> Vec<String> {
    let root = target.trim();
    let normalized = if root.starts_with("http://") || root.starts_with("https://") {
        root.to_string()
    } else {
        format!("https://{root}")
    };
    let mut bases = vec![normalized.clone()];
    if normalized.starts_with("https://") {
        bases.push(normalized.replacen("https://", "http://", 1));
    }
    for p in &ctx.discovered_paths {
        if p.starts_with("http") {
            bases.push(p.clone());
        }
    }
    if let Some(bus) = ctx.intelligence_bus.as_ref() {
        for art in bus.snapshot() {
            if art.source_url.starts_with("http") {
                bases.push(art.source_url.clone());
            }
        }
    }
    bases.sort();
    bases.dedup();
    bases
}
