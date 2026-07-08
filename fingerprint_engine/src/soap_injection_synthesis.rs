//! SOAP / WSDL injection synthesis — full catalog + live XML abuse vectors.
//!
//! Hunts WSDL surfaces, probes XXE/SOAPAction/WS-Security injection with runtime canaries,
//! parses WSDL operations, and synthesizes zero-day paths from intelligence bus.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    http_get, http_get_with_headers, http_post_bytes_with_headers, normalize_url, HttpProbe,
};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use std::collections::HashSet;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const MAX_VECTORS_PER_BASE: usize = 260;
const PROBE_CONCURRENCY: usize = 22;
const MAX_WSDL_OPS: usize = 12;
const MAX_WSDL_LOCS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoapProbeTransport {
    GetWsdl,
    PostSoap,
}

#[derive(Clone, Debug)]
pub struct SoapProbeVector {
    pub category: &'static str,
    pub transport: SoapProbeTransport,
    pub path: String,
    pub body: Vec<u8>,
    pub content_type: String,
    pub soap_action: Option<String>,
    pub extra_headers: Vec<(String, String)>,
    pub synthetic: bool,
    pub canary: String,
}

#[derive(Default, Debug)]
pub struct SoapSynthesisStats {
    pub vectors_generated: usize,
    pub synthetic_generated: usize,
}

#[derive(Clone, Debug, Default)]
pub struct WsdlSignal {
    pub is_wsdl: bool,
    pub has_bindings: bool,
    pub has_operations: bool,
    pub has_ws_security: bool,
    pub has_documentation: bool,
    pub operation_estimate: usize,
    pub service_estimate: usize,
}

#[derive(Clone, Debug)]
pub struct SoapInjectionSignal {
    pub xxe_reflected: bool,
    pub entity_error: bool,
    pub soap_fault: bool,
    pub wsse_accepted: bool,
    pub action_reflected: bool,
}

#[derive(Clone, Debug, Default)]
pub struct WsdlExtraction {
    pub operations: Vec<String>,
    pub locations: Vec<String>,
    pub services: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SoapProbeHit {
    pub vector: SoapProbeVector,
    pub status: u16,
    pub body_len: usize,
    pub wsdl: WsdlSignal,
    pub injection: SoapInjectionSignal,
    pub final_url: String,
    pub extraction: WsdlExtraction,
}

#[derive(Clone, Debug)]
pub struct SoapOperationHit {
    pub operation: String,
    pub status: u16,
    pub body_len: usize,
    pub final_url: String,
    pub fault: bool,
}

fn synthesis_nonce() -> String {
    let nano = Instant::now().elapsed().as_nanos();
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("wsp{unix:x}{nano:x}")
}

fn push_vector(
    out: &mut Vec<SoapProbeVector>,
    category: &'static str,
    transport: SoapProbeTransport,
    path: &str,
    body: Vec<u8>,
    content_type: &str,
    soap_action: Option<&str>,
    headers: Vec<(String, String)>,
    canary: &str,
    synthetic: bool,
) {
    out.push(SoapProbeVector {
        category,
        transport,
        path: path.to_string(),
        body,
        content_type: content_type.to_string(),
        soap_action: soap_action.map(str::to_string),
        extra_headers: headers,
        synthetic,
        canary: canary.to_string(),
    });
}

fn static_wsdl_paths() -> Vec<(&'static str, &'static str)> {
    vec![
        ("/services?wsdl", "wsdl_services"),
        ("/ws?wsdl", "wsdl_ws"),
        ("/soap?wsdl", "wsdl_soap"),
        ("/service?wsdl", "wsdl_service"),
        ("/api?wsdl", "wsdl_api"),
        ("/Service.svc?wsdl", "wcf_svc"),
        ("/service.asmx?WSDL", "dotnet_asmx"),
        ("/webservice.asmx?wsdl", "dotnet_webservice"),
        ("/axis2/services/listServices", "axis2_list"),
        ("/axis2/services/version", "axis2_version"),
        ("/axis/services/AdminService?wsdl", "axis_admin"),
        ("/cxf/services?wsdl", "cxf_services"),
        ("/jboss-net/services?wsdl", "jboss_net"),
        ("/ws/services?wsdl", "generic_ws_services"),
        ("/soap/services?wsdl", "soap_services"),
        ("/uapi?wsdl", "uapi_wsdl"),
        ("/api/soap?wsdl", "api_soap_wsdl"),
        ("/api/ws?wsdl", "api_ws_wsdl"),
        ("/backend/soap?wsdl", "backend_soap"),
        ("/internal/ws?wsdl", "internal_wsdl"),
        ("/admin/soap?wsdl", "admin_wsdl"),
        ("/portal/services?wsdl", "portal_wsdl"),
        ("/esb/services?wsdl", "esb_wsdl"),
        ("/bus/services?wsdl", "bus_wsdl"),
        ("/mule/services?wsdl", "mule_wsdl"),
        ("/tibco/services?wsdl", "tibco_wsdl"),
        ("/sap/bc/soap/wsdl", "sap_wsdl"),
        ("/wsdl", "wsdl_root"),
        ("/WSDL", "wsdl_upper"),
        ("/?wsdl", "wsdl_query_root"),
        ("/api/v1/soap?wsdl", "api_v1_soap"),
        ("/api/v2/soap?wsdl", "api_v2_soap"),
        ("/gateway/soap?wsdl", "gateway_soap"),
        ("/rpc/soap?wsdl", "rpc_soap"),
    ]
}

fn static_soap_endpoints() -> Vec<(&'static str, &'static str)> {
    vec![
        ("/soap", "soap_root"),
        ("/ws", "ws_root"),
        ("/services", "services_root"),
        ("/service.asmx", "asmx_root"),
        ("/Service.svc", "svc_root"),
        ("/api/soap", "api_soap"),
        ("/api/ws", "api_ws"),
        ("/backend/soap", "backend_soap_post"),
        ("/axis2/services", "axis2_post"),
        ("/cxf/endpoint", "cxf_endpoint"),
        ("/jms/soap", "jms_soap"),
        ("/esb/soap", "esb_soap"),
    ]
}

fn xxe_envelope(canary: &str, param: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "{canary}">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><{param}>&xxe;</{param}></soap:Body></soap:Envelope>"#
    )
}

fn xxe_parameter_entity(canary: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "data:text/plain,{canary}"><!ENTITY call "%xxe;">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><probe>&call;</probe></soap:Body></soap:Envelope>"#
    )
}

fn nested_entity_probe(canary: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "{canary}"><!ENTITY b "&a;&a;">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><probe>&b;</probe></soap:Body></soap:Envelope>"#
    )
}

fn soap12_envelope(inner: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Body>{inner}</env:Body></env:Envelope>"#
    )
}

fn operation_envelope(op: &str, canary: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><{op}><id>{canary}</id></{op}></soap:Body></soap:Envelope>"#
    )
}

fn wsse_username_envelope(canary: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><soap:Header><wsse:Security><wsse:UsernameToken><wsse:Username>admin</wsse:Username><wsse:Password>{canary}</wsse:Password></wsse:UsernameToken></wsse:Security></soap:Header><soap:Body><probe/></soap:Body></soap:Envelope>"#
    )
}

fn xpath_injection_envelope(canary: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><query>' or '{canary}'='{canary}</query></soap:Body></soap:Envelope>"#
    )
}

fn cdata_envelope(canary: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><![CDATA[{canary}]]></soap:Body></soap:Envelope>"#
    )
}

fn soap_payload_catalog(canary: &str) -> Vec<(&'static str, String, &'static str, Option<&'static str>)> {
    vec![
        ("xxe_doctype", xxe_envelope(canary, "probe"), "text/xml", Some("probe")),
        ("xxe_doctype", xxe_envelope(canary, "request"), "text/xml", Some("urn:probe")),
        (
            "xxe_parameter_entity",
            xxe_parameter_entity(canary),
            "text/xml",
            Some("probe"),
        ),
        (
            "nested_entity",
            nested_entity_probe(canary),
            "text/xml",
            Some("probe"),
        ),
        (
            "soap12_xxe",
            soap12_envelope(&format!("<!DOCTYPE x [<!ENTITY e \"{canary}\">]><probe>&e;</probe>")),
            "application/soap+xml",
            None,
        ),
        (
            "ws_security",
            wsse_username_envelope(canary),
            "text/xml",
            Some("wsse"),
        ),
        (
            "xpath_injection",
            xpath_injection_envelope(canary),
            "text/xml",
            Some("xpath"),
        ),
        ("cdata_wrap", cdata_envelope(canary), "text/xml", Some("cdata")),
        (
            "sql_injection",
            format!(
                r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><login><user>admin' OR '{canary}'='{canary}</user></login></soap:Body></soap:Envelope>"#
            ),
            "text/xml",
            Some("login"),
        ),
    ]
}

fn static_catalog(canary: &str) -> Vec<SoapProbeVector> {
    let mut out = Vec::new();
    for (path, cat) in static_wsdl_paths() {
        push_vector(
            &mut out,
            cat,
            SoapProbeTransport::GetWsdl,
            path,
            Vec::new(),
            "",
            None,
            Vec::new(),
            canary,
            false,
        );
    }
    for (path, ep_cat) in static_soap_endpoints() {
        for (payload_cat, body, ctype, action) in soap_payload_catalog(canary) {
            push_vector(
                &mut out,
                payload_cat,
                SoapProbeTransport::PostSoap,
                path,
                body.into_bytes(),
                ctype,
                action,
                Vec::new(),
                canary,
                false,
            );
            let _ = ep_cat;
        }
        push_vector(
            &mut out,
            "content_type_variant",
            SoapProbeTransport::PostSoap,
            path,
            xxe_envelope(canary, "probe").into_bytes(),
            "application/xml",
            Some("probe"),
            Vec::new(),
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
        format!("/{slug}/services?wsdl"),
        "synthetic_host_slug",
    ));
    out.push((
        format!("/weissman-{nonce}/soap?wsdl"),
        "synthetic_nonce_path",
    ));
    for p in ctx.discovered_paths.iter().take(20) {
        let base = p.trim_end_matches('/');
        if base.is_empty() {
            continue;
        }
        out.push((format!("{base}?wsdl"), "synthetic_intel_path"));
        out.push((format!("{base}/?wsdl"), "synthetic_intel_path"));
        out.push((format!("{base}?WSDL"), "synthetic_intel_path"));
        if !base.contains("wsdl") && !base.contains("WSDL") {
            out.push((format!("{base}?wsdl"), "synthetic_intel_path"));
        }
        for suffix in ["/soap", "/ws", "/services", "/service.asmx"] {
            out.push((format!("{base}{suffix}"), "synthetic_intel_endpoint"));
            out.push((format!("{base}{suffix}?wsdl"), "synthetic_intel_path"));
        }
    }
    if let Some(bus) = ctx.intelligence_bus.as_ref() {
        for art in bus.snapshot().iter().take(14) {
            if let Ok(u) = url::Url::parse(&art.source_url) {
                let path = u.path().trim_end_matches('/').to_string();
                let root = if path.is_empty() { "/api".into() } else { path };
                out.push((format!("{root}?wsdl"), "synthetic_bus_artifact"));
                out.push((format!("{root}/soap"), "synthetic_bus_artifact"));
                if art.proof.contains("gateway") {
                    out.push((format!("{root}/gateway/soap?wsdl"), "synthetic_bus_gateway"));
                }
            }
        }
    }
    for payload in ctx.memory_payloads.iter().take(5) {
        let safe: String = payload
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .take(24)
            .collect();
        if !safe.is_empty() {
            out.push((
                format!("/services/{safe}?wsdl"),
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
) -> Vec<SoapProbeVector> {
    let mut out = Vec::new();
    let auth = auth_header_pairs(&ctx.job_params);
    for (path, cat) in synthetic_paths(host, nonce, ctx) {
        if path.contains("wsdl") || path.contains("WSDL") {
            let mut hdrs = vec![("X-Weissman-Soap-Canary".into(), canary.to_string())];
            for (k, v) in &auth {
                hdrs.push((k.clone(), v.clone()));
            }
            push_vector(
                &mut out,
                cat,
                SoapProbeTransport::GetWsdl,
                &path,
                Vec::new(),
                "",
                None,
                hdrs,
                canary,
                true,
            );
        } else {
            for (payload_cat, body, ctype, action) in soap_payload_catalog(canary) {
                let mut hdrs = vec![("X-Weissman-Soap-Canary".into(), canary.to_string())];
                for (k, v) in &auth {
                    hdrs.push((k.clone(), v.clone()));
                }
                push_vector(
                    &mut out,
                    payload_cat,
                    SoapProbeTransport::PostSoap,
                    &path,
                    body.into_bytes(),
                    ctype,
                    action,
                    hdrs,
                    canary,
                    true,
                );
            }
        }
    }
    for i in 0..10u8 {
        let path = format!("/soap?wsp={nonce}&n={i}");
        push_vector(
            &mut out,
            "synthetic_encoding",
            SoapProbeTransport::GetWsdl,
            &path,
            Vec::new(),
            "",
            None,
            Vec::new(),
            canary,
            true,
        );
    }
    out
}

#[must_use]
pub fn synthesize_soap_injection_vectors(
    host: &str,
    ctx: &EngineRunContext,
) -> (Vec<SoapProbeVector>, SoapSynthesisStats) {
    let nonce = synthesis_nonce();
    let canary = format!("canary-{nonce}");
    let synthetic = synthetic_vectors(host, ctx, &nonce, &canary);
    let syn_count = synthetic.len();
    let mut static_v = static_catalog(&canary);
    let mut all = synthetic;
    all.append(&mut static_v);
    let mut seen = HashSet::new();
    all.retain(|v| {
        let k = format!(
            "{:?}|{}|{}|{:?}",
            v.transport, v.path, v.canary, v.soap_action
        );
        seen.insert(k)
    });
    all.truncate(MAX_VECTORS_PER_BASE);
    let generated = all.len();
    (
        all,
        SoapSynthesisStats {
            vectors_generated: generated,
            synthetic_generated: syn_count.min(generated),
        },
    )
}

#[must_use]
pub fn analyze_wsdl(body: &str) -> WsdlSignal {
    let low = body.to_ascii_lowercase();
    let mut s = WsdlSignal::default();
    s.is_wsdl = low.contains("<wsdl:") || low.contains("<definitions") || low.contains("targetnamespace");
    s.has_bindings = low.contains("<binding") || low.contains("soap:binding");
    s.has_operations = low.contains("operation name=") || low.contains("<operation");
    s.has_ws_security = low.contains("ws-security") || low.contains("wss:security") || low.contains("policy");
    s.has_documentation = low.contains("<documentation") || low.contains("wsdl:documentation");
    s.operation_estimate = body.matches("operation name=").count().min(500);
    s.service_estimate = body.matches("service name=").count().min(100);
    s
}

#[must_use]
pub fn analyze_injection(body: &str, canary: &str) -> SoapInjectionSignal {
    let low = body.to_ascii_lowercase();
    SoapInjectionSignal {
        xxe_reflected: body.contains(canary),
        entity_error: low.contains("entity")
            || low.contains("doctype")
            || low.contains("parseerror")
            || low.contains("xml declaration"),
        soap_fault: low.contains("soap:fault") || low.contains("faultstring") || low.contains("faultcode"),
        wsse_accepted: low.contains("wsse") || low.contains("username token") || low.contains("securitytoken"),
        action_reflected: false,
    }
}

#[must_use]
pub fn extract_wsdl_operations(body: &str) -> Vec<String> {
    let mut ops = Vec::new();
    let mut seen = HashSet::new();
    for marker in ["operation name=\"", "operation name='"] {
        for cap in body.match_indices(marker) {
            let rest = &body[cap.0 + marker.len()..];
            let end = rest.find(['"', '\'']).unwrap_or(0);
            let name = &rest[..end];
            if !name.is_empty() && name.len() < 64 && seen.insert(name.to_string()) {
                ops.push(name.to_string());
                if ops.len() >= MAX_WSDL_OPS {
                    return ops;
                }
            }
        }
    }
    ops
}

#[must_use]
pub fn extract_wsdl_locations(body: &str) -> Vec<String> {
    let mut locs = Vec::new();
    let mut seen = HashSet::new();
    for marker in ["location=\"", "soap:address location=\""] {
        for cap in body.match_indices(marker) {
            let rest = &body[cap.0 + marker.len()..];
            if let Some(end) = rest.find('"') {
                let loc = &rest[..end];
                if (loc.starts_with("http") || loc.starts_with('/'))
                    && seen.insert(loc.to_string())
                {
                    locs.push(loc.to_string());
                    if locs.len() >= MAX_WSDL_LOCS {
                        return locs;
                    }
                }
            }
        }
    }
    locs
}

#[must_use]
pub fn extract_wsdl_services(body: &str) -> Vec<String> {
    let mut services = Vec::new();
    let mut seen = HashSet::new();
    for cap in body.match_indices("service name=\"") {
        let rest = &body[cap.0 + 14..];
        if let Some(end) = rest.find('"') {
            let name = &rest[..end];
            if !name.is_empty() && seen.insert(name.to_string()) {
                services.push(name.to_string());
            }
        }
    }
    services
}

#[must_use]
pub fn extract_full_wsdl(body: &str) -> WsdlExtraction {
    WsdlExtraction {
        operations: extract_wsdl_operations(body),
        locations: extract_wsdl_locations(body),
        services: extract_wsdl_services(body),
    }
}

pub fn evaluate_soap_hit(vector: &SoapProbeVector, probe: &HttpProbe) -> Option<SoapProbeHit> {
    if probe.status == 404 {
        return None;
    }
    let wsdl = analyze_wsdl(&probe.body);
    let injection = analyze_injection(&probe.body, &vector.canary);
    let wsdl_hit = vector.transport == SoapProbeTransport::GetWsdl
        && probe.status == 200
        && wsdl.is_wsdl;
    let inject_hit = vector.transport == SoapProbeTransport::PostSoap
        && (injection.xxe_reflected
            || injection.entity_error
            || injection.soap_fault
            || injection.wsse_accepted
            || probe.body.contains(&vector.canary));
    if !wsdl_hit && !inject_hit {
        return None;
    }
    let extraction = if wsdl_hit {
        extract_full_wsdl(&probe.body)
    } else {
        WsdlExtraction::default()
    };
    Some(SoapProbeHit {
        vector: vector.clone(),
        status: probe.status,
        body_len: probe.body.len(),
        wsdl,
        injection,
        final_url: probe.final_url.clone(),
        extraction,
    })
}

async fn execute_vector(
    client: &Client,
    base: &str,
    vector: &SoapProbeVector,
) -> Option<(SoapProbeVector, HttpProbe)> {
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
    let probe = match vector.transport {
        SoapProbeTransport::GetWsdl => http_get_with_headers(client, &url, &hdrs).await,
        SoapProbeTransport::PostSoap => {
            if !vector.content_type.is_empty() {
                hdrs.push(("Content-Type", vector.content_type.as_str()));
            }
            if let Some(ref a) = vector.soap_action {
                hdrs.push(("SOAPAction", a.as_str()));
            }
            http_post_bytes_with_headers(client, &url, &vector.body, &hdrs).await
        }
    };
    probe.map(|p| (vector.clone(), p))
}

pub async fn probe_soap_vectors_concurrent(
    client: &Client,
    base: &str,
    vectors: Vec<SoapProbeVector>,
) -> Vec<SoapProbeHit> {
    stream::iter(vectors)
        .map(|v| {
            let c = client.clone();
            let b = base.to_string();
            async move { execute_vector(&c, &b, &v).await }
        })
        .buffer_unordered(PROBE_CONCURRENCY)
        .filter_map(|x| async move { x })
        .filter_map(|(vector, probe)| async move { evaluate_soap_hit(&vector, &probe) })
        .collect()
        .await
}

pub async fn probe_wsdl_operations(
    client: &Client,
    base: &str,
    operations: &[String],
    canary: &str,
) -> Vec<SoapOperationHit> {
    let mut hits = Vec::new();
    for op in operations.iter().take(MAX_WSDL_OPS) {
        let body = operation_envelope(op, canary);
        for path in ["/soap", "/ws", "/services", "/service.asmx"] {
            let url = format!("{}{}", base.trim_end_matches('/'), path);
            let hdrs = [("Content-Type", "text/xml"), ("SOAPAction", op.as_str())];
            if let Some(p) = http_post_bytes_with_headers(client, &url, body.as_bytes(), &hdrs).await {
                let fault = p.body.to_ascii_lowercase().contains("fault");
                if p.status < 500 && (p.status != 404 || fault) {
                    hits.push(SoapOperationHit {
                        operation: op.clone(),
                        status: p.status,
                        body_len: p.body.len(),
                        final_url: p.final_url,
                        fault,
                    });
                    break;
                }
            }
        }
    }
    hits
}

pub async fn probe_wsdl_locations(
    client: &Client,
    locations: &[String],
    canary: &str,
) -> Vec<SoapProbeHit> {
    let mut hits = Vec::new();
    for loc in locations.iter().take(MAX_WSDL_LOCS) {
        let url = if loc.starts_with("http") {
            loc.clone()
        } else {
            continue;
        };
        if let Some(p) = http_get(client, &url).await {
            let vector = SoapProbeVector {
                category: "wsdl_location_followup",
                transport: SoapProbeTransport::GetWsdl,
                path: url.clone(),
                body: Vec::new(),
                content_type: String::new(),
                soap_action: None,
                extra_headers: Vec::new(),
                synthetic: true,
                canary: canary.to_string(),
            };
            if let Some(hit) = evaluate_soap_hit(&vector, &p) {
                hits.push(hit);
            }
        }
    }
    hits
}

pub fn soap_probe_bases(target: &str, ctx: &EngineRunContext) -> Vec<String> {
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
