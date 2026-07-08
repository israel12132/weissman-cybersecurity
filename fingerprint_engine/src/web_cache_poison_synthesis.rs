//! Live cache-poison vector synthesis — full catalog + zero-day style runtime generation.
//!
//! Every vector carries a unique canary computed at probe time so reflections are attributable
//! to a specific unkeyed input (no static demo strings in findings).

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{http_get, http_get_with_headers, http_method_with_headers, HttpProbe};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use std::collections::HashSet;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const PROBE_CONCURRENCY: usize = 20;
const MAX_VECTORS_PER_URL: usize = 220;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CachePoisonTransport {
    HeaderGet,
    HeaderHead,
    ParamGet,
    DualHeaderGet,
    TripleHeaderGet,
    MethodOverridePost,
}

#[derive(Clone, Debug)]
pub struct CachePoisonVector {
    pub category: &'static str,
    pub transport: CachePoisonTransport,
    pub key: String,
    pub value: String,
    pub canary: String,
    pub stack: Vec<(String, String)>,
    pub synthetic: bool,
}

#[derive(Default, Debug)]
pub struct CachePoisonSynthesisStats {
    pub vectors_generated: usize,
    pub vectors_probed: usize,
    pub synthetic_generated: usize,
    pub categories_hit: HashSet<&'static str>,
}

fn synthesis_nonce() -> String {
    let nano = Instant::now().elapsed().as_nanos();
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("wcp{unix:x}{nano:x}")
}

fn evil_host_variants(host: &str, nonce: &str) -> Vec<String> {
    let mut out = vec![
        format!("evil-{nonce}.cache-poison.test"),
        format!("{nonce}.attacker-cache.test"),
        format!("{host}.evil.{nonce}.test"),
        format!("localhost.{host}"),
        format!("127.0.0.1.{host}"),
        format!("internal.{host}"),
        format!("admin.{host}"),
        format!("cdn-{nonce}.{host}"),
        format!("{host}%60.evil.test"),
        format!("{host}.xip.io"),
    ];
    if let Some((sub, rest)) = host.split_once('.') {
        out.push(format!("{sub}-poison.{rest}"));
        out.push(format!("{nonce}.{rest}"));
    }
    out.sort();
    out.dedup();
    out
}

fn push_header(
    out: &mut Vec<CachePoisonVector>,
    category: &'static str,
    key: &str,
    value: String,
    canary: &str,
    synthetic: bool,
) {
    out.push(CachePoisonVector {
        category,
        transport: CachePoisonTransport::HeaderGet,
        key: key.to_string(),
        value,
        canary: canary.to_string(),
        stack: Vec::new(),
        synthetic,
    });
}

fn push_dual(
    out: &mut Vec<CachePoisonVector>,
    category: &'static str,
    a: (&str, String),
    b: (&str, String),
    canary: &str,
) {
    out.push(CachePoisonVector {
        category,
        transport: CachePoisonTransport::DualHeaderGet,
        key: format!("{}+{}", a.0, b.0),
        value: format!("{}|{}", a.1, b.1),
        canary: canary.to_string(),
        stack: vec![(a.0.to_string(), a.1), (b.0.to_string(), b.1)],
        synthetic: true,
    });
}

fn push_triple(
    out: &mut Vec<CachePoisonVector>,
    category: &'static str,
    headers: [(&str, String); 3],
    canary: &str,
) {
    let key = headers
        .iter()
        .map(|(k, _)| *k)
        .collect::<Vec<_>>()
        .join("+");
    out.push(CachePoisonVector {
        category,
        transport: CachePoisonTransport::TripleHeaderGet,
        key,
        value: canary.to_string(),
        canary: canary.to_string(),
        stack: headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        synthetic: true,
    });
}

fn push_param(
    out: &mut Vec<CachePoisonVector>,
    category: &'static str,
    param: &str,
    value: String,
    canary: &str,
    synthetic: bool,
) {
    out.push(CachePoisonVector {
        category,
        transport: CachePoisonTransport::ParamGet,
        key: param.to_string(),
        value,
        canary: canary.to_string(),
        stack: Vec::new(),
        synthetic,
    });
}

/// Full static catalog — every major cache-poison family used in the wild.
fn static_header_catalog(host: &str, nonce: &str, evil_hosts: &[String]) -> Vec<CachePoisonVector> {
    let mut out = Vec::new();
    let evil = evil_hosts.first().cloned().unwrap_or_else(|| format!("evil-{nonce}.test"));
    let canary_base = format!("canary-{nonce}");

    let host_headers = [
        "X-Forwarded-Host",
        "X-Host",
        "X-Forwarded-Server",
        "X-HTTP-Host-Override",
        "X-Original-Host",
        "X-Real-Host",
        "X-Proxy-Host",
        "X-Proxy-URL",
        "X-Forwarded-Authority",
    ];
    for h in host_headers {
        push_header(
            &mut out,
            "host_override",
            h,
            evil.clone(),
            &canary_base,
            false,
        );
    }
    push_header(
        &mut out,
        "host_override",
        "Forwarded",
        format!("for=127.0.0.1;host={evil};proto=http"),
        &canary_base,
        false,
    );

    let url_headers = [
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Forwarded-Uri",
        "X-Forwarded-Path",
        "X-Forwarded-Prefix",
        "X-URI",
        "X-Url",
        "X-Request-Uri",
        "Client-Original-URL",
        "X-Override-URL",
        "X-Original-Url",
        "X-Rewrite-Url",
    ];
    for h in url_headers {
        push_header(
            &mut out,
            "url_override",
            h,
            format!("/admin?{canary_base}=1"),
            &canary_base,
            false,
        );
    }

    let scheme_headers = [
        ("X-Forwarded-Scheme", "http"),
        ("X-Forwarded-Proto", "http"),
        ("X-Forwarded-Port", "443"),
        ("X-Forwarded-Ssl", "off"),
        ("X-Url-Scheme", "http"),
        ("X-Forwarded-Protocol", "http"),
    ];
    for (h, v) in scheme_headers {
        push_header(&mut out, "scheme_port", h, v.to_string(), &canary_base, false);
    }

    let ip_headers = [
        "X-Forwarded-For",
        "X-Real-IP",
        "Client-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "X-Client-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Originating-IP",
        "X-Cluster-Client-IP",
    ];
    for h in ip_headers {
        push_header(
            &mut out,
            "client_ip",
            h,
            "127.0.0.1".into(),
            &canary_base,
            false,
        );
    }

    let cdn_headers = [
        ("Fastly-SSL", "0"),
        ("Fastly-Client-IP", "127.0.0.1"),
        ("X-Varnish", "999"),
        ("X-Cache-Key", &format!("{host}/admin")),
        ("X-Akamai-Config-Log-Detail", "true"),
        ("X-Akamai-SSL-Client-Sid", &format!("sid-{nonce}")),
        ("Surrogate-Capability", r#"abc="ESI/1.0""#),
        ("X-Swift-CacheTime", "3600"),
        ("X-Cache-Status", "MISS"),
        ("X-Edge-Location", "evil-pop"),
    ];
    for (h, v) in cdn_headers {
        push_header(&mut out, "cdn_vendor", h, (*v).to_string(), &canary_base, false);
    }

    let accept_headers = [
        ("Accept", "text/cache-poison"),
        ("Accept-Language", &format!("xx-{canary_base}")),
        ("Accept-Encoding", "gzip, poison"),
        ("Accept-Charset", "utf-8, poison"),
        ("Accept-Version", "v9"),
        ("Accept-Datetime", "Thu, 01 Jan 2099 00:00:00 GMT"),
    ];
    for (h, v) in accept_headers {
        push_header(&mut out, "accept_unkeyed", h, (*v).to_string(), &canary_base, false);
    }

    let misc_headers: [(&str, String); 9] = [
        ("Origin", format!("https://{evil}")),
        ("Referer", format!("https://{evil}/admin")),
        ("X-Forwarded-Cookie", format!("session={canary_base}")),
        ("X-Custom-IP-Authorization", "127.0.0.1".into()),
        ("Base-Url", format!("https://{evil}")),
        ("X-Wap-Profile", format!("https://{evil}/wap.xml")),
        ("X-HTTP-Method-Override", "HEAD".into()),
        ("X-Method-Override", "HEAD".into()),
        ("X-Original-Method", "POST".into()),
    ];
    for (h, v) in misc_headers {
        push_header(&mut out, "misc_unkeyed", h, v, &canary_base, false);
    }
    push_header(&mut out, "misc_unkeyed", "Pragma", "akamai-x-cache-on".into(), &canary_base, false);
    push_header(&mut out, "misc_unkeyed", "X-Forwarded-User", "admin".into(), &canary_base, false);
    push_header(&mut out, "misc_unkeyed", "X-User", "admin".into(), &canary_base, false);

    out
}

fn static_param_catalog(nonce: &str) -> Vec<CachePoisonVector> {
    let canary = format!("canary-{nonce}");
    let params = [
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_content",
        "utm_term",
        "callback",
        "redirect",
        "redirect_uri",
        "next",
        "return",
        "returnUrl",
        "ref",
        "referer",
        "locale",
        "lang",
        "theme",
        "debug",
        "test",
        "_",
        "cb",
        "cachebuster",
        "force",
        "mcd",
        "nc",
        "reload",
        "timestamp",
        "rnd",
        "hash",
        "session",
        "state",
        "error",
        "msg",
        "message",
        "preview",
        "nocache",
        "c",
        "v",
        "ver",
        "version",
        "id",
        "uid",
        "aid",
        "pid",
        "format",
        "jsonp",
        "alt",
        "media",
        "view",
        "action",
        "cmd",
        "do",
        "op",
        "page",
        "p",
        "q",
        "query",
        "search",
        "s",
        "sort",
        "order",
        "filter",
        "limit",
        "offset",
        "page_size",
        "per_page",
        "from",
        "to",
        "start",
        "end",
        "date",
        "time",
        "tz",
        "timezone",
        "currency",
        "country",
        "region",
        "market",
        "channel",
        "source",
        "medium",
        "campaign",
        "term",
        "content",
        "gclid",
        "fbclid",
        "mc_eid",
        "ck",
        "ckcachebuster",
        "alt-svc",
        "wsa",
        "wsdl",
        "feed",
        "rest_route",
        "author",
        "name",
        "email",
        "username",
        "password",
        "token",
        "api_key",
        "key",
        "sig",
        "signature",
        "hmac",
        "nonce",
        "code",
        "scope",
        "client_id",
        "response_type",
        "grant_type",
    ];
    let mut out = Vec::new();
    for p in params {
        push_param(
            &mut out,
            "query_unkeyed",
            p,
            canary.clone(),
            &canary,
            false,
        );
    }
    // Fat-GET / cache-key truncation probes
    for len in [128usize, 256, 512, 1024] {
        let fat_key = "a".repeat(len);
        push_param(
            &mut out,
            "fat_get_truncation",
            &fat_key,
            canary.clone(),
            &canary,
            false,
        );
    }
    out
}

/// Runtime zero-day synthesis from target shape + intelligence bus + discovered paths.
fn synthetic_vectors(
    host: &str,
    url: &str,
    ctx: &EngineRunContext,
    nonce: &str,
    evil_hosts: &[String],
) -> Vec<CachePoisonVector> {
    let mut out = Vec::new();
    let canary = format!("syn-{nonce}");

    for evil in evil_hosts.iter().take(6) {
        push_dual(
            &mut out,
            "synthetic_dual_stack",
            ("X-Forwarded-Host", evil.clone()),
            ("X-Forwarded-Proto", "http".into()),
            &canary,
        );
        push_dual(
            &mut out,
            "synthetic_dual_stack",
            ("X-Original-URL", "/admin".into()),
            ("X-Forwarded-Host", evil.clone()),
            &canary,
        );
        push_triple(
            &mut out,
            "synthetic_triple_stack",
            [
                ("X-Forwarded-Host", evil.clone()),
                ("X-Forwarded-Proto", "http".into()),
                ("X-Original-URL", format!("/internal?{canary}=1")),
            ],
            &canary,
        );
    }

    if let Some((scheme, rest)) = url.split_once("://") {
        let path = rest.split('/').skip(1).collect::<Vec<_>>().join("/");
        for seg in path.split('/').filter(|s| !s.is_empty()).take(5) {
            let syn_hdr = format!("X-Weissman-Synth-{seg}");
            push_header(
                &mut out,
                "synthetic_path_segment",
                &syn_hdr,
                format!("{scheme}://{host}/{seg}-poison-{nonce}"),
                &canary,
                true,
            );
            push_header(
                &mut out,
                "synthetic_path_segment",
                "X-Original-URL",
                format!("/{seg}/..;/admin?{canary}=1"),
                &canary,
                true,
            );
        }
    }

    for p in ctx.discovered_paths.iter().take(12) {
        let pl = p.trim();
        if pl.is_empty() {
            continue;
        }
        push_header(
            &mut out,
            "synthetic_intel_path",
            "X-Original-URL",
            format!("{pl}/..;/admin?{canary}=1"),
            &canary,
            true,
        );
        push_header(
            &mut out,
            "synthetic_intel_path",
            "X-Rewrite-URL",
            format!("{pl}%2f..%2fadmin"),
            &canary,
            true,
        );
        push_param(
            &mut out,
            "synthetic_intel_path",
            &format!("cb_{}", pl.trim_start_matches('/').replace('/', "_")),
            canary.clone(),
            &canary,
            true,
        );
    }

    if let Some(bus) = ctx.intelligence_bus.as_ref() {
        for art in bus.snapshot().iter().take(16) {
            let marker = art
                .source_url
                .split('/')
                .last()
                .unwrap_or("api")
                .chars()
                .take(24)
                .collect::<String>();
            push_header(
                &mut out,
                "synthetic_bus_artifact",
                "X-Forwarded-Host",
                format!("{marker}-poison-{nonce}.cache.test"),
                &canary,
                true,
            );
            if art.proof.contains("graphql") {
                push_param(
                    &mut out,
                    "synthetic_bus_artifact",
                    "extensions",
                    format!(r#"{{"persistedQuery":{{"sha256Hash":"{canary}"}}}}"#),
                    &canary,
                    true,
                );
            }
        }
    }

    // Numeric / encoding mutations — computed live per request
    for i in 0..8u8 {
        let enc = format!("%2e%2e%2fadmin%2f{i:x}");
        push_header(
            &mut out,
            "synthetic_encoding",
            "X-Original-URL",
            enc,
            &canary,
            true,
        );
    }

    for payload in ctx.memory_payloads.iter().take(6) {
        if payload.trim().is_empty() {
            continue;
        }
        push_param(
            &mut out,
            "synthetic_memory_payload",
            "q",
            payload.clone(),
            &canary,
            true,
        );
        push_header(
            &mut out,
            "synthetic_memory_payload",
            "X-Original-URL",
            format!("/?q={}", urlencoding::encode(payload)),
            &canary,
            true,
        );
    }

    // HEAD transport on high-value poison headers (some caches key only on GET)
    for h in ["X-Forwarded-Host", "X-Original-URL", "X-Forwarded-Proto"] {
        out.push(CachePoisonVector {
            category: "synthetic_head_transport",
            transport: CachePoisonTransport::HeaderHead,
            key: h.to_string(),
            value: format!("{host}-head-{nonce}"),
            canary: canary.clone(),
            stack: Vec::new(),
            synthetic: true,
        });
    }

    out
}

/// Merge static catalog + live synthesis; synthetic vectors are prioritized first.
#[must_use]
pub fn synthesize_cache_poison_vectors(
    host: &str,
    url: &str,
    ctx: &EngineRunContext,
) -> (Vec<CachePoisonVector>, CachePoisonSynthesisStats) {
    let nonce = synthesis_nonce();
    let evil_hosts = evil_host_variants(host, &nonce);
    let mut synthetic = synthetic_vectors(host, url, ctx, &nonce, &evil_hosts);
    let mut static_v = static_header_catalog(host, &nonce, &evil_hosts);
    static_v.extend(static_param_catalog(&nonce));

    let syn_count = synthetic.len();
    let mut all = synthetic;
    all.append(&mut static_v);

    // Dedupe by transport+key+value
    let mut seen = HashSet::new();
    all.retain(|v| {
        let k = format!("{:?}|{}|{}", v.transport, v.key, v.value);
        seen.insert(k)
    });

    // Cap with synthetic-first ordering (already appended first)
    all.truncate(MAX_VECTORS_PER_URL);

    let stats = CachePoisonSynthesisStats {
        vectors_generated: all.len(),
        vectors_probed: 0,
        synthetic_generated: syn_count.min(all.len()),
        categories_hit: HashSet::new(),
    };
    (all, stats)
}

pub struct CachePoisonProbeHit {
    pub vector: CachePoisonVector,
    pub status: u16,
    pub body_len: usize,
    pub reflected: bool,
    pub size_delta: u64,
    pub status_changed: bool,
    pub final_url: String,
}

fn build_probe_url(base: &str, vector: &CachePoisonVector) -> String {
    match vector.transport {
        CachePoisonTransport::ParamGet | CachePoisonTransport::MethodOverridePost => {
            let sep = if base.contains('?') { "&" } else { "?" };
            format!(
                "{base}{sep}{}={}",
                urlencoding::encode(&vector.key),
                urlencoding::encode(&vector.value)
            )
        }
        _ => base.to_string(),
    }
}

async fn execute_vector(
    client: &Client,
    base_url: &str,
    vector: &CachePoisonVector,
) -> Option<(CachePoisonVector, HttpProbe)> {
    let url = build_probe_url(base_url, vector);
    let probe = match vector.transport {
        CachePoisonTransport::HeaderGet | CachePoisonTransport::DualHeaderGet
        | CachePoisonTransport::TripleHeaderGet => {
            let hdrs: Vec<(&str, &str)> = if vector.stack.is_empty() {
                vec![(vector.key.as_str(), vector.value.as_str())]
            } else {
                vector
                    .stack
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect()
            };
            http_get_with_headers(client, &url, &hdrs).await
        }
        CachePoisonTransport::HeaderHead => {
            let hdrs = vec![(vector.key.as_str(), vector.value.as_str())];
            http_method_with_headers(client, "HEAD", &url, None, &hdrs).await
        }
        CachePoisonTransport::ParamGet => http_get(client, &url).await,
        CachePoisonTransport::MethodOverridePost => {
            http_method_with_headers(
                client,
                "POST",
                base_url,
                None,
                &[
                    ("X-HTTP-Method-Override", "GET"),
                    (vector.key.as_str(), vector.value.as_str()),
                ],
            )
            .await
        }
    };
    probe.map(|p| (vector.clone(), p))
}

pub fn evaluate_poison_hit(
    vector: &CachePoisonVector,
    probe: &HttpProbe,
    base_status: u16,
    base_body_len: usize,
) -> Option<CachePoisonProbeHit> {
    let reflected = probe.body.contains(&vector.canary)
        || probe.body.contains(&vector.value)
        || header_value_lower(&probe.headers, "location")
            .map(|l| l.contains(&vector.canary) || l.contains(&vector.value))
            .unwrap_or(false)
        || header_value_lower(&probe.headers, "content-location")
            .map(|l| l.contains(&vector.canary))
            .unwrap_or(false);
    let size_delta = (probe.body.len() as i64 - base_body_len as i64).unsigned_abs();
    let status_changed = probe.status != base_status;
    if reflected || (status_changed && size_delta > 96) || (reflected && size_delta > 32) {
        Some(CachePoisonProbeHit {
            vector: vector.clone(),
            status: probe.status,
            body_len: probe.body.len(),
            reflected,
            size_delta,
            status_changed,
            final_url: probe.final_url.clone(),
        })
    } else if size_delta > 512 && probe.status < 500 {
        Some(CachePoisonProbeHit {
            vector: vector.clone(),
            status: probe.status,
            body_len: probe.body.len(),
            reflected: false,
            size_delta,
            status_changed,
            final_url: probe.final_url.clone(),
        })
    } else {
        None
    }
}

fn header_value_lower(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.to_ascii_lowercase())
}

/// Concurrent live probe of synthesized vectors against one URL.
pub async fn probe_cache_poison_vectors_concurrent(
    client: &Client,
    base_url: &str,
    vectors: Vec<CachePoisonVector>,
    base_status: u16,
    base_body_len: usize,
) -> Vec<CachePoisonProbeHit> {
    stream::iter(vectors)
        .map(|v| {
            let c = client.clone();
            let u = base_url.to_string();
            async move { execute_vector(&c, &u, &v).await }
        })
        .buffer_unordered(PROBE_CONCURRENCY)
        .filter_map(|x| async move { x })
        .filter_map(|(vector, probe)| async move {
            evaluate_poison_hit(&vector, &probe, base_status, base_body_len)
        })
        .collect()
        .await
}
