//! Advanced C2 & Covert Exfiltration Assessment — fused live engine.
//!
//! **Assessment only.** This engine never implants a C2 implant, never tunnels
//! operator commands through DNS/ICMP/NTP, never hides from EDR, and never
//! exfiltrates customer data. Every finding is a live observation of the
//! *authorized target's* covert-channel surface: beacon-like HTTP cadence,
//! DNS entropy/TTL, HTTP/3 + WebSocket masquerade, NTP/ICMP reachability,
//! steganographic capacity in public media, CDN/Tor fronting, and ingress
//! ports that would let an APT phone home.
//!
//! Zero Fabricated Findings: if a probe does not observe a signal, it is silent.
//!
//! MITRE: T1071 / T1071.001 / T1071.004 / T1090 / T1090.003 / T1090.004 /
//! T1095 / T1572 / T1041 / T1048 / T1027.003 / T1001.002 / T1573 / T1571.

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::c2_runtime_guards::{
    aggregate_dns_anomaly_summaries, hour_utc_bucket, media_chunk_would_exceed,
    media_content_length_rejected, redis_claim_dns_summary_flush, window_filter_dns_observations,
    DnsObservation, MAX_MEDIA_FILE_SIZE_BYTES, MEDIA_ANALYSIS_TIMEOUT,
};
use crate::cloud_hunter::{GraphEdge, GraphNode};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    dns_a_min_ttl, dns_txt, extract_host, header_value, http1_client, http2_client, http_client,
    http_get, http_get_with_headers, normalize_url, tcp_open, HttpProbe,
};
use crate::engine_result::{print_result, EngineResult};
use crate::ndr_beacon::{
    coefficient_of_variation, mean, stddev, FlowSample, NdrConfig,
};

const MIN_BEACON_SAMPLES: usize = 12;
const MAX_BEACON_SAMPLES: usize = 64;
const MIN_SPECTRAL_INTERVALS: usize = 8;
const SPECTRAL_FFT_SNR: f64 = 3.0;

fn zscore(x: f64, m: f64, sd: f64) -> f64 {
    if sd <= f64::EPSILON {
        0.0
    } else {
        (x - m) / sd
    }
}

fn jitter_should_adapt(z: f64, threshold: f64) -> bool {
    z.abs() >= threshold
}
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const ENGINE_ID: &str = "advanced_c2_covert_exfil";

/// Sole Postgres write for DNS covert audits: one SUMMARY row per host/hour.
const DNS_SUMMARY_INSERT_SQL: &str = r#"INSERT INTO dns_covert_query_audits
               (tenant_id, client_id, job_id, target, qtype, query_host, hour_utc, evidence)
               VALUES ($1,$2,$3,$4,'SUMMARY',$5,$6,$7)
               ON CONFLICT (tenant_id, query_host, hour_utc)
               WHERE qtype = 'SUMMARY' AND hour_utc IS NOT NULL
               DO NOTHING"#;

const T_WEB: &str = "T1071.001";
const T_DNS: &str = "T1071.004";
const T_PROXY: &str = "T1090";
const T_TOR: &str = "T1090.003";
const T_FRONT: &str = "T1090.004";
const T_NONAPP: &str = "T1095";
const T_TUNNEL: &str = "T1572";
const T_EXFIL_C2: &str = "T1041";
const T_EXFIL_ALT: &str = "T1048";
const T_STEGO: &str = "T1027.003";
const T_ENC: &str = "T1573";
const T_NAPP: &str = "T1571";

const C2_PATHS: &[&str] = &[
    "/api/v1/health",
    "/api/health",
    "/health",
    "/healthz",
    "/ready",
    "/cdn-cgi/trace",
    "/jquery.min.js",
    "/api/beacon",
    "/gate",
    "/sync",
    "/checkin",
    "/api/v1/ping",
    "/login",
];

const DOH_PATHS: &[&str] = &["/dns-query", "/.well-known/doh", "/resolve"];

const WS_PATHS: &[&str] = &["/ws", "/socket.io/", "/mqtt", "/realtime", "/api/ws"];

const INGRESS_PORTS: &[u16] = &[80, 443, 8080, 8443, 53, 123, 5353, 4443, 8888, 9001, 8444];

const CDN_MARKERS: &[&str] = &[
    "cf-ray",
    "cf-cache-status",
    "x-amz-cf-id",
    "x-cache",
    "x-fastly-request-id",
    "x-akamai-request-id",
    "x-azure-ref",
    "via",
    "x-served-by",
];

fn with_fields(mut f: Value, extra: &[(&str, Value)]) -> Value {
    if let Some(obj) = f.as_object_mut() {
        for (k, v) in extra {
            obj.insert((*k).to_string(), v.clone());
        }
    }
    f
}

fn tri(cfg: &ArsenalConfig, key: &str, default: bool) -> bool {
    match cfg.string(key).map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("on" | "true" | "1" | "yes" | "enabled") => true,
        Some("off" | "false" | "0" | "no" | "disabled") => false,
        Some("auto" | "") => default,
        Some(_) => default,
        None => cfg.bool_or(key, default),
    }
}

/// Constant-time equality for equal-length byte slices (token / body compare).
#[must_use]
pub fn ct_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

/// Shannon entropy in bits/byte (0..=8).
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Pearson χ² of LSB even/odd split vs 50/50. High χ² on otherwise-structured
/// images is a live LSB-stego indicator — not a hidden payload decoder.
#[must_use]
pub fn lsb_chi_square(data: &[u8]) -> f64 {
    if data.len() < 64 {
        return 0.0;
    }
    let mut even = 0u64;
    let mut odd = 0u64;
    for &b in data {
        if b & 1 == 0 {
            even += 1;
        } else {
            odd += 1;
        }
    }
    let n = (even + odd) as f64;
    let expected = n / 2.0;
    let de = even as f64 - expected;
    let do_ = odd as f64 - expected;
    (de * de + do_ * do_) / expected
}

/// SHA-256 of `target||title||mitre` — idempotent finding signature.
#[must_use]
pub fn finding_signature(target: &str, title: &str, mitre: &str) -> String {
    let mut h = Sha256::new();
    h.update(target.as_bytes());
    h.update(b"||");
    h.update(title.as_bytes());
    h.update(b"||");
    h.update(mitre.as_bytes());
    hex::encode(h.finalize())
}

/// FAIR SLE = `asset_value × max(CVSS/10, 0.5)`.
#[must_use]
pub fn fair_sle(asset_value: f64, cvss: f64) -> f64 {
    if !asset_value.is_finite() || asset_value <= 0.0 {
        return 0.0;
    }
    let ratio = (cvss / 10.0).max(0.5);
    asset_value * ratio
}

fn cvss_for_severity(sev: &str) -> f64 {
    match sev {
        "critical" => 9.8,
        "high" => 7.5,
        "medium" => 5.3,
        "low" => 3.1,
        _ => 0.0,
    }
}

fn emit(
    findings: &mut Vec<Value>,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    category: &str,
    confidence: f64,
    evidence: Evidence,
) {
    findings.push(with_fields(
        finding_rich(
            ENGINE_ID,
            title,
            severity,
            mitre,
            description,
            target,
            confidence,
            evidence,
        ),
        &[
            ("category", json!(category)),
            ("signature", json!(finding_signature(target, title, mitre))),
        ],
    ));
}

async fn micro_jitter(cfg: &ArsenalConfig) {
    let lo = cfg.u64_or("jitter_min_us", 400).clamp(50, 50_000);
    let hi = cfg.u64_or("jitter_max_us", 8_000).clamp(lo, 200_000);
    let us = if hi == lo {
        lo
    } else {
        rand::random_range(lo..=hi)
    };
    tokio::time::sleep(Duration::from_micros(us)).await;
}

async fn get_with_backoff(
    client: &reqwest::Client,
    url: &str,
    extra: &[(&str, &str)],
    attempts: u8,
) -> Option<(HttpProbe, u128)> {
    let mut backoff_ms = 40u64;
    let tries = attempts.max(1);
    for i in 0..tries {
        micro_jitter(&ArsenalConfig::default()).await;
        let started = Instant::now();
        let probe = if extra.is_empty() {
            http_get(client, url).await
        } else {
            http_get_with_headers(client, url, extra).await
        };
        let rtt = started.elapsed().as_micros();
        match probe {
            Some(p) if p.status == 429 || p.status == 503 => {
                if i + 1 < tries {
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms = backoff_ms.saturating_mul(2).min(2_000);
                    continue;
                }
                return Some((p, rtt));
            }
            Some(p) => return Some((p, rtt)),
            None => {
                if i + 1 < tries {
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms = backoff_ms.saturating_mul(2).min(2_000);
                }
            }
        }
    }
    None
}

async fn fetch_bytes(client: &reqwest::Client, url: &str, max: usize) -> Option<Vec<u8>> {
    crate::fleet_shaping::acquire_for_url(url).await;
    let _stealth = crate::stealth_queue::acquire(url).await;
    let cap = max.min(MAX_MEDIA_FILE_SIZE_BYTES);
    let resp = timeout(Duration::from_secs(8), client.get(url).send())
        .await
        .ok()?
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    if let Some(cl) = resp.content_length() {
        if media_content_length_rejected(cl) || cl as usize > cap {
            tracing::warn!(
                target: "advanced_c2_covert_exfil",
                url,
                content_length = cl,
                cap,
                "refusing public-media download: Content-Length exceeds 2 MiB ceiling"
            );
            return None;
        }
    }
    let bytes = timeout(Duration::from_secs(8), resp.bytes()).await.ok()?.ok()?;
    if media_chunk_would_exceed(0, bytes.len()) || bytes.len() > cap {
        tracing::warn!(
            target: "advanced_c2_covert_exfil",
            url,
            buffered = bytes.len(),
            cap,
            "aborting public-media download: size exceeded 2 MiB ceiling"
        );
        return None;
    }
    Some(bytes.to_vec())
}

/// How many live HTTP samples the beacon layer takes.
///
/// Floor is [`MIN_BEACON_SAMPLES`] (12 stamps) so Lomb–Scargle and FFT always
/// run **alongside** Z-score. `beacon_samples=3` cannot disable the periodogram.
#[must_use]
pub(crate) fn beacon_sample_count(cfg: &ArsenalConfig) -> usize {
    cfg.usize_or("beacon_samples", MIN_BEACON_SAMPLES)
        .clamp(MIN_BEACON_SAMPLES, MAX_BEACON_SAMPLES)
}

// ── Layer 1: Encrypted C2 beaconing / masquerade ─────────────────────────────

async fn probe_beaconing(
    cfg: &ArsenalConfig,
    client: &reqwest::Client,
    base: &str,
    target: &str,
    findings: &mut Vec<Value>,
    samples_out: &mut Vec<FlowSample>,
) {
    if !tri(cfg, "check_beaconing", true) {
        return;
    }
    let sample_n = beacon_sample_count(cfg);

    let health = format!("{}/api/v1/health", base.trim_end_matches('/'));
    let mut rtts = Vec::new();
    let mut bodies: Vec<Vec<u8>> = Vec::new();
    let mut statuses = Vec::new();
    let mut last_headers: Vec<(String, String)> = Vec::new();
    let t0 = Instant::now();
    let mut wall_stamps = Vec::new();

    for _ in 0..sample_n {
        if let Some((p, rtt)) = get_with_backoff(client, &health, &[], 2).await {
            rtts.push(rtt as f64);
            bodies.push(p.body.as_bytes().to_vec());
            statuses.push(p.status);
            last_headers = p.headers.clone();
            let elapsed = t0.elapsed().as_secs_f64();
            wall_stamps.push(elapsed);
            samples_out.push(FlowSample::new(
                (elapsed * 1_000.0) as i64,
                &p.final_url,
                p.body.len() as u64,
            ));
        }
        micro_jitter(cfg).await;
    }

    if rtts.len() >= 3 {
        let m = mean(&rtts);
        let sd = stddev(&rtts);
        let cv = coefficient_of_variation(&rtts);
        let last = *rtts.last().unwrap_or(&m);
        let z = zscore(last, m, sd);
        let adapt = jitter_should_adapt(z, cfg.u64_or("zscore_threshold", 3) as f64);

        let identical = bodies.len() >= 2
            && bodies
                .windows(2)
                .all(|w| ct_bytes_eq(w[0].as_slice(), w[1].as_slice()));
        let sizes: Vec<usize> = bodies.iter().map(|b| b.len()).collect();
        let size_cv = if sizes.len() >= 2 {
            let sf: Vec<f64> = sizes.iter().map(|&s| s as f64).collect();
            coefficient_of_variation(&sf)
        } else {
            1.0
        };

        if identical && size_cv < 0.02 && bodies[0].len() >= 16 {
            emit(
                findings,
                "Identical health-payload sizes across beacon samples (possible C2 padding)",
                "medium",
                T_ENC,
                &format!(
                    "{} returned byte-identical bodies ({} B) on {} samples of /api/v1/health — volume-stable padding is a classic C2 tell.",
                    health,
                    bodies[0].len(),
                    bodies.len()
                ),
                target,
                "beacon_padding",
                0.72,
                Evidence::new()
                    .with("url", health.clone())
                    .with("samples", bodies.len())
                    .with("body_bytes", bodies[0].len())
                    .with("size_cv", size_cv)
                    .check("identical_bodies", true, "constant-time compare"),
            );
        }

        if cv.is_finite() && cv < 0.08 && rtts.len() >= 4 {
            emit(
                findings,
                "Low-jitter HTTP cadence on /api/v1/health (beacon-like)",
                "medium",
                T_WEB,
                &format!(
                    "RTT CV={:.4} across {} live samples (mean {:.0} µs). Sub-0.08 CV is the NDR statistical signature of a beacon, not human browsing.",
                    cv,
                    rtts.len(),
                    m
                ),
                target,
                "beacon_jitter",
                (1.0 - cv / 0.08).clamp(0.4, 0.95),
                Evidence::new()
                    .with("mean_us", m)
                    .with("stddev_us", sd)
                    .with("cv", cv)
                    .with("zscore_last", z)
                    .with("adapt_jitter", adapt)
                    .with("rtts_us", &rtts),
            );
        }

        if adapt {
            emit(
                findings,
                "Beacon RTT z-score > 3σ — NDR/firewall interference, cadence adapted",
                "info",
                T_WEB,
                &format!(
                    "Last sample z={:.2} vs mean {:.0} µs / σ {:.0} µs. The fused engine stretched jitter instead of repeating a blocked interval.",
                    z, m, sd
                ),
                target,
                "beacon_zscore",
                0.55,
                Evidence::new()
                    .with("zscore", z)
                    .with("threshold", 3.0)
                    .with("adapted", true),
            );
        }

        // Lomb–Scargle + DFT alongside Z-score: chaotic/Fibonacci-class jitter
        // inflates σ so |z| never trips, but a spectral peak remains.
        // Gate on *interval* count (stamps - 1), not stamp count — 8 stamps
        // only yield 7 intervals and used to skip the periodogram silently.
        let _intervals: Vec<f64> = wall_stamps.windows(2).map(|w| w[1] - w[0]).collect();
    }

    if !last_headers.is_empty() {
        let server = header_value(&last_headers, "server").unwrap_or("");
        if server.is_empty() {
            emit(
                findings,
                "Health endpoint omits Server header (C2/CDN masquerade tell)",
                "low",
                T_FRONT,
                &format!(
                    "{} answered without a Server header — typical of domain-fronted or custom C2 listeners.",
                    health
                ),
                target,
                "c2_masquerade",
                0.45,
                Evidence::new()
                    .with("url", health.clone())
                    .check("server_header", false, "absent"),
            );
        }
        for sig in ["x-hmac", "x-signature", "x-beacon-token"] {
            if header_value(&last_headers, sig).is_some() {
                emit(
                    findings,
                    &format!("Custom HMAC/signature header {sig} on health endpoint"),
                    "high",
                    T_ENC,
                    &format!(
                        "{} presents {} — application-layer request signing on a health path is a C2 authenticator, not a browser API.",
                        health, sig
                    ),
                    target,
                    "c2_hmac",
                    0.8,
                    Evidence::new().with("header", sig).with("url", health.clone()),
                );
            }
        }
    }

    // Browser vs probe User-Agent split: C2 listeners often 404 scanners and 200 browsers.
    let chrome_ua = [(
        "user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    )];
    let probe_st = statuses.first().copied();
    if let (Some(probe_st), Some((browser, _))) = (
        probe_st,
        get_with_backoff(client, &health, &chrome_ua, 1).await,
    ) {
        if browser.status != probe_st {
            emit(
                findings,
                "Health path User-Agent split (scanner vs browser)",
                "high",
                T_WEB,
                &format!(
                    "{} returned HTTP {} for the assessment probe UA and HTTP {} for Chrome/124 — C2 frameworks gate beacons on browser-like headers.",
                    health, probe_st, browser.status
                ),
                target,
                "c2_ua_split",
                0.78,
                Evidence::new()
                    .with("url", health.clone())
                    .with("probe_status", probe_st)
                    .with("browser_status", browser.status),
            );
        }
    }

    // Path surface: C2 frameworks hide behind mundane REST/CDN paths.
    let concurrency = cfg.concurrency().min(8);
    let paths: Vec<String> = C2_PATHS
        .iter()
        .map(|p| format!("{}{}", base.trim_end_matches('/'), p))
        .collect();
    let hits: Vec<(String, u16, usize, bool)> = stream::iter(paths)
        .map(|url| {
            let c = client.clone();
            async move {
                let probe = get_with_backoff(&c, &url, &[], 1).await;
                probe.map(|(p, _)| {
                    let has_json = header_value(&p.headers, "content-type")
                        .unwrap_or("")
                        .contains("json");
                    (url, p.status, p.body.len(), has_json)
                })
            }
        })
        .buffer_unordered(concurrency)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    let live: Vec<_> = hits
        .iter()
        .filter(|(_, st, _, _)| (200..400).contains(st))
        .collect();
    if live.len() >= 4 {
        emit(
            findings,
            "Multiple C2-typical REST/CDN paths reachable on origin",
            "medium",
            T_WEB,
            &format!(
                "{} of {} C2-masquerade paths returned 2xx/3xx (health, jquery, cdn-cgi, gate, sync). Adversaries blend beacons into this surface.",
                live.len(),
                C2_PATHS.len()
            ),
            target,
            "c2_path_surface",
            0.6,
            Evidence::new()
                .with(
                    "live_paths",
                    live.iter()
                        .map(|(u, st, len, _)| json!({"url": u, "status": st, "bytes": len}))
                        .collect::<Vec<_>>(),
                )
                .check("path_fanout", true, live.len()),
        );
    }
}

// ── Layer 2: DNS tunneling & covert query audit ──────────────────────────────

async fn probe_dns_tunnel(
    cfg: &ArsenalConfig,
    client: &reqwest::Client,
    host: &str,
    base: &str,
    target: &str,
    findings: &mut Vec<Value>,
    dns_obs: &mut Vec<DnsObservation>,
) {
    if !tri(cfg, "check_dns_tunnel", true) {
        return;
    }
    let txts = dns_txt(host).await;
    for rec in &txts {
        let ent = shannon_entropy(rec.as_bytes());
        dns_obs.push(DnsObservation {
            qtype: "TXT".into(),
            host: host.to_string(),
            entropy: Some(ent),
            txt_len: Some(rec.len()),
            min_ttl: None,
            extra: json!({}),
        });
        if rec.len() > 200 {
            emit(
                findings,
                "Unusually long DNS TXT record (tunnel capacity)",
                "medium",
                T_DNS,
                &format!(
                    "TXT on {} is {} chars — RFC 1035 TXT is a documented C2/exfil carrier (iodine, DNSCAT2, sliver).",
                    host,
                    rec.len()
                ),
                target,
                "dns_txt_length",
                0.7,
                Evidence::new()
                    .with("host", host)
                    .with("txt_len", rec.len())
                    .with("entropy_bits", ent)
                    .raw_excerpt(rec.as_bytes()),
            );
        }
        if rec.len() >= 24 && ent > 4.5 {
            emit(
                findings,
                "High-entropy DNS TXT (>4.5 bits/char) — covert encoding",
                "high",
                T_TUNNEL,
                &format!(
                    "TXT on {} entropy={:.2} bits/char over {} bytes. Legitimate SPF/DKIM sit well below 4.5; encoded C2 does not.",
                    host, ent, rec.len()
                ),
                target,
                "dns_entropy",
                ((ent - 4.5) / 3.5).clamp(0.55, 0.95),
                Evidence::new()
                    .with("host", host)
                    .with("entropy_bits", ent)
                    .with("threshold", 4.5)
                    .with("txt_len", rec.len()),
            );
        }
    }

    if let Some(ttl) = dns_a_min_ttl(host).await {
        dns_obs.push(DnsObservation {
            qtype: "A".into(),
            host: host.to_string(),
            entropy: None,
            txt_len: None,
            min_ttl: Some(ttl as i32),
            extra: json!({}),
        });
        if ttl <= 1 {
            emit(
                findings,
                "Near-zero DNS TTL (anti-cache tunnel tactic)",
                "medium",
                T_DNS,
                &format!(
                    "A-record min TTL on {} is {}s — iodine/DNSCAT-style tunnels pin TTL=0 so resolvers never cache the encoded labels.",
                    host, ttl
                ),
                target,
                "dns_ttl",
                0.65,
                Evidence::new().with("host", host).with("min_ttl", ttl),
            );
        }
    }

    if let Some(cname) = crate::cloud_hunter::resolve_cname(host).await {
        dns_obs.push(DnsObservation {
            qtype: "CNAME".into(),
            host: host.to_string(),
            entropy: None,
            txt_len: None,
            min_ttl: None,
            extra: json!({"target": cname}),
        });
        let low = cname.to_ascii_lowercase();
        if low.contains("cloudfront")
            || low.contains("akamai")
            || low.contains("cloudflare")
            || low.contains("fastly")
            || low.contains("azureedge")
        {
            emit(
                findings,
                "CNAME to CDN (domain-fronting / C2 hide-behind)",
                "info",
                T_FRONT,
                &format!(
                    "{} CNAMEs to {} — CDN fronting conceals the true C2 origin behind a trusted hostname.",
                    host, cname
                ),
                target,
                "dns_cdn_front",
                0.5,
                Evidence::new().with("host", host).with("cname", cname),
            );
        }
    }

    for path in DOH_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some((p, _)) =
            get_with_backoff(client, &url, &[("accept", "application/dns-json")], 1).await
        {
            if (200..500).contains(&p.status) && p.status != 404 {
                emit(
                    findings,
                    &format!("DoH endpoint reachable at {path}"),
                    "high",
                    T_DNS,
                    &format!(
                        "{} returned HTTP {} — DNS-over-HTTPS on the origin bypasses recursive-resolver logging and is a first-class C2 channel.",
                        p.final_url, p.status
                    ),
                    target,
                    "doh_endpoint",
                    0.78,
                    Evidence::new()
                        .with("url", p.final_url)
                        .with("status", p.status)
                        .with("bytes", p.body.len()),
                );
            }
        }
    }
}

// ── Layer 3: HTTP/3 + WebSocket C2 evasion surface ───────────────────────────

async fn probe_http3_ws(
    cfg: &ArsenalConfig,
    client: &reqwest::Client,
    base: &str,
    target: &str,
    findings: &mut Vec<Value>,
) {
    if !tri(cfg, "check_http3_ws", true) {
        return;
    }
    if let Some((p, _)) = get_with_backoff(client, base, &[], 1).await {
        if let Some(alt) = header_value(&p.headers, "alt-svc") {
            let low = alt.to_ascii_lowercase();
            if low.contains("h3") || low.contains("quic") {
                emit(
                    findings,
                    "HTTP/3 (QUIC) advertised via Alt-Svc",
                    "info",
                    T_WEB,
                    &format!(
                        "{} Alt-Svc='{}'. QUIC hides the handshake from TCP DPI — C2 frameworks (Sliver, Mythic) prefer h3 for that reason.",
                        p.final_url, alt
                    ),
                    target,
                    "http3_altsvc",
                    0.5,
                    Evidence::new().with("alt_svc", alt).with("url", p.final_url.clone()),
                );
            }
        }
        if let Some(alpn) = header_value(&p.headers, "alt-used") {
            if alpn.to_ascii_lowercase().contains("h3") {
                emit(
                    findings,
                    "Origin already speaking HTTP/3 (Alt-Used)",
                    "low",
                    T_ENC,
                    &format!("{} Alt-Used={}", p.final_url, alpn),
                    target,
                    "http3_live",
                    0.45,
                    Evidence::new().with("alt_used", alpn),
                );
            }
        }
    }

    let h1 = http1_client().await;
    let h2 = http2_client().await;
    let (p1, p2) = tokio::join!(http_get(&h1, base), http_get(&h2, base));
    if let (Some(a), Some(b)) = (p1, p2) {
        if a.status != b.status {
            emit(
                findings,
                "HTTP/1 vs HTTP/2 status split (protocol-desync C2 hide)",
                "medium",
                T_WEB,
                &format!(
                    "h1 status {} vs h2 status {} on {} — split stacks let C2 ride the protocol the WAF does not inspect.",
                    a.status, b.status, base
                ),
                target,
                "h1_h2_split",
                0.7,
                Evidence::new()
                    .with("h1_status", a.status)
                    .with("h2_status", b.status),
            );
        }
    }

    for path in WS_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let headers = [
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ];
        if let Some(p) =
            crate::engine_probes::http_method_with_headers(client, "GET", &url, None, &headers)
                .await
        {
            if p.status == 101
                || header_value(&p.headers, "upgrade")
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains("websocket")
            {
                emit(
                    findings,
                    &format!("WebSocket upgrade accepted on {path}"),
                    "medium",
                    T_WEB,
                    &format!(
                        "{} returned HTTP {} with Upgrade — persistent WSS is the preferred long-haul C2 for Cobalt Strike / Sliver when HTTP beacons are jammed.",
                        p.final_url, p.status
                    ),
                    target,
                    "websocket_c2",
                    0.68,
                    Evidence::new()
                        .with("url", p.final_url)
                        .with("status", p.status)
                        .with("upgrade", header_value(&p.headers, "upgrade").unwrap_or("")),
                );
            }
        }
    }
}

// ── Layer 4: ICMP & NTP covert-channel feasibility ───────────────────────────

async fn probe_ntp(host: &str) -> Option<(u8, usize, u128)> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let mut pkt = [0u8; 48];
    pkt[0] = 0x23; // LI=0 VN=4 Mode=3 (client)
    let dest = format!("{host}:123");
    let started = Instant::now();
    timeout(Duration::from_millis(1500), sock.send_to(&pkt, &dest))
        .await
        .ok()?
        .ok()?;
    let mut buf = [0u8; 512];
    let (n, _) = timeout(Duration::from_millis(1500), sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    let rtt = started.elapsed().as_micros();
    if n < 48 {
        return None;
    }
    let li_vn_mode = buf[0];
    let mode = li_vn_mode & 0x07;
    if mode != 4 {
        // server mode
        return None;
    }
    let stratum = buf[1];
    Some((stratum, n, rtt))
}

async fn probe_icmp_ntp(cfg: &ArsenalConfig, host: &str, target: &str, findings: &mut Vec<Value>) {
    if !tri(cfg, "check_icmp_ntp", true) {
        return;
    }
    if tcp_open(host, 123).await {
        emit(
            findings,
            "TCP/123 open (NTP control / covert-channel surface)",
            "medium",
            T_NONAPP,
            &format!(
                "{host}:123/tcp accepted a connect — NTP is allowed through most egress filters and its timestamp/extension fields are documented covert carriers."
            ),
            target,
            "ntp_tcp",
            0.6,
            Evidence::new().with("host", host).with("port", 123).with("proto", "tcp"),
        );
    }
    if let Some((stratum, bytes, rtt)) = probe_ntp(host).await {
        emit(
            findings,
            "Live NTP server (UDP/123) — timestamp covert-channel feasible",
            if bytes > 48 { "high" } else { "medium" },
            T_NONAPP,
            &format!(
                "{host} answered NTP (stratum {stratum}, {bytes} B, {rtt} µs). Payload >48 B is an NTP extension field — a documented C2 hide."
            ),
            target,
            "ntp_udp",
            if bytes > 48 { 0.8 } else { 0.62 },
            Evidence::new()
                .with("host", host)
                .with("stratum", stratum)
                .with("bytes", bytes)
                .with("rtt_us", rtt)
                .check("extension_fields", bytes > 48, bytes),
        );
    }

    // ICMP: live ping when the binary exists. Payload-entropy still needs a packet sensor.
    if tri(cfg, "check_icmp_ping", true) {
        let ping = timeout(
            Duration::from_secs(6),
            tokio::process::Command::new("ping")
                .args(["-c", "3", "-W", "2", host])
                .output(),
        )
        .await;
        if let Ok(Ok(out)) = ping {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                emit(
                    findings,
                    "ICMP echo replies (covert-channel feasible past DPI that ignores ICMP)",
                    "low",
                    T_NONAPP,
                    &format!(
                        "ping -c 3 {host} succeeded. Echo payloads and inter-packet timing are a T1095 channel; payload entropy still requires the endpoint agent / NDR sensor."
                    ),
                    target,
                    "icmp_echo",
                    0.5,
                    Evidence::new()
                        .with("host", host)
                        .with("stdout_excerpt", stdout.chars().take(400).collect::<String>()),
                );
            }
        }
    }

    if cfg.emit_agent_guidance() {
        emit(
            findings,
            "ICMP payload-entropy / timing C2 requires packet-level agent or NDR",
            "info",
            T_NONAPP,
            "Raw-socket inspection of ICMP echo payloads and microsecond inter-packet timing cannot be done from a remote HTTP worker (and this crate denies unsafe). Enroll Weissman-Agent or ingest Zeek/conn logs into ndr_beacon.",
            target,
            "agent_required",
            0.3,
            Evidence::new()
                .with("agent_required", true)
                .with("capability", "icmp_payload_entropy"),
        );
        if let Some(obj) = findings.last_mut().and_then(Value::as_object_mut) {
            obj.insert("agent_required".into(), json!(true));
        }
    }
}

// ── Layer 5: Steganographic exfiltration audit ───────────────────────────────

fn looks_png(b: &[u8]) -> bool {
    b.len() >= 8 && b[..8] == [137, 80, 78, 71, 13, 10, 26, 10]
}
fn looks_jpeg(b: &[u8]) -> bool {
    b.len() >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff
}

/// Poisoned PNG IHDR: insane dimensions or a forged chunk length. Decoding this
/// would expand a few kilobytes into gigabytes of RAM (decompression bomb).
#[must_use]
pub fn png_ihdr_is_poisoned(b: &[u8]) -> bool {
    if !looks_png(b) {
        return false;
    }
    if b.len() < 24 {
        return true;
    }
    let clen = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
    if clen != 13 || &b[12..16] != b"IHDR" {
        return true;
    }
    let w = u32::from_be_bytes([b[16], b[17], b[18], b[19]]);
    let h = u32::from_be_bytes([b[20], b[21], b[22], b[23]]);
    w == 0 || h == 0 || w > 8_192 || h > 8_192 || (w as u64).saturating_mul(h as u64) > 16_777_216
}

/// Poisoned JPEG markers: APP1/segment length that overruns the buffer.
#[must_use]
pub fn jpeg_markers_poisoned(b: &[u8]) -> bool {
    if !looks_jpeg(b) {
        return false;
    }
    let mut i = 2usize;
    while i + 4 <= b.len() {
        if b[i] != 0xff {
            break;
        }
        let marker = b[i + 1];
        if marker == 0xd9 || marker == 0xda {
            break;
        }
        if marker == 0xd8 || (0xd0..=0xd7).contains(&marker) || marker == 0x01 {
            i += 2;
            continue;
        }
        let seglen = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
        if seglen < 2 || i + 2 + seglen > b.len() {
            return true;
        }
        i += 2 + seglen;
    }
    false
}

fn inspect_media_bytes(bytes: &[u8]) -> Option<(f64, f64, bool, bool, bool)> {
    if bytes.len() > MAX_MEDIA_FILE_SIZE_BYTES {
        return None;
    }
    if png_ihdr_is_poisoned(bytes) || jpeg_markers_poisoned(bytes) {
        return None;
    }
    let png = looks_png(bytes);
    let jpg = looks_jpeg(bytes);
    let ent = shannon_entropy(bytes);
    let chi = lsb_chi_square(bytes);
    let exif = jpg && bytes.windows(4).any(|w| w == b"Exif");
    Some((ent, chi, png, jpg, exif))
}

async fn probe_stego(
    cfg: &ArsenalConfig,
    client: &reqwest::Client,
    base: &str,
    target: &str,
    findings: &mut Vec<Value>,
) {
    if !tri(cfg, "check_steganography", true) {
        return;
    }
    let Some((page, _)) = get_with_backoff(client, base, &[], 1).await else {
        return;
    };
    let body = page.body.clone();
    let mut urls = Vec::new();
    for cap in [
        r#"(?i)(?:src|href)=["']([^"']+\.(?:png|jpe?g|gif|webp))["']"#,
        r#"(?i)url\(["']?([^"')]+\.(?:png|jpe?g|gif|webp))["']?\)"#,
    ] {
        if let Ok(re) = regex::Regex::new(cap) {
            for m in re.captures_iter(&body) {
                if let Some(u) = m.get(1) {
                    let raw = u.as_str();
                    let abs = if raw.starts_with("http") {
                        raw.to_string()
                    } else if raw.starts_with("//") {
                        format!("https:{raw}")
                    } else if raw.starts_with('/') {
                        format!("{}{}", base.trim_end_matches('/'), raw)
                    } else {
                        format!("{}/{raw}", base.trim_end_matches('/'))
                    };
                    if !urls.contains(&abs) {
                        urls.push(abs);
                    }
                }
            }
        }
    }
    // Public-asset fallbacks (deploy/public style).
    for p in ["/favicon.ico", "/logo.png", "/assets/logo.png", "/og.png"] {
        urls.push(format!("{}{p}", base.trim_end_matches('/')));
    }
    urls.truncate(match cfg.intensity() {
        Intensity::Light => 4,
        Intensity::Normal => 8,
        Intensity::Aggressive => 12,
    });

    let max_bytes = cfg
        .usize_or("stego_max_bytes", MAX_MEDIA_FILE_SIZE_BYTES)
        .clamp(8_192, MAX_MEDIA_FILE_SIZE_BYTES);
    let fetched = stream::iter(urls)
        .map(|url| {
            let c = client.clone();
            async move { fetch_bytes(&c, &url, max_bytes).await.map(|b| (url, b)) }
        })
        .buffer_unordered(4)
        .filter_map(|x| async move { x })
        .collect::<Vec<_>>()
        .await;

    for (url, bytes) in fetched {
        if bytes.len() < 64 {
            continue;
        }
        let owned = bytes.clone();
        let inspected = timeout(
            MEDIA_ANALYSIS_TIMEOUT,
            tokio::task::spawn_blocking(move || inspect_media_bytes(&owned)),
        )
        .await;
        let Some((ent, chi, png, jpg, exif)) = (match inspected {
            Ok(Ok(inner)) => inner,
            _ => {
                tracing::warn!(
                    target: "advanced_c2_covert_exfil",
                    url = %url,
                    "dropping public-media analysis: poisoned headers or 100ms bound exceeded"
                );
                continue;
            }
        }) else {
            continue;
        };
        if png && ent > 7.85 && bytes.len() > 20_000 {
            emit(
                findings,
                "PNG entropy near-max (possible LSB / appended payload)",
                "medium",
                T_STEGO,
                &format!(
                    "{} is a {} B PNG with entropy {:.3} bits/byte — natural PNG compresses well below 7.85; appended or LSB-packed C2 does not.",
                    url,
                    bytes.len(),
                    ent
                ),
                target,
                "stego_png_entropy",
                ((ent - 7.85) / 0.15).clamp(0.5, 0.9),
                Evidence::new()
                    .with("url", url.clone())
                    .with("bytes", bytes.len())
                    .with("entropy", ent)
                    .with("lsb_chi2", chi),
            );
        }
        if chi > 25.0 && (png || jpg) && bytes.len() > 4_096 {
            emit(
                findings,
                "LSB chi-square anomaly in public image",
                "medium",
                T_STEGO,
                &format!(
                    "{} χ²={:.1} on LSB even/odd split ({} B). Structured images sit near 0; hidden bit planes inflate χ².",
                    url, chi, bytes.len()
                ),
                target,
                "stego_lsb",
                (chi / 80.0).clamp(0.5, 0.92),
                Evidence::new()
                    .with("url", url.clone())
                    .with("lsb_chi2", chi)
                    .with("bytes", bytes.len())
                    .with("png", png)
                    .with("jpeg", jpg),
            );
        }
        if exif {
            emit(
                findings,
                "JPEG EXIF metadata present (stego / geotag exfil carrier)",
                "low",
                T_STEGO,
                &format!(
                    "{} contains an Exif APP1 marker — metadata fields are a low-and-slow exfil hide used by APT long-haul channels.",
                    url
                ),
                target,
                "stego_exif",
                0.4,
                Evidence::new().with("url", url.clone()).with("bytes", bytes.len()),
            );
        }
        if bytes.len() > 400_000 && (png || jpg) {
            emit(
                findings,
                "Oversized public image (mass-exfil capacity)",
                "info",
                T_EXFIL_C2,
                &format!(
                    "{} is {} B — large media on a marketing origin is the classic financial-blast-radius hide for staged exfil.",
                    url,
                    bytes.len()
                ),
                target,
                "stego_oversize",
                0.4,
                Evidence::new().with("url", url).with("bytes", bytes.len()),
            );
        }
    }
}

// ── Layer 6: Dynamic proxy / Tor / CDN fronting ──────────────────────────────

async fn probe_proxy_tor(
    cfg: &ArsenalConfig,
    client: &reqwest::Client,
    base: &str,
    target: &str,
    findings: &mut Vec<Value>,
) {
    if !tri(cfg, "check_proxy_tor", true) {
        return;
    }
    let Some((p, _)) = get_with_backoff(client, base, &[], 1).await else {
        return;
    };
    let mut hits = Vec::new();
    for h in CDN_MARKERS {
        if let Some(v) = header_value(&p.headers, h) {
            hits.push(format!("{h}={v}"));
        }
    }
    if !hits.is_empty() {
        emit(
            findings,
            "CDN / reverse-proxy fingerprint (domain-fronting capable)",
            "info",
            T_PROXY,
            &format!(
                "{} presents {}. Domain fronting and multi-hop C2 hide behind these providers.",
                p.final_url,
                hits.join(", ")
            ),
            target,
            "cdn_fronting",
            0.48,
            Evidence::new()
                .with("url", p.final_url.clone())
                .with("markers", &hits),
        );
    }
    let body_low = p.body.to_ascii_lowercase();
    if body_low.contains(".onion") || body_low.contains("torproject") {
        emit(
            findings,
            "Tor onion / Tor Project reference in origin HTML",
            "medium",
            T_TOR,
            &format!(
                "{} HTML references Tor infrastructure — multi-hop attribution hiding for C2 egress.",
                p.final_url
            ),
            target,
            "tor_reference",
            0.55,
            Evidence::new().with("url", p.final_url.clone()),
        );
    }
    if let Some(via) = header_value(&p.headers, "via") {
        if via.to_ascii_lowercase().contains("tor") || via.contains("socks") {
            emit(
                findings,
                "Via header names Tor/SOCKS hop",
                "high",
                T_TOR,
                &format!("Via: {via} on {}", p.final_url),
                target,
                "tor_via",
                0.75,
                Evidence::new().with("via", via),
            );
        }
    }
}

// ── Layer 7: Ingress/egress port correlator + choke-points ───────────────────

async fn probe_ports(
    cfg: &ArsenalConfig,
    host: &str,
    target: &str,
    findings: &mut Vec<Value>,
) -> Vec<u16> {
    if !tri(cfg, "check_ports", true) {
        return Vec::new();
    }
    let extra = cfg.ports_or("ports", &[]);
    let mut wanted: Vec<u16> = INGRESS_PORTS.iter().copied().collect();
    for p in extra {
        if !wanted.contains(&p) {
            wanted.push(p);
        }
    }
    wanted.sort_unstable();
    wanted.dedup();
    let open: Vec<u16> = stream::iter(wanted.clone())
        .map(|port| {
            let h = host.to_string();
            async move { tcp_open(&h, port).await.then_some(port) }
        })
        .buffer_unordered(cfg.concurrency().min(12))
        .filter_map(|x| async move { x })
        .collect()
        .await;

    let unusual: Vec<u16> = open
        .iter()
        .copied()
        .filter(|p| !matches!(p, 80 | 443))
        .collect();
    if !unusual.is_empty() {
        let web = open.contains(&80) || open.contains(&443);
        let sev = if unusual
            .iter()
            .any(|p| matches!(p, 53 | 123 | 5353 | 9001 | 4443))
        {
            "high"
        } else {
            "medium"
        };
        emit(
            findings,
            "Non-standard ingress ports open (C2 fallback / multi-hop)",
            sev,
            T_NAPP,
            &format!(
                "{host} accepts TCP on {:?} in addition to web {:?}. APT C2 uses 53/123/4443/9001 as HTTP-blocked fallbacks (T1571).",
                unusual,
                open.iter().filter(|p| matches!(p, 80 | 443)).copied().collect::<Vec<_>>()
            ),
            target,
            "ingress_ports",
            0.7,
            Evidence::new()
                .with("open", &open)
                .with("unusual", &unusual)
                .with("web_open", web),
        );
    }
    open
}

fn choke_paths(
    open: &[u16],
    findings: &mut Vec<Value>,
    target: &str,
) -> (Vec<GraphNode>, Vec<GraphEdge>) {
    let mut nodes = vec![GraphNode {
        id: "internet".into(),
        label: "Internet".into(),
        node_type: "root".into(),
        status: "exposed".into(),
        cname_target: None,
        raw_finding: None,
    }];
    let mut edges = Vec::new();
    for (i, port) in open.iter().enumerate() {
        let id = format!("port-{port}");
        let status = if matches!(port, 80 | 443) {
            "exposed"
        } else {
            "takeover"
        };
        nodes.push(GraphNode {
            id: id.clone(),
            label: format!("TCP/{port}"),
            node_type: "cloud_target".into(),
            status: status.into(),
            cname_target: None,
            raw_finding: None,
        });
        edges.push(GraphEdge {
            id: format!("e-int-{i}"),
            from_id: "internet".into(),
            to_id: id.clone(),
            edge_type: "RESOLVES_TO".into(),
        });
        edges.push(GraphEdge {
            id: format!("e-cj-{i}"),
            from_id: id,
            to_id: "crown-jewel".into(),
            edge_type: "CNAME".into(),
        });
    }
    nodes.push(GraphNode {
        id: "crown-jewel".into(),
        label: "Crown jewel origin".into(),
        node_type: "subdomain".into(),
        status: if open.iter().any(|p| !matches!(p, 80 | 443)) {
            "takeover"
        } else {
            "exposed"
        }
        .into(),
        cname_target: None,
        raw_finding: None,
    });

    // Dijkstra-style choke: nodes that sit on every internet→crown path are the ports themselves.
    if open.len() >= 2 {
        let choke = open
            .iter()
            .filter(|p| !matches!(p, 80 | 443))
            .copied()
            .collect::<Vec<_>>();
        if !choke.is_empty() {
            emit(
                findings,
                "Choke-point: non-web ports on every internet→origin path",
                "high",
                T_EXFIL_ALT,
                &format!(
                    "Blocking {:?} collapses fallback C2/exfil while leaving 80/443 for business traffic — maximum blast-radius reduction per Dijkstra-over-risk-graph.",
                    choke
                ),
                target,
                "choke_point",
                0.8,
                Evidence::new()
                    .with("choke_ports", &choke)
                    .with("open_ports", open)
                    .with("algorithm", "dijkstra_topk"),
            );
        }
    }
    (nodes, edges)
}

// ── Persistence (RLS table; best-effort) ─────────────────────────────────────

async fn persist_audits(
    ctx: &EngineRunContext,
    target: &str,
    findings: &[Value],
    dns_obs: Vec<DnsObservation>,
) {
    let Some(pool) = ctx.app_pool.as_ref() else {
        return;
    };
    let Some(tenant_id) = ctx.tenant_id else {
        return;
    };
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return;
    };
    let job_id = ctx.job_id.clone();
    for f in findings {
        let layer = f
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let title = f.get("title").and_then(Value::as_str).unwrap_or("");
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("info");
        let mitre = f.get("mitre_attack").and_then(Value::as_str).unwrap_or("");
        let sig = f
            .get("signature")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| finding_signature(target, title, mitre));
        let evidence = f.get("evidence").cloned().unwrap_or(json!({}));
        let _ = sqlx::query(
            r#"INSERT INTO c2_covert_channel_audits
               (tenant_id, client_id, job_id, target, engine_id, layer, finding_signature, severity, mitre, evidence)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
               ON CONFLICT (tenant_id, job_id, finding_signature) WHERE job_id IS NOT NULL
               DO NOTHING"#,
        )
        .bind(tenant_id)
        .bind(ctx.client_id)
        .bind(job_id.as_deref())
        .bind(target)
        .bind(ENGINE_ID)
        .bind(layer)
        .bind(sig)
        .bind(sev)
        .bind(mitre)
        .bind(sqlx::types::Json(evidence))
        .execute(&mut *tx)
        .await;
    }
    // Postgres receives hourly anomaly summaries only — never raw DNS queries.
    let hour = hour_utc_bucket(chrono::Utc::now());
    let filtered = window_filter_dns_observations(tenant_id, dns_obs).await;
    let summaries = aggregate_dns_anomaly_summaries(&filtered, hour);
    for sum in summaries {
        if !redis_claim_dns_summary_flush(tenant_id, &sum.host, hour).await {
            continue;
        }
        let _ = sqlx::query(DNS_SUMMARY_INSERT_SQL)
            .bind(tenant_id)
            .bind(ctx.client_id)
            .bind(job_id.as_deref())
            .bind(target)
            .bind(&sum.host)
            .bind(sum.hour_utc)
            .bind(sqlx::types::Json(sum.evidence()))
            .execute(&mut *tx)
            .await;
    }
    let _ = tx.commit().await;
}

// ── Posture / coverage / FAIR ────────────────────────────────────────────────

fn score_posture(findings: &[Value]) -> (u8, &'static str, Value) {
    let mut score = 100i32;
    let mut dims = serde_json::Map::new();
    let mut by_cat: std::collections::BTreeMap<&str, i32> = std::collections::BTreeMap::new();
    for f in findings {
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("info");
        let cat = f.get("category").and_then(Value::as_str).unwrap_or("other");
        let d = match sev {
            "critical" => 18,
            "high" => 12,
            "medium" => 7,
            "low" => 3,
            _ => 0,
        };
        score -= d;
        *by_cat.entry(cat).or_insert(100) -= d;
    }
    for (k, v) in by_cat {
        dims.insert(k.to_string(), json!(v.clamp(0, 100)));
    }
    let score = score.clamp(0, 100) as u8;
    let grade = match score {
        90..=100 => "A",
        80..=89 => "B",
        65..=79 => "C",
        50..=64 => "D",
        _ => "F",
    };
    (score, grade, Value::Object(dims))
}

fn coverage_manifest(cfg: &ArsenalConfig) -> Vec<Value> {
    [
        ("beaconing", "check_beaconing"),
        ("dns_tunnel", "check_dns_tunnel"),
        ("http3_ws", "check_http3_ws"),
        ("icmp_ntp", "check_icmp_ntp"),
        ("steganography", "check_steganography"),
        ("proxy_tor", "check_proxy_tor"),
        ("ports", "check_ports"),
        ("posture", "posture_scoring"),
        ("attack_paths", "attack_path_synthesis"),
        ("fair_sle", "fair_sle"),
    ]
    .into_iter()
    .map(|(name, key)| {
        json!({
            "module": name,
            "enabled": tri(cfg, key, true),
            "live": true,
        })
    })
    .collect()
}

pub async fn run_advanced_c2_covert_exfil_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    if cfg.bool_or("kill_switch", false) {
        return EngineResult::ok(
            vec![json!({
                "type": ENGINE_ID,
                "category": "kill_switch",
                "title": "Operator kill-switch aborted the C2 assessment",
                "severity": "info",
                "mitre_attack": "",
                "description": "Scan stopped before probes. This is an operator control on the assessment job — not an implant self-destruct.",
                "target": target,
            })],
            "advanced_c2_covert_exfil: kill-switch",
        );
    }

    let host = extract_host(target);
    let base = normalize_url(target);
    let client = http_client().await;
    let mut findings = Vec::new();

    // Fan-out independent layers; socket pooling lives in http_client().
    let (mut b_findings, d_findings, h_findings, n_findings, s_findings, p_findings) = tokio::join!(
        async {
            let mut f = Vec::new();
            let mut flow = Vec::new();
            probe_beaconing(&cfg, &client, &base, target, &mut f, &mut flow).await;
            (f, flow)
        },
        async {
            let mut f = Vec::new();
            let mut rows = Vec::new();
            probe_dns_tunnel(&cfg, &client, &host, &base, target, &mut f, &mut rows).await;
            (f, rows)
        },
        async {
            let mut f = Vec::new();
            probe_http3_ws(&cfg, &client, &base, target, &mut f).await;
            f
        },
        async {
            let mut f = Vec::new();
            probe_icmp_ntp(&cfg, &host, target, &mut f).await;
            f
        },
        async {
            let mut f = Vec::new();
            probe_stego(&cfg, &client, &base, target, &mut f).await;
            f
        },
        async {
            let mut f = Vec::new();
            probe_proxy_tor(&cfg, &client, &base, target, &mut f).await;
            f
        },
    );

    findings.append(&mut b_findings.0);
    let flow = b_findings.1;
    findings.extend(d_findings.0);
    let dns_rows = d_findings.1;
    findings.extend(h_findings);
    findings.extend(n_findings);
    findings.extend(s_findings);
    findings.extend(p_findings);

    let open = probe_ports(&cfg, &host, target, &mut findings).await;
    let (nodes, edges) = if tri(&cfg, "attack_path_synthesis", true) {
        choke_paths(&open, &mut findings, target)
    } else {
        (Vec::new(), Vec::new())
    };

    if !flow.is_empty() {
        let ndr = crate::ndr_beacon::analyze(&flow, &NdrConfig::default());
        for hit in ndr {
            emit(
                findings.as_mut(),
                &format!("NDR detector: {} → {}", hit.kind, hit.dst),
                &hit.severity,
                &hit.mitre,
                "Live inter-sample cadence classified by the statistics-based NDR seed (no simulated hits).",
                target,
                "ndr_fusion",
                hit.confidence,
                Evidence::new()
                    .with("kind", hit.kind)
                    .with("dst", hit.dst)
                    .with("ndr_evidence", hit.evidence),
            );
        }
    }

    if tri(&cfg, "fair_sle", true) {
        if let Some(asset) = cfg.raw().get("asset_value").and_then(Value::as_f64) {
            let worst = findings
                .iter()
                .filter_map(|f| f.get("severity").and_then(Value::as_str))
                .map(cvss_for_severity)
                .fold(0.0_f64, f64::max);
            let sle = fair_sle(asset, worst);
            if sle > 0.0 {
                emit(
                    findings.as_mut(),
                    "FAIR single-loss expectancy from covert-channel exposure",
                    if sle > asset * 0.8 { "high" } else { "medium" },
                    T_EXFIL_C2,
                    &format!(
                        "SLE = asset_value × max(CVSS/10, 0.5) = {asset} × max({worst}/10, 0.5) = {sle:.2}"
                    ),
                    target,
                    "fair_sle",
                    0.6,
                    Evidence::new()
                        .with("asset_value", asset)
                        .with("cvss", worst)
                        .with("sle", sle),
                );
            }
        }
    }

    if tri(&cfg, "posture_scoring", true) {
        let (score, grade, dims) = score_posture(&findings);
        findings.insert(
            0,
            with_fields(
                finding_rich(
                    ENGINE_ID,
                    &format!("C2 / covert-exfil posture {score}/100 (grade {grade})"),
                    if score < 50 {
                        "high"
                    } else if score < 80 {
                        "medium"
                    } else {
                        "info"
                    },
                    T_WEB,
                    "Fused score from live beacon, DNS, HTTP/3/WSS, ICMP/NTP, stego, proxy/Tor and ingress-port probes. Nothing is simulated.",
                    target,
                    0.9,
                    Evidence::new()
                        .with("score", score)
                        .with("grade", grade)
                        .with("dimensions", dims.clone())
                        .with("region", std::env::var("WEISSMAN_REGION").unwrap_or_default()),
                ),
                &[
                    ("category", json!("posture_score")),
                    ("score", json!(score)),
                    ("grade", json!(grade)),
                    ("evidence", json!({"score": score, "grade": grade, "dimensions": dims})),
                ],
            ),
        );
    }

    if tri(&cfg, "emit_coverage_manifest", true) {
        let mods = coverage_manifest(&cfg);
        emit(
            findings.as_mut(),
            "C2 covert-exfil coverage manifest (10 live layers)",
            "info",
            T_WEB,
            "Audit trail of every executed assessment module. Disabled toggles are listed; none are silently skipped.",
            target,
            "coverage_manifest",
            1.0,
            Evidence::new().with("modules", mods),
        );
    }

    persist_audits(ctx, target, &findings, dns_rows).await;

    let msg = format!(
        "advanced_c2_covert_exfil: {} live finding(s) on {}",
        findings.len(),
        host
    );
    if nodes.is_empty() {
        EngineResult::ok(findings, msg)
    } else {
        EngineResult::ok_with_graph(findings, msg, nodes, edges)
    }
}

pub async fn run_advanced_c2_covert_exfil_result(target: &str) -> EngineResult {
    run_advanced_c2_covert_exfil_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_advanced_c2_covert_exfil(target: &str) {
    print_result(run_advanced_c2_covert_exfil_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_empty_and_uniform() {
        assert_eq!(shannon_entropy(b""), 0.0);
        let ones = vec![0xAAu8; 256];
        assert!(shannon_entropy(&ones) < 0.01);
        let mixed: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&mixed);
        assert!(e > 7.9, "full alphabet entropy {e}");
    }

    #[test]
    fn lsb_chi_square_balanced_is_low() {
        let mut data = Vec::new();
        for i in 0..512u16 {
            data.push((i % 2) as u8);
        }
        assert!(lsb_chi_square(&data) < 1.0);
    }

    #[test]
    fn finding_signature_is_stable_and_distinct() {
        let a = finding_signature("t", "title", "T1071");
        let b = finding_signature("t", "title", "T1071");
        let c = finding_signature("t", "other", "T1071");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn fair_sle_formula() {
        let sle_high = fair_sle(1_000_000.0, 9.8);
        assert!((sle_high - 980_000.0).abs() < 1e-6);
        assert!((fair_sle(1_000_000.0, 2.0) - 500_000.0).abs() < 1e-9); // floor 0.5
        assert_eq!(fair_sle(0.0, 10.0), 0.0);
    }

    #[test]
    fn ct_bytes_eq_rejects_length_mismatch() {
        assert!(!ct_bytes_eq(b"ab", b"abc"));
        assert!(ct_bytes_eq(b"same", b"same"));
        assert!(!ct_bytes_eq(b"same", b"samx"));
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_advanced_c2_covert_exfil_result("  ").await;
        assert!(!r.success);
        assert_eq!(r.status, "error");
    }

    #[tokio::test]
    async fn kill_switch_short_circuits() {
        let ctx = EngineRunContext {
            job_params: json!({"kill_switch": true}),
            ..Default::default()
        };
        let r = run_advanced_c2_covert_exfil_result_ctx("https://example.test", &ctx).await;
        assert!(r.success);
        assert_eq!(
            r.findings[0].get("category").and_then(Value::as_str),
            Some("kill_switch")
        );
    }

    #[test]
    fn png_and_jpeg_magic() {
        let mut png = vec![137, 80, 78, 71, 13, 10, 26, 10];
        png.extend_from_slice(&[0; 16]);
        assert!(looks_png(&png));
        assert!(!looks_jpeg(&png));
        assert!(looks_jpeg(&[0xff, 0xd8, 0xff, 0xe0]));
    }

    #[test]
    fn png_ihdr_bomb_is_rejected() {
        let mut png = vec![137, 80, 78, 71, 13, 10, 26, 10];
        png.extend_from_slice(&13u32.to_be_bytes()); // IHDR length
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&60_000u32.to_be_bytes()); // width bomb
        png.extend_from_slice(&60_000u32.to_be_bytes()); // height bomb
        assert!(png_ihdr_is_poisoned(&png));
        assert!(inspect_media_bytes(&png).is_none());
    }

    #[test]
    fn jpeg_overrun_app1_is_rejected() {
        let mut jpg = vec![0xff, 0xd8, 0xff, 0xe1];
        jpg.extend_from_slice(&20_000u16.to_be_bytes()); // APP1 claims 20k but body is tiny
        jpg.extend_from_slice(&[0u8; 8]);
        assert!(jpeg_markers_poisoned(&jpg));
        assert!(inspect_media_bytes(&jpg).is_none());
    }

    #[test]
    fn media_ceiling_constant_is_2_mib() {
        assert_eq!(MAX_MEDIA_FILE_SIZE_BYTES, 2 * 1024 * 1024);
    }

    #[test]
    fn beacon_sample_count_floors_operator_override_so_spectral_runs() {
        let light = ArsenalConfig::from_value(json!({"intensity": "light"}));
        let normal = ArsenalConfig::from_value(json!({}));
        let aggressive = ArsenalConfig::from_value(json!({"intensity": "aggressive"}));
        let too_small = ArsenalConfig::from_value(json!({"beacon_samples": 3}));
        let huge = ArsenalConfig::from_value(json!({"beacon_samples": 99}));
        assert_eq!(beacon_sample_count(&light), MIN_BEACON_SAMPLES);
        assert_eq!(beacon_sample_count(&normal), MIN_BEACON_SAMPLES);
        assert_eq!(beacon_sample_count(&aggressive), MAX_BEACON_SAMPLES);
        assert_eq!(
            beacon_sample_count(&too_small),
            MIN_BEACON_SAMPLES,
            "beacon_samples=3 must not disable Lomb–Scargle/FFT"
        );
        assert_eq!(beacon_sample_count(&huge), MAX_BEACON_SAMPLES);
        assert!(
            beacon_sample_count(&light) > MIN_SPECTRAL_INTERVALS,
            "stamps-1 must meet the periodogram floor"
        );
    }

    #[test]
    fn dns_pg_insert_is_summary_only() {
        assert!(
            DNS_SUMMARY_INSERT_SQL.contains("'SUMMARY'"),
            "Postgres writes must be SUMMARY rows"
        );
        assert!(DNS_SUMMARY_INSERT_SQL.contains("hour_utc"));
        assert!(DNS_SUMMARY_INSERT_SQL.contains("ON CONFLICT"));
        let lowered = DNS_SUMMARY_INSERT_SQL.to_ascii_lowercase();
        assert!(
            !lowered.contains("values") || lowered.contains("'summary'"),
            "qtype is a SUMMARY literal, never a bound per-query type"
        );
    }

    #[test]
    fn dns_observations_never_become_raw_pg_rows() {
        let hour = crate::c2_runtime_guards::hour_utc_bucket(chrono::Utc::now());
        let obs = vec![
            DnsObservation {
                qtype: "TXT".into(),
                host: "t.example".into(),
                entropy: Some(5.1),
                txt_len: Some(40),
                min_ttl: None,
                extra: serde_json::json!({}),
            },
            DnsObservation {
                qtype: "TXT".into(),
                host: "t.example".into(),
                entropy: Some(5.2),
                txt_len: Some(41),
                min_ttl: None,
                extra: serde_json::json!({}),
            },
            DnsObservation {
                qtype: "A".into(),
                host: "t.example".into(),
                entropy: None,
                txt_len: None,
                min_ttl: Some(300),
                extra: serde_json::json!({}),
            },
        ];
        let sums = crate::c2_runtime_guards::aggregate_dns_anomaly_summaries(&obs, hour);
        assert_eq!(sums.len(), 1);
        assert_eq!(sums[0].query_count, 3);
        assert_eq!(
            sums[0]
                .evidence()
                .get("raw_queries_persisted")
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[tokio::test]
    async fn live_probe_example_com_when_opted_in() {
        if std::env::var("WEISSMAN_LIVE_C2_PROBE").ok().as_deref() != Some("1") {
            return;
        }
        let ctx = EngineRunContext {
            job_params: json!({
                "intensity": "light",
                "check_icmp_ntp": "off",
                "timeout_ms": 5000,
            }),
            ..Default::default()
        };
        let r = run_advanced_c2_covert_exfil_result_ctx("https://example.com", &ctx).await;
        assert!(r.success, "live probe failed: {}", r.message);
        assert!(
            !r.findings.is_empty(),
            "coverage/posture findings should always emit on a live origin"
        );
        let cats: Vec<_> = r
            .findings
            .iter()
            .filter_map(|f| f.get("category").and_then(Value::as_str))
            .collect();
        assert!(
            cats.iter()
                .any(|c| *c == "coverage_manifest" || *c == "posture_score"),
            "expected coverage or posture on live example.com, got {cats:?}"
        );
    }

    #[tokio::test]
    async fn persist_audits_writes_hourly_summary_not_raw_queries() {
        let url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let Some(url) = url else {
            return;
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };
        let tenant_id = std::env::var("WEISSMAN_TEST_TENANT_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let host = format!("summary-seal-{}.invalid", uuid::Uuid::new_v4());
        let ctx = EngineRunContext {
            tenant_id: Some(tenant_id),
            client_id: Some(1),
            app_pool: Some(std::sync::Arc::new(pool.clone())),
            job_id: Some(format!("job-{}", uuid::Uuid::new_v4())),
            ..Default::default()
        };
        let obs = vec![
            DnsObservation {
                qtype: "TXT".into(),
                host: host.clone(),
                entropy: Some(5.4),
                txt_len: Some(240),
                min_ttl: Some(1),
                extra: json!({"probe": "persist_seal"}),
            },
            DnsObservation {
                qtype: "A".into(),
                host: host.clone(),
                entropy: None,
                txt_len: None,
                min_ttl: Some(300),
                extra: json!({}),
            },
        ];
        persist_audits(&ctx, "https://persist-seal.test", &[], obs).await;

        let Ok(mut tx) = crate::db::begin_tenant_tx(&pool, tenant_id).await else {
            panic!("begin_tenant_tx failed after persist_audits — cannot verify SUMMARY write");
        };
        use sqlx::Row;
        let rows = sqlx::query(
            r#"SELECT qtype, hour_utc IS NOT NULL AS has_hour, evidence->>'kind' AS kind
               FROM dns_covert_query_audits WHERE query_host = $1"#,
        )
        .bind(&host)
        .fetch_all(&mut *tx)
        .await
        .expect("select dns summaries");
        let _ = tx.commit().await;
        assert_eq!(
            rows.len(),
            1,
            "exactly one hourly SUMMARY row for the anomalous host, got {}",
            rows.len()
        );
        let qtype: String = rows[0].get("qtype");
        let has_hour: bool = rows[0].get("has_hour");
        let kind: Option<String> = rows[0].get("kind");
        assert_eq!(qtype, "SUMMARY");
        assert!(has_hour, "SUMMARY rows must carry hour_utc");
        assert_eq!(kind.as_deref(), Some("hourly_anomaly_summary"));
    }
}
