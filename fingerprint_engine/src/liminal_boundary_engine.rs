//! **Liminal Boundary Engine** — discovers fractures at invisible trust boundaries that
//! conventional scanners never cross systematically.
//!
//! Most WAF/CDN/reverse-proxy stacks apply *different* routing, auth, and inspection rules
//! depending on whether the client speaks HTTP/1.1 or HTTP/2, which cache-key dimensions
//! vary the stored object, and which "trusted" rewrite headers the edge forwards. Attackers
//! exploit these liminal gaps daily; this engine probes them with live traffic only — zero
//! simulated findings.
//!
//! Probes:
//! 1. **Protocol schism** — same URL over HTTP/1.1-only vs HTTP/2 (ALPN); flags status/body
//!    divergence (e.g. 403 on h1 → 200 on h2 = auth bypass at the protocol boundary).
//! 2. **Cache Vary oracle** — content that changes with `Accept-Language` or `Cookie` but
//!    lacks a correct `Vary` + is publicly cacheable → personalized/auth content leak.
//! 3. **Trusted-header rewrite** — `X-Original-URL` / `X-Rewrite-URL` / `X-Forwarded-Prefix`
//!    causing the edge to serve a different resource than the path suggests.
//! 4. **Entropy divergence** — identical HTTP status but radically different response entropy
//!    across protocol stacks → shadow API tier / canary path exposure.

use crate::engine_probes::{
    empty_ok, extract_host, finding, header_value, http_get_with_headers, http1_client,
    http2_client, normalize_url, HttpProbe,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

const PROBE_PATHS: &[&str] = &["/", "/admin", "/api", "/api/v1", "/internal", "/dashboard"];

#[derive(Debug)]
struct ProbePair {
    path: String,
    h1: HttpProbe,
    h2: HttpProbe,
}

fn body_sha256(body: &str) -> String {
    format!("{:x}", Sha256::digest(body.as_bytes()))
}

/// Shannon entropy (bits/byte) — high for structured JSON/API, low for error HTML.
fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in data.bytes() {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn is_auth_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn is_auth_block(status: u16) -> bool {
    matches!(status, 401 | 403 | 405)
}

async fn fetch_protocol_pair(base: &str, path: &str) -> Option<ProbePair> {
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let h1c = http1_client().await;
    let h2c = http2_client().await;
    let h1 = http_get_with_headers(&h1c, &url, &[]).await?;
    let h2 = http_get_with_headers(&h2c, &url, &[]).await?;
    Some(ProbePair {
        path: path.to_string(),
        h1,
        h2,
    })
}

fn probe_protocol_schism(target: &str, pair: &ProbePair, findings: &mut Vec<Value>) {
    let h1 = &pair.h1;
    let h2 = &pair.h2;
    let h1_hash = body_sha256(&h1.body);
    let h2_hash = body_sha256(&h2.body);

    // Classic auth bypass: blocked on one stack, open on the other.
    if is_auth_block(h1.status) && is_auth_success(h2.status) {
        findings.push(finding(
            "liminal_boundary",
            &format!(
                "Protocol schism auth bypass on {} (HTTP/1.1 {} → HTTP/2 {})",
                pair.path, h1.status, h2.status
            ),
            "critical",
            "T1190",
            &format!(
                "The path {} on {} returns HTTP {} over HTTP/1.1 but HTTP {} over HTTP/2 \
                 (ALPN). The WAF/reverse-proxy applies inconsistent access control across \
                 protocol stacks — a known bypass class no commercial scanner tests systematically. \
                 Evidence: h1_body_sha256={} h2_body_sha256={} h2_body_len={}",
                pair.path,
                target,
                h1.status,
                h2.status,
                &h1_hash[..16],
                &h2_hash[..16],
                h2.body.len()
            ),
            target,
        ));
        return;
    }
    if is_auth_block(h2.status) && is_auth_success(h1.status) {
        findings.push(finding(
            "liminal_boundary",
            &format!(
                "Protocol schism auth bypass on {} (HTTP/2 {} → HTTP/1.1 {})",
                pair.path, h2.status, h1.status
            ),
            "critical",
            "T1190",
            &format!(
                "The path {} on {} is blocked over HTTP/2 (HTTP {}) but accessible over HTTP/1.1 \
                 (HTTP {}). Attackers can downgrade/upgrade protocol to bypass edge controls. \
                 Evidence: h1_body_sha256={} h2_body_sha256={}",
                pair.path, target, h2.status, h1.status, &h1_hash[..16], &h2_hash[..16]
            ),
            target,
        ));
        return;
    }

    // Same 2xx but materially different bodies → shadow stack / canary path.
    if is_auth_success(h1.status)
        && h1.status == h2.status
        && h1_hash != h2_hash
        && body_size_delta_ratio(&h1.body, &h2.body) > 0.15
    {
        let e1 = shannon_entropy(&h1.body);
        let e2 = shannon_entropy(&h2.body);
        let sev = if (e1 - e2).abs() > 2.0 { "high" } else { "medium" };
        findings.push(finding(
            "liminal_boundary",
            &format!(
                "Protocol schism body divergence on {} (HTTP {} both stacks, different content)",
                pair.path, h1.status
            ),
            sev,
            "T1190",
            &format!(
                "Path {} returns HTTP {} on both HTTP/1.1 and HTTP/2 but the response bodies \
                 differ (h1_len={} h2_len={} h1_entropy={:.2} h2_entropy={:.2}). This indicates \
                 separate backend pools or canary deployments reachable only via one protocol — \
                 a liminal fracture attackers use to reach unfixed code paths.",
                pair.path,
                h1.status,
                h1.body.len(),
                h2.body.len(),
                e1,
                e2
            ),
            target,
        ));
    }
}

fn body_size_delta_ratio(a: &str, b: &str) -> f64 {
    let la = a.len().max(1) as f64;
    let lb = b.len().max(1) as f64;
    (la - lb).abs() / la.max(lb)
}

async fn probe_cache_vary_oracle(
    target: &str,
    base: &str,
    findings: &mut Vec<Value>,
) {
    let client = http1_client().await;
    let url = format!("{}/", base.trim_end_matches('/'));
    let baseline = match http_get_with_headers(&client, &url, &[]).await {
        Some(p) => p,
        None => return,
    };
    let lang_a = http_get_with_headers(
        &client,
        &url,
        &[("Accept-Language", "en-US,en;q=0.9")],
    )
    .await;
    let lang_b = http_get_with_headers(
        &client,
        &url,
        &[("Accept-Language", "zh-CN,zh;q=0.9")],
    )
    .await;
    if let (Some(a), Some(b)) = (lang_a, lang_b) {
        let hash_a = body_sha256(&a.body);
        let hash_b = body_sha256(&b.body);
        if hash_a != hash_b && a.status == b.status && is_auth_success(a.status) {
            let cache_ctrl = header_value(&a.headers, "cache-control").unwrap_or("");
            let vary = header_value(&a.headers, "vary").unwrap_or("");
            let publicly_cacheable = cache_ctrl.contains("public")
                || cache_ctrl.contains("s-maxage")
                || (!cache_ctrl.contains("private") && !cache_ctrl.contains("no-store"));
            let vary_ok = vary.to_ascii_lowercase().contains("accept-language");
            if publicly_cacheable && !vary_ok {
                findings.push(finding(
                    "liminal_boundary",
                    "Cache Vary oracle — language-variant content publicly cacheable without Vary",
                    "high",
                    "T1190",
                    &format!(
                        "Responses at {} differ by Accept-Language (sha256 {} vs {}) with HTTP {} \
                         but Cache-Control='{}' and Vary='{}'. A shared CDN cache may serve one \
                         user's language/session-specific content to another — a liminal cache-key \
                         fracture not covered by traditional cache-poisoning scanners.",
                        url,
                        &hash_a[..12],
                        &hash_b[..12],
                        a.status,
                        cache_ctrl,
                        vary
                    ),
                    target,
                ));
            }
        }
    }

    // Cookie dimension: anonymous vs synthetic session cookie.
    if let Some(with_cookie) = http_get_with_headers(
        &client,
        &url,
        &[("Cookie", "session=weissman-liminal-probe")],
    )
    .await
    {
        let base_hash = body_sha256(&baseline.body);
        let cookie_hash = body_sha256(&with_cookie.body);
        if base_hash != cookie_hash
            && baseline.status == with_cookie.status
            && is_auth_success(baseline.status)
        {
            let cache_ctrl = header_value(&baseline.headers, "cache-control").unwrap_or("");
            let vary = header_value(&baseline.headers, "vary").unwrap_or("");
            let publicly_cacheable = cache_ctrl.contains("public")
                || (!cache_ctrl.contains("private") && !cache_ctrl.contains("no-store"));
            let vary_ok = vary.to_ascii_lowercase().contains("cookie");
            if publicly_cacheable && !vary_ok {
                findings.push(finding(
                    "liminal_boundary",
                    "Cache Vary oracle — cookie-variant content cacheable without Vary: Cookie",
                    "critical",
                    "T1190",
                    &format!(
                        "The homepage at {} returns different content when a Cookie header is present \
                         (anonymous sha256={} vs cookie sha256={}) but lacks Vary: Cookie while being \
                         publicly cacheable (Cache-Control='{}'). Authenticated page fragments can be \
                         served to anonymous users via CDN — a boundary failure invisible to path-based scanners.",
                        url,
                        &base_hash[..12],
                        &cookie_hash[..12],
                        cache_ctrl
                    ),
                    target,
                ));
            }
        }
    }
}

async fn probe_trusted_header_rewrite(
    target: &str,
    base: &str,
    findings: &mut Vec<Value>,
) {
    let client = http1_client().await;
    let sensitive = ["/admin", "/api/admin", "/internal", "/manager", "/console"];
    for path in sensitive {
        let direct_url = format!("{}{}", base.trim_end_matches('/'), path);
        let direct = match http_get_with_headers(&client, &direct_url, &[]).await {
            Some(p) => p,
            None => continue,
        };
        let root_url = format!("{}/", base.trim_end_matches('/'));
        for (header, _label) in [
            ("X-Original-URL", "X-Original-URL"),
            ("X-Rewrite-URL", "X-Rewrite-URL"),
            ("X-Forwarded-Prefix", "X-Forwarded-Prefix"),
        ] {
            if let Some(rewritten) =
                http_get_with_headers(&client, &root_url, &[(header, path)]).await
            {
                let direct_hash = body_sha256(&direct.body);
                let rewrite_hash = body_sha256(&rewritten.body);
                // Rewrite via trusted header reached the same resource with better auth outcome.
                if rewrite_hash == direct_hash
                    && is_auth_success(rewritten.status)
                    && is_auth_block(direct.status)
                {
                    findings.push(finding(
                        "liminal_boundary",
                        &format!(
                            "Trusted-header rewrite bypass via {} → {}",
                            header, path
                        ),
                        "critical",
                        "T1190",
                        &format!(
                            "GET {} returns HTTP {} but GET / with {}: {} returns HTTP {} with \
                             identical body (sha256={}). The edge trusts {} for internal routing \
                             while the direct path is blocked — a liminal trust-boundary fracture.",
                            direct_url,
                            direct.status,
                            header,
                            path,
                            rewritten.status,
                            &direct_hash[..16],
                            header
                        ),
                        target,
                    ));
                } else if rewrite_hash == direct_hash
                    && rewritten.status == direct.status
                    && is_auth_success(rewritten.status)
                    && direct.body.len() > 64
                {
                    findings.push(finding(
                        "liminal_boundary",
                        &format!("Trusted-header {} exposes {}", header, path),
                        "high",
                        "T1190",
                        &format!(
                            "Header {}: {} on GET / returns the same content as GET {} (HTTP {}, \
                             body_len={}). Internal/admin paths are reachable through header-based \
                             rewrite — invisible to URL-only crawlers.",
                            header,
                            path,
                            path,
                            rewritten.status,
                            rewritten.body.len()
                        ),
                        target,
                    ));
                }
            }
        }
    }
}

pub async fn run_liminal_boundary_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_url(target);
    let host = extract_host(target);
    if host.is_empty() {
        return EngineResult::error("invalid target host");
    }

    let mut findings: Vec<Value> = Vec::new();

    // Only HTTPS targets support meaningful HTTP/2 ALPN comparison.
    let is_https = base.starts_with("https://");
    if is_https {
        for path in PROBE_PATHS {
            if let Some(pair) = fetch_protocol_pair(&base, path).await {
                probe_protocol_schism(target, &pair, &mut findings);
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
    }

    probe_cache_vary_oracle(target, &base, &mut findings).await;
    probe_trusted_header_rewrite(target, &base, &mut findings).await;

    // Attach structured evidence block for downstream correlation.
    for f in &mut findings {
        if let Some(obj) = f.as_object_mut() {
            obj.insert(
                "evidence".into(),
                json!({
                    "engine": "liminal_boundary",
                    "probe_class": "live_http_boundary",
                    "host": host,
                    "protocol_schism_tested": is_https,
                }),
            );
            obj.insert("cwe".into(), json!("CWE-693"));
        }
    }

    if findings.is_empty() {
        empty_ok("liminal_boundary", target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!("liminal_boundary: {} live boundary fracture(s) on {}", n, host),
        )
    }
}

cli_wrapper!(run_liminal_boundary, run_liminal_boundary_result);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_json_higher_than_repeated_char() {
        let json = r#"{"users":[{"id":1,"email":"a@b.c","role":"admin"},{"id":2,"email":"x@y.z","role":"user"}]}"#;
        let flat = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(shannon_entropy(json) > shannon_entropy(flat));
    }

    #[test]
    fn body_size_delta_detects_material_change() {
        assert!(body_size_delta_ratio("a", "abcdefghij") > 0.15);
        assert!(body_size_delta_ratio("same", "same") < 0.01);
    }

    #[test]
    fn auth_classifiers() {
        assert!(is_auth_block(403));
        assert!(is_auth_success(200));
    }
}
