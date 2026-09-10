//! Dedicated live probes for web-injection classes and ZTNA/SASE posture.
//!
//! These IDs used to collapse into `http_feedback_fuzz` / `cloud_network_attack`.
//! Each function performs distinct HTTP/TLS/DNS I/O and emits findings only when
//! the live response actually exhibits the class (error strings, reflection,
//! redirect, timing delta, SASE/ZTNA product headers). Empty target → error;
//! no signal → `empty_ok`.

use crate::engine_probes::{
    empty_ok, extract_host, finding, has_header, header_value, http_client, http_get,
    http_get_with_headers, http_post_json, join_url, normalize_url, resolve_ips, tcp_open,
};
use crate::engine_result::EngineResult;
use serde_json::Value;
use std::time::Instant;

fn sql_error_haystack(body: &str, headers: &[(String, String)]) -> bool {
    let h = format!(
        "{} {}",
        body.to_ascii_lowercase(),
        headers
            .iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase()
    );
    const NEEDLES: &[&str] = &[
        "sql syntax",
        "mysql_",
        "mysqli",
        "pg_query",
        "postgresql",
        "ora-00",
        "unclosed quotation",
        "odbc sql",
        "sqlite3.",
        "syntax error at or near",
        "microsoft ole db",
        "sqlstate",
        "you have an error in your sql",
    ];
    NEEDLES.iter().any(|n| h.contains(n))
}

fn reflected_raw(body: &str, token: &str) -> bool {
    !token.is_empty() && body.contains(token)
}

/// Time-based + error-based SQLi against live query params and common login fields.
pub async fn run_sqli_advanced_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();

    let baseline = Instant::now();
    let Some(orig) = http_get(&client, &base).await else {
        return empty_ok("sqli_advanced", t);
    };
    let baseline_ms = baseline.elapsed().as_millis();

    let payloads = [
        ("error", "'\"`) AND 1=CONVERT(int,@@version)--"),
        ("error_pg", "' AND 1=CAST((SELECT version()) AS int)--"),
        ("boolean", "' OR '1'='1"),
    ];
    for (kind, payload) in payloads {
        let url = if base.contains('?') {
            format!("{base}&id={}", urlencoding_lite(payload))
        } else {
            format!("{base}?id={}", urlencoding_lite(payload))
        };
        if let Some(p) = http_get(&client, &url).await {
            if sql_error_haystack(&p.body, &p.headers) {
                findings.push(finding(
                    "sqli_advanced",
                    "SQL error leaked in HTTP response",
                    "high",
                    "T1190",
                    &format!(
                        "Payload class {kind} against {} produced DBMS error text (status {}).",
                        p.final_url, p.status
                    ),
                    t,
                ));
                break;
            }
        }
    }

    let sleepy = if base.contains('?') {
        format!("{base}&id=1'%20AND%20SLEEP(2)--")
    } else {
        format!("{base}?id=1'%20AND%20SLEEP(2)--")
    };
    let t0 = Instant::now();
    let _ = http_get(&client, &sleepy).await;
    let sleepy_ms = t0.elapsed().as_millis();
    if sleepy_ms >= baseline_ms.saturating_add(1500) && sleepy_ms >= 1800 {
        findings.push(finding(
            "sqli_advanced",
            "Time-based SQL delay consistent with SLEEP injection",
            "high",
            "T1190",
            &format!(
                "Baseline GET {} ms; injected SLEEP(2) GET {} ms against {}.",
                baseline_ms, sleepy_ms, orig.final_url
            ),
            t,
        ));
    }

    if findings.is_empty() {
        empty_ok("sqli_advanced", t)
    } else {
        EngineResult::ok(findings.clone(), format!("sqli_advanced: {}", findings.len()))
    }
}

/// Reflected XSS: unique canary must come back unencoded.
pub async fn run_xss_advanced_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let canary = format!(
        "weissmanxss{}",
        &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]
    );
    let payload = format!("\"'><svg/onload=alert({canary})>");
    let url = if base.contains('?') {
        format!("{base}&q={}", urlencoding_lite(&payload))
    } else {
        format!("{base}?q={}", urlencoding_lite(&payload))
    };
    let Some(p) = http_get(&client, &url).await else {
        return empty_ok("xss_advanced", t);
    };
    if reflected_raw(&p.body, &canary) && p.body.contains("<svg") {
        EngineResult::ok(
            vec![finding(
                "xss_advanced",
                "Reflected XSS canary returned unencoded",
                "high",
                "T1059.007",
                &format!(
                    "Canary {canary} and raw <svg markup reflected from {} (status {}).",
                    p.final_url, p.status
                ),
                t,
            )],
            "xss_advanced: 1",
        )
    } else if reflected_raw(&p.body, &canary) {
        EngineResult::ok(
            vec![finding(
                "xss_advanced",
                "User input reflected (encoding to verify)",
                "medium",
                "T1059.007",
                &format!(
                    "Canary {canary} reflected from {} — markup appears encoded or filtered.",
                    p.final_url
                ),
                t,
            )],
            "xss_advanced: 1",
        )
    } else {
        empty_ok("xss_advanced", t)
    }
}

/// CSRF: cookie SameSite missing + state-changing form without token.
pub async fn run_csrf_exploit_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let Some(p) = http_get(&client, &url).await else {
        return empty_ok("csrf_exploit", t);
    };
    let mut findings = Vec::new();
    let set_cookie = header_value(&p.headers, "set-cookie").unwrap_or("");
    if !set_cookie.is_empty()
        && !set_cookie.to_ascii_lowercase().contains("samesite")
    {
        findings.push(finding(
            "csrf_exploit",
            "Session cookie lacks SameSite",
            "medium",
            "T1185",
            &format!(
                "Set-Cookie from {} has no SameSite attribute — cross-site POST can ride the session.",
                p.final_url
            ),
            t,
        ));
    }
    let body_l = p.body.to_ascii_lowercase();
    if body_l.contains("<form")
        && !body_l.contains("csrf")
        && !body_l.contains("_token")
        && !body_l.contains("authenticity_token")
    {
        findings.push(finding(
            "csrf_exploit",
            "HTML form without CSRF token field",
            "medium",
            "T1185",
            &format!(
                "Page {} renders a form without csrf/_token/authenticity_token fields.",
                p.final_url
            ),
            t,
        ));
    }
    if findings.is_empty() {
        empty_ok("csrf_exploit", t)
    } else {
        EngineResult::ok(findings.clone(), format!("csrf_exploit: {}", findings.len()))
    }
}

/// Mongo/Couch operator injection via JSON POST and query-string.
pub async fn run_nosql_injection_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let payload = serde_json::json!({ "username": { "$gt": "" }, "password": { "$gt": "" } });
    let mut findings = Vec::new();
    if let Some(p) = http_post_json(&client, &url, &payload).await {
        let bl = p.body.to_ascii_lowercase();
        if p.status == 200
            && (bl.contains("mongodb")
                || bl.contains("\"ok\":true")
                || bl.contains("token")
                || bl.contains("session"))
            && !bl.contains("invalid")
        {
            findings.push(finding(
                "nosql_injection",
                "JSON $gt operator accepted by API",
                "high",
                "T1190",
                &format!(
                    "POST {{username:{{$gt:\"\"}}}} to {} returned HTTP {} with session-like body.",
                    p.final_url, p.status
                ),
                t,
            ));
        }
    }
    let qurl = format!("{url}{}", if url.contains('?') { "&" } else { "?" });
    let qurl = format!("{qurl}user[$gt]=");
    if let Some(p) = http_get(&client, &qurl).await {
        if sql_error_haystack(&p.body, &p.headers)
            || p.body.to_ascii_lowercase().contains("mongo")
        {
            findings.push(finding(
                "nosql_injection",
                "Query-string $gt reached data layer",
                "medium",
                "T1190",
                &format!("GET {} surfaced data-layer error/mongo text.", p.final_url),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("nosql_injection", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("nosql_injection: {}", findings.len()),
        )
    }
}

/// Open redirect via common parameter names.
pub async fn run_open_redirect_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let evil = "https://weissman-redirect-check.invalid/landing";
    let params = ["url", "next", "redirect", "return", "returnUrl", "continue", "dest"];
    for param in params {
        let url = if base.contains('?') {
            format!("{base}&{param}={}", urlencoding_lite(evil))
        } else {
            format!("{base}?{param}={}", urlencoding_lite(evil))
        };
        if let Some(p) = http_get(&client, &url).await {
            let loc = header_value(&p.headers, "location").unwrap_or("");
            if (p.status == 301 || p.status == 302 || p.status == 303 || p.status == 307)
                && loc.contains("weissman-redirect-check.invalid")
            {
                return EngineResult::ok(
                    vec![finding(
                        "open_redirect",
                        "Open redirect via Location header",
                        "medium",
                        "T1566",
                        &format!(
                            "Parameter {param} on {} redirected to {loc} (status {}).",
                            p.final_url, p.status
                        ),
                        t,
                    )],
                    "open_redirect: 1",
                );
            }
        }
    }
    empty_ok("open_redirect", t)
}

/// Parallel request TOCTOU: divergent Set-Cookie / body hashes under concurrency.
pub async fn run_race_condition_web_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let mut futs = Vec::new();
    for _ in 0..8 {
        futs.push(http_get(&client, &url));
    }
    let results = futures::future::join_all(futs).await;
    let probes: Vec<_> = results.into_iter().flatten().collect();
    if probes.len() < 4 {
        return empty_ok("race_condition_web", t);
    }
    let hashes: std::collections::BTreeSet<u64> = probes
        .iter()
        .map(|p| {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            p.body.hash(&mut h);
            header_value(&p.headers, "set-cookie")
                .unwrap_or("")
                .hash(&mut h);
            h.finish()
        })
        .collect();
    if hashes.len() > 1 {
        EngineResult::ok(
            vec![finding(
                "race_condition_web",
                "Concurrent GETs returned divergent bodies or session cookies",
                "medium",
                "T1499.003",
                &format!(
                    "{} parallel GETs to {} produced {} distinct response fingerprints — TOCTOU/session race surface.",
                    probes.len(),
                    url,
                    hashes.len()
                ),
                t,
            )],
            "race_condition_web: 1",
        )
    } else {
        empty_ok("race_condition_web", t)
    }
}

/// REST surface fuzz: OpenAPI, unusual methods, mass-assignment-shaped JSON.
pub async fn run_api_fuzzing_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings = Vec::new();
    let paths = [
        "/openapi.json",
        "/swagger.json",
        "/api/docs",
        "/v1",
        "/api/v1",
        "/graphql",
    ];
    let hits = crate::engine_probes::probe_paths_concurrent(&client, &base, &paths, 6).await;
    for p in hits {
        if p.status == 200 && (p.body.contains("\"openapi\"") || p.body.contains("\"swagger\""))
        {
            findings.push(finding(
                "api_fuzzing",
                "OpenAPI/Swagger document publicly reachable",
                "medium",
                "T1190",
                &format!("{} returned API schema ({} bytes).", p.final_url, p.body.len()),
                t,
            ));
        } else if p.status == 200 && p.final_url.contains("graphql") {
            findings.push(finding(
                "api_fuzzing",
                "GraphQL endpoint reachable without auth",
                "medium",
                "T1190",
                &format!("{} HTTP 200 on GraphQL path.", p.final_url),
                t,
            ));
        }
    }
    let proto = serde_json::json!({ "__proto__": { "admin": true }, "constructor": { "prototype": { "admin": true } } });
    if let Some(p) = http_post_json(&client, &base, &proto).await {
        if p.status == 200 && p.body.to_ascii_lowercase().contains("admin") {
            findings.push(finding(
                "api_fuzzing",
                "Prototype-pollution JSON keys accepted",
                "high",
                "T1190",
                &format!(
                    "POST __proto__ to {} returned HTTP {} with admin-like body.",
                    p.final_url, p.status
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("api_fuzzing", t)
    } else {
        EngineResult::ok(findings.clone(), format!("api_fuzzing: {}", findings.len()))
    }
}

/// Real ZTNA/IdP/device-posture probes — not HSTS-only.
pub async fn run_zero_trust_bypass_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let host = extract_host(t);
    let mut findings = Vec::new();

    let Some(p) = http_get(&client, &url).await else {
        return empty_ok("zero_trust_bypass", t);
    };

    if crate::live_truth::observe_hsts_probe(&p).emit_missing() {
        findings.push(finding(
            "zero_trust_bypass",
            "Protected resource missing HSTS",
            "low",
            "T1078",
            &format!("{} lacks Strict-Transport-Security.", p.final_url),
            t,
        ));
    }

    let cf_access = header_value(&p.headers, "cf-access-authenticated-user-email")
        .or_else(|| header_value(&p.headers, "cf-ray"));
    let has_cf_login = p.body.contains("Cloudflare Access") || p.final_url.contains("cloudflareaccess.com");
    let has_okta = p.body.contains("okta-signin") || host.contains("okta.com");
    let has_zscaler = has_header(&p.headers, "x-zscaler")
        || p.body.to_ascii_lowercase().contains("zscaler");
    let has_prisma = p.body.to_ascii_lowercase().contains("globalprotect")
        || p.body.to_ascii_lowercase().contains("prisma access");
    let www_auth = header_value(&p.headers, "www-authenticate");

    if p.status == 200
        && www_auth.is_none()
        && !has_cf_login
        && !has_okta
        && !has_zscaler
        && !has_prisma
        && !p.body.to_ascii_lowercase().contains("sign in")
    {
        findings.push(finding(
            "zero_trust_bypass",
            "App reachable without ZTNA challenge",
            "high",
            "T1078",
            &format!(
                "{} returned HTTP 200 with no WWW-Authenticate, Cloudflare Access, Okta, Zscaler, or Prisma challenge — identity-aware proxy not enforcing.",
                p.final_url
            ),
            t,
        ));
    }

    if let Some(acao) = header_value(&p.headers, "access-control-allow-origin") {
        if acao.trim() == "*" {
            findings.push(finding(
                "zero_trust_bypass",
                "ZT app CORS allows any origin",
                "medium",
                "T1078",
                &format!(
                    "{} Access-Control-Allow-Origin: * — browser session can be abused cross-site.",
                    p.final_url
                ),
                t,
            ));
        }
    }

    let admin = join_url(&url, "/admin");
    if let Some(a) = http_get(&client, &admin).await {
        if a.status == 200 && !a.body.to_ascii_lowercase().contains("login") {
            findings.push(finding(
                "zero_trust_bypass",
                "Admin path reachable without identity challenge",
                "high",
                "T1078",
                &format!("{} HTTP {}", a.final_url, a.status),
                t,
            ));
        }
    }

    if cf_access.is_some() && p.status == 200 {
        findings.push(finding(
            "zero_trust_bypass",
            "Cloudflare Access headers present on 200 — device posture not blocking",
            "medium",
            "T1078",
            &format!(
                "{} served content with CF Access telemetry while HTTP 200 — confirm device-posture rules.",
                p.final_url
            ),
            t,
        ));
    }

    let _ = tcp_open(&host, 443).await;

    if findings.is_empty() {
        empty_ok("zero_trust_bypass", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("zero_trust_bypass: {}", findings.len()),
        )
    }
}

/// SASE/SSE bypass: product fingerprints, split-tunnel (direct IP vs name), SWG headers.
pub async fn run_sase_security_bypass_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let host = extract_host(t);
    let mut findings = Vec::new();

    let Some(named) = http_get(&client, &url).await else {
        return empty_ok("sase_security_bypass", t);
    };

    let hay = format!(
        "{} {}",
        named.body.to_ascii_lowercase(),
        named
            .headers
            .iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase()
    );
    let sase_vendor = if hay.contains("zscaler") || hay.contains("z-tunnel") {
        Some("Zscaler")
    } else if hay.contains("netskope") {
        Some("Netskope")
    } else if hay.contains("prisma access") || hay.contains("globalprotect") {
        Some("Palo Alto Prisma Access")
    } else if hay.contains("cloudflare access") || hay.contains("cf-access") {
        Some("Cloudflare SSE")
    } else {
        None
    };

    if sase_vendor.is_none()
        && header_value(&named.headers, "x-forwarded-for").is_none()
        && named.status == 200
    {
        findings.push(finding(
            "sase_security_bypass",
            "No SASE/SWG fingerprint on egress",
            "medium",
            "T1685",
            &format!(
                "{} HTTP {} lacks Zscaler/Netskope/Prisma/Cloudflare Access headers — traffic may bypass the SSE fabric (split tunnel).",
                named.final_url, named.status
            ),
            t,
        ));
    }

    let ips = resolve_ips(&host);
    if let Some(ip) = ips.iter().find(|i| !i.starts_with('[') && *i != "127.0.0.1") {
        let ip_url = url.replacen(&host, ip, 1);
        if let Some(direct) = http_get_with_headers(
            &client,
            &ip_url,
            &[("Host", host.as_str()), ("user-agent", "Weissman-SASE-Probe/1")],
        )
        .await
        {
            if direct.status == 200 && named.status != 200 {
                findings.push(finding(
                    "sase_security_bypass",
                    "Direct-IP access succeeded while hostname was challenged",
                    "high",
                    "T1685",
                    &format!(
                        "Host {} blocked/challenged; raw IP {} returned HTTP {} — classic split-tunnel/CASB bypass.",
                        host, ip, direct.status
                    ),
                    t,
                ));
            }
        }
    }

    for path in ["/global-protect/login.esp", "/dana-na/auth/url_default/welcome.cgi"] {
        let u = join_url(&url, path);
        if let Some(p) = http_get(&client, &u).await {
            if p.status == 200 {
                findings.push(finding(
                    "sase_security_bypass",
                    "VPN/ZTNA portal exposed",
                    "info",
                    "T1685",
                    &format!("{} reachable (status {}).", p.final_url, p.status),
                    t,
                ));
            }
        }
    }

    if findings.is_empty() {
        empty_ok("sase_security_bypass", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("sase_security_bypass: {}", findings.len()),
        )
    }
}

fn urlencoding_lite(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_target_errors() {
        assert!(!run_sqli_advanced_result("").await.success);
        assert!(!run_xss_advanced_result("").await.success);
        assert!(!run_csrf_exploit_result("").await.success);
        assert!(!run_nosql_injection_result("").await.success);
        assert!(!run_open_redirect_result("").await.success);
        assert!(!run_race_condition_web_result("").await.success);
        assert!(!run_api_fuzzing_result("").await.success);
        assert!(!run_zero_trust_bypass_result("").await.success);
        assert!(!run_sase_security_bypass_result("").await.success);
    }

    #[test]
    fn sql_error_detects_mysql() {
        assert!(sql_error_haystack(
            "You have an error in your SQL syntax",
            &[]
        ));
        assert!(!sql_error_haystack("hello world", &[]));
    }
}
