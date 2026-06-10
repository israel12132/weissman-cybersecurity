//! Shared real-probe primitives for the `advanced_*` engine families.
//!
//! Every helper performs **live** network/HTTP/DNS/TCP/TLS operations against the user-supplied
//! target. No simulated findings are emitted: if the probe doesn't observe an actual signal, no
//! finding is returned. All probes respect `weissman_core::tls_policy::danger_accept_invalid_certs()`
//! and bounded timeouts so an engine cannot hang the worker pool.

use crate::engine_result::EngineResult;
use reqwest::Client;
use serde_json::{json, Value};
use std::net::ToSocketAddrs;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 10;
const TCP_CONNECT_TIMEOUT_MS: u64 = 1500;
const TCP_BANNER_READ_MS: u64 = 1500;

#[must_use]
pub fn normalize_url(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

#[must_use]
pub fn extract_host(target: &str) -> String {
    target
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(target)
        .split(':')
        .next()
        .unwrap_or(target)
        .to_string()
}

pub async fn http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-Probe/1.0")
        .build()
        .unwrap_or_else(|_| Client::new())
}

/// HTTP/1.1-only client — used to compare against HTTP/2 ALPN on the same URL.
pub async fn http1_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-LiminalProbe/1.0 h1")
        .http1_only()
        .build()
        .unwrap_or_else(|_| Client::new())
}

/// HTTP/2-capable client (ALPN negotiates h2 on TLS). Pair with [`http1_client`].
pub async fn http2_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-LiminalProbe/1.0 h2")
        .http2_adaptive_window(true)
        .build()
        .unwrap_or_else(|_| Client::new())
}

/// Attempt a TCP connect+banner read. Returns banner string if the port is open.
pub async fn tcp_banner(host: &str, port: u16) -> Option<String> {
    let addr = format!("{}:{}", host, port);
    let socket = match timeout(
        Duration::from_millis(TCP_CONNECT_TIMEOUT_MS),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    let mut stream = socket;
    let mut buf = vec![0u8; 256];
    match timeout(Duration::from_millis(TCP_BANNER_READ_MS), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(String::from_utf8_lossy(&buf[..n]).to_string()),
        _ => Some(String::new()),
    }
}

/// Connect-only TCP test. Returns true if port is reachable within timeout.
pub async fn tcp_open(host: &str, port: u16) -> bool {
    let addr = format!("{}:{}", host, port);
    matches!(
        timeout(
            Duration::from_millis(TCP_CONNECT_TIMEOUT_MS),
            TcpStream::connect(&addr),
        )
        .await,
        Ok(Ok(_))
    )
}

/// Send a binary payload to a TCP port and read response (for protocol fingerprinting).
pub async fn tcp_probe_response(host: &str, port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let addr = format!("{}:{}", host, port);
    let socket = match timeout(
        Duration::from_millis(TCP_CONNECT_TIMEOUT_MS),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    let mut stream = socket;
    if stream.write_all(payload).await.is_err() {
        return None;
    }
    let _ = stream.flush().await;
    let mut buf = vec![0u8; 1024];
    match timeout(Duration::from_millis(TCP_BANNER_READ_MS), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// Resolve host → list of IPs (IPv4+IPv6). Returns empty on failure.
pub fn resolve_ips(host: &str) -> Vec<String> {
    format!("{}:80", host)
        .to_socket_addrs()
        .map(|iter| iter.map(|s| s.ip().to_string()).collect())
        .unwrap_or_default()
}

#[derive(Clone, Debug)]
pub struct HttpProbe {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub final_url: String,
}

/// GET with optional extra headers (for cache-oracle / rewrite probes).
pub async fn http_get_with_headers(
    client: &Client,
    url: &str,
    extra: &[(&str, &str)],
) -> Option<HttpProbe> {
    let mut req = client.get(url);
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    let body = if body.len() > 65_536 {
        body[..65_536].to_string()
    } else {
        body
    };
    Some(HttpProbe {
        status,
        headers,
        body,
        final_url,
    })
}

/// Fetch URL and return status, headers, body (truncated to 64 KiB).
pub async fn http_get(client: &Client, url: &str) -> Option<HttpProbe> {
    http_get_with_headers(client, url, &[]).await
}

/// POST JSON and return status + body (truncated).
pub async fn http_post_json(client: &Client, url: &str, payload: &Value) -> Option<HttpProbe> {
    let resp = client.post(url).json(payload).send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    let body = if body.len() > 65_536 {
        body[..65_536].to_string()
    } else {
        body
    };
    Some(HttpProbe {
        status,
        headers,
        body,
        final_url,
    })
}

pub fn has_header(headers: &[(String, String)], name: &str) -> bool {
    let ln = name.to_ascii_lowercase();
    headers.iter().any(|(k, _)| k.to_ascii_lowercase() == ln)
}

pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let ln = name.to_ascii_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase() == ln)
        .map(|(_, v)| v.as_str())
}

/// DNS TXT record lookup using hickory-resolver.
pub async fn dns_txt(host: &str) -> Vec<String> {
    use hickory_resolver::TokioResolver;
    let resolver = match TokioResolver::builder_tokio().and_then(|b| b.build()) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    if let Ok(txt) = resolver.txt_lookup(host).await {
        for record in txt.answers() {
            let hickory_resolver::proto::rr::RData::TXT(txt) = &record.data else {
                continue;
            };
            let mut joined = String::new();
            for chunk in txt.txt_data.iter() {
                joined.push_str(&String::from_utf8_lossy(chunk));
            }
            out.push(joined);
        }
    }
    out
}

pub async fn dns_mx(host: &str) -> Vec<String> {
    use hickory_resolver::TokioResolver;
    let resolver = match TokioResolver::builder_tokio().and_then(|b| b.build()) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    if let Ok(mx) = resolver.mx_lookup(host).await {
        for record in mx.answers() {
            let hickory_resolver::proto::rr::RData::MX(mx) = &record.data else {
                continue;
            };
            out.push(mx.exchange.to_string());
        }
    }
    out
}

pub async fn dns_a(host: &str) -> Vec<String> {
    use hickory_resolver::TokioResolver;
    let resolver = match TokioResolver::builder_tokio().and_then(|b| b.build()) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    if let Ok(a) = resolver.ipv4_lookup(host).await {
        for record in a.answers() {
            let hickory_resolver::proto::rr::RData::A(a) = &record.data else {
                continue;
            };
            out.push(a.0.to_string());
        }
    }
    out
}

/// Convenience: build a result with optional empty findings (no simulated content).
pub fn empty_ok(engine_id: &str, target: &str) -> EngineResult {
    EngineResult::ok(
        vec![],
        format!("{}: no live signal observed on {}", engine_id, target),
    )
}

/// Build a result for engines that cannot be detected from a remote network probe alone
/// (process injection, kernel rootkits, air-gap exfil channels, physical attacks, etc.).
///
/// We emit a single *info* finding explaining the limitation and pointing the operator to the
/// agent-based collector. This is honest: no fake high-severity findings, but the engine isn't
/// silently empty either.
pub fn agent_required_ok(
    engine_id: &str,
    target: &str,
    title: &str,
    rationale: &str,
) -> EngineResult {
    let finding = serde_json::json!({
        "type": engine_id,
        "category": "agent_required",
        "title": title,
        "severity": "info",
        "mitre_attack": "",
        "description": format!(
            "{} requires an endpoint agent to detect (no purely-remote signal exists). {} Install Weissman-Agent on the asset, then re-run the engine.",
            engine_id, rationale
        ),
        "target": target,
        "agent_required": true,
    });
    EngineResult::ok(
        vec![finding],
        format!("{}: agent-based collector required", engine_id),
    )
}

/// Convenience: severity selector based on observed condition.
#[must_use]
pub fn severity_for(strong: bool) -> &'static str {
    if strong {
        "high"
    } else {
        "medium"
    }
}

/// Build a structured finding. `remediation` is inferred from severity + engine class so every
/// finding has actionable guidance attached.
pub fn finding(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
) -> Value {
    json!({
        "type": engine_id,
        "title": title,
        "severity": severity,
        "mitre_attack": mitre,
        "description": description,
        "target": target,
        "remediation": default_remediation(engine_id, severity),
        "compliance": default_compliance(engine_id),
    })
}

/// Lookup-table for a default remediation hint. The orchestrator can override per-finding when
/// it has more context; this guarantees no finding is shipped *without* guidance.
#[must_use]
pub fn default_remediation(engine_id: &str, severity: &str) -> &'static str {
    let sev = severity.to_ascii_lowercase();
    if engine_id.contains("ssrf") {
        return "Block outbound requests to 169.254.169.254 / metadata.google.internal at the egress firewall and on the application server. Validate URL inputs with an allow-list of approved hosts.";
    }
    if engine_id.contains("graphql") {
        return "Disable introspection in production (`graphql.config.introspection = false`), enable depth + complexity limits, and require authentication on the /graphql endpoint.";
    }
    if engine_id.contains("jwt") {
        return "Pin the JWT signing algorithm (reject 'none' and weak HMAC keys), rotate the signing key, enforce short token lifetime, and validate aud/iss claims server-side.";
    }
    if engine_id.contains("cors") {
        return "Replace `Access-Control-Allow-Origin: *` with an allow-list of trusted origins. Never combine `*` or `null` with `Access-Control-Allow-Credentials: true`.";
    }
    if engine_id.contains("liminal_boundary") {
        return "Unify WAF/auth rules across HTTP/1.1 and HTTP/2 (ALPN) paths; add correct Vary headers for every cache-key dimension (Cookie, Accept-Language); strip or validate X-Original-URL / X-Rewrite-URL at the edge; disable trusted-header routing unless explicitly required.";
    }
    if engine_id.contains("xss") || engine_id.contains("css_injection") || engine_id.contains("template_injection") {
        return "Adopt a strict Content-Security-Policy: `default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none';`. HTML-escape all dynamic content.";
    }
    if engine_id.contains("clickjacking") {
        return "Send `X-Frame-Options: DENY` (or `SAMEORIGIN`) and the CSP directive `frame-ancestors 'self'`. Verify with `securityheaders.com`.";
    }
    if engine_id.contains("subdomain_takeover") {
        return "Remove the dangling DNS record (CNAME or A) pointing at the unclaimed third-party service, or re-register the resource on the upstream provider.";
    }
    if engine_id.contains("s3") || engine_id.contains("cloud_data_exfil") {
        return "Block public ACLs at the AWS account level (`BlockPublicAccess`), set bucket policy to private, and enable S3 Object Ownership = BucketOwnerEnforced.";
    }
    if engine_id.contains("scada") || engine_id.contains("modbus") || engine_id.contains("plc") || engine_id.contains("opcua") {
        return "OT protocols (Modbus, DNP3, OPC-UA, IEC 61850) must never be reachable from the internet. Isolate inside the OT VLAN, place a Purdue-Level 3.5 firewall, and require VPN + MFA for engineering access.";
    }
    if engine_id.contains("mfa") {
        return "Enforce MFA for all privileged accounts. Block fallback to SMS one-time codes; prefer phishing-resistant factors (WebAuthn / FIDO2).";
    }
    if engine_id.contains("password") {
        return "Disable password reuse, enforce zxcvbn ≥ 3 strength, require MFA, monitor for credential-stuffing patterns and rotate any leaked secrets.";
    }
    if engine_id.contains("supply_chain") || engine_id.contains("npm_package") || engine_id.contains("pypi") || engine_id.contains("docker_image_poison") {
        return "Lock dependencies (lockfiles + hash verification), enable Sigstore / cosign signature verification, and scan via OSV / pip-audit / npm audit on every build.";
    }
    if engine_id.contains("pki") || engine_id.contains("tls") {
        return "Issue certificates with at least 2048-bit RSA / 256-bit ECC, enable HSTS with `max-age=31536000; includeSubDomains; preload`, and disable TLS 1.0 / 1.1.";
    }
    match sev.as_str() {
        "critical" => "Treat as P0: take affected resource offline if exposure is confirmed, rotate credentials/keys, deploy patched configuration, and run a confirmation scan.",
        "high" => "Schedule a fix within 7 days. Apply vendor patch or harden configuration; add detection rule for further exploitation attempts.",
        "medium" => "Plan a fix within the current sprint (≤30 days). Document the risk in your asset register.",
        "low" => "Track as backlog. Re-evaluate when surrounding controls change.",
        _ => "Investigate the observation and validate whether it represents real risk in your environment.",
    }
}

/// Standard compliance-framework tags so the UI can group findings by GDPR / SOC2 / NIS2 etc.
#[must_use]
pub fn default_compliance(engine_id: &str) -> Vec<&'static str> {
    let mut tags: Vec<&'static str> = Vec::new();
    if engine_id.contains("password")
        || engine_id.contains("mfa")
        || engine_id.contains("session")
        || engine_id.contains("kerberos")
    {
        tags.extend_from_slice(&["ISO27001:A.9", "SOC2:CC6.1", "NIS2:Art.21(2)(i)"]);
    }
    if engine_id.contains("tls") || engine_id.contains("crypto") || engine_id.contains("pqc") {
        tags.extend_from_slice(&["ISO27001:A.10", "SOC2:CC6.7", "PCI:4.1"]);
    }
    if engine_id.contains("scada") || engine_id.contains("ot") || engine_id.contains("modbus") || engine_id.contains("plc") {
        tags.extend_from_slice(&["NIS2:Art.21(2)(h)", "IEC62443"]);
    }
    if engine_id.contains("cloud") || engine_id.contains("aws") || engine_id.contains("azure") || engine_id.contains("gcp") {
        tags.extend_from_slice(&["SOC2:CC6.6", "CSA-CCM:DCS-04"]);
    }
    if engine_id.contains("supply_chain") || engine_id.contains("sbom") {
        tags.extend_from_slice(&["NIS2:Art.21(2)(d)", "SOC2:CC7.1"]);
    }
    if engine_id.contains("gdpr") || engine_id.contains("personal") || engine_id.contains("pii") {
        tags.push("GDPR:Art.32");
    }
    if tags.is_empty() {
        tags.push("ISO27001:A.12");
    }
    tags
}
