//! Active host liveness proof required before `VERIFIED_FIXED`.
//!
//! A scanner that finishes `status=ok` with zero findings is **not** proof the
//! vulnerability is gone. The host may have been powered off, firewalled, or
//! unreachable. Closing on that signal is a false verification.
//!
//! Liveness is proven in the same scan window by one of:
//!   * the live scan itself emitting findings against the target
//!   * a TLS handshake (certificate verification is irrelevant — the peer spoke)
//!   * an HTTP response of any status (including 4xx/5xx)
//!   * a TCP banner (the peer sent bytes)
//!   * a `weissman-agent` heartbeat for **this target host** (`last_seen_at`
//!     within 3 minutes). A sibling agent on the same `client_id` is **not**
//!     proof — that was a false `VERIFIED_FIXED` when the vulnerable host was
//!     offline.

use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

/// Agent heartbeats older than this are not contemporaneous with the scan.
pub const AGENT_HEARTBEAT_MAX_AGE_SQL: &str = "3 minutes";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLiveness {
    pub live: bool,
    pub method: &'static str,
}

impl HostLiveness {
    pub fn unproven() -> Self {
        Self {
            live: false,
            method: "unproven",
        }
    }

    pub fn proven(method: &'static str) -> Self {
        Self { live: true, method }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "live": self.live,
            "method": self.method,
        })
    }
}

/// Combine independent signals. Scan-emitted findings are the strongest proof
/// the engine spoke to the host; they short-circuit active probes.
pub fn decide_live(
    scan_had_findings: bool,
    tls_handshake: bool,
    http_response: bool,
    tcp_banner: bool,
    agent_heartbeat: bool,
) -> HostLiveness {
    if scan_had_findings {
        return HostLiveness::proven("scan_findings");
    }
    if tls_handshake {
        return HostLiveness::proven("tls_handshake");
    }
    if http_response {
        return HostLiveness::proven("http_response");
    }
    if tcp_banner {
        return HostLiveness::proven("tcp_banner");
    }
    if agent_heartbeat {
        return HostLiveness::proven("weissman_agent");
    }
    HostLiveness::unproven()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetEndpoint {
    pub host: String,
    pub port: u16,
    pub https: bool,
}

/// Parse host/port/scheme from a scan target (URL, `host:port`, or bare host).
pub fn parse_target_endpoint(target: &str) -> TargetEndpoint {
    let t = target.trim();
    let https = if t.starts_with("http://") {
        false
    } else {
        true
    };
    let host = crate::engine_probes::extract_host(t);
    let port = extract_port(t).unwrap_or(if t.starts_with("http://") { 80 } else { 443 });
    TargetEndpoint { host, port, https }
}

fn extract_port(target: &str) -> Option<u16> {
    let after_scheme = target
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(rest) = host_port.strip_prefix('[') {
        let end = rest.find(']')?;
        let after = rest.get(end + 1..)?;
        let p = after.strip_prefix(':')?;
        return p.parse().ok();
    }
    let mut parts = host_port.rsplitn(2, ':');
    let maybe_port = parts.next()?;
    let has_host = parts.next().is_some();
    if !has_host {
        return None;
    }
    maybe_port.parse().ok()
}

/// Prove the host answered in this scan window. Fail closed on any probe error.
pub async fn prove_host_live(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    target: &str,
    scan_had_findings: bool,
) -> HostLiveness {
    if scan_had_findings {
        return HostLiveness::proven("scan_findings");
    }
    let ep = parse_target_endpoint(target);
    if ep.host.is_empty() {
        return HostLiveness::unproven();
    }

    if tls_handshake_live(&ep.host, ep.port).await {
        return HostLiveness::proven("tls_handshake");
    }
    // HTTPS defaulted to 443; a host that only speaks HTTP on 80 still counts.
    if ep.port != 443 && tls_handshake_live(&ep.host, 443).await {
        return HostLiveness::proven("tls_handshake");
    }

    if http_response_live(target, &ep).await {
        return HostLiveness::proven("http_response");
    }

    if tcp_banner_live(&ep.host, ep.port).await {
        return HostLiveness::proven("tcp_banner");
    }

    if agent_heartbeat_live(pool, tenant_id, client_id, &ep.host).await {
        return HostLiveness::proven("weissman_agent");
    }

    HostLiveness::unproven()
}

async fn tls_handshake_live(host: &str, port: u16) -> bool {
    let host = host.to_string();
    tokio::task::spawn_blocking(move || tls_handshake_blocking(&host, port))
        .await
        .unwrap_or(false)
}

fn tls_handshake_blocking(host: &str, port: u16) -> bool {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let mut builder = match SslConnector::builder(SslMethod::tls()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    // Verification is irrelevant: we only need the peer to complete a handshake.
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let sni = host.trim_matches(|c| c == '[' || c == ']').to_string();
    let addr = match format!("{host}:{port}").to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return false,
        },
        Err(_) => return false,
    };
    let stream = match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    connector.connect(&sni, stream).is_ok()
}

async fn http_response_live(target: &str, ep: &TargetEndpoint) -> bool {
    let url = if target.trim().contains("://") {
        crate::engine_probes::normalize_url(target)
    } else if !ep.https || ep.port == 80 {
        format!("http://{}/", ep.host)
    } else if ep.port == 443 {
        format!("https://{}/", ep.host)
    } else {
        format!("https://{}:{}/", ep.host, ep.port)
    };
    let client = crate::scan_http_client::scan_http_client(Duration::from_secs(3));
    match client.get(&url).send().await {
        Ok(resp) => {
            let _ = resp.status().as_u16();
            true
        }
        Err(_) => {
            if url.starts_with("https://") {
                let http = format!("http://{}/", ep.host);
                client.get(&http).send().await.is_ok()
            } else {
                false
            }
        }
    }
}

async fn tcp_banner_live(host: &str, port: u16) -> bool {
    crate::engine_probes::tcp_probe_response(host, port, b"")
        .await
        .map(|b| !b.is_empty())
        .unwrap_or(false)
}

/// Bind an agent row to the scan target. Sibling hosts on the same client
/// must not count. Short-name ↔ FQDN is allowed **only** when the FQDN is
/// exactly `{short}.{suffix}` for a suffix in the tenant/client allow-list
/// (`clients.domains` and/or `WEISSMAN_LIVENESS_DNS_SUFFIXES`).
/// `web01.dev.local` must never prove `web01.prod.local` live.
#[must_use]
pub fn agent_host_binds_target(
    hostname: &str,
    device_name: &str,
    agent_uuid: &str,
    target_host: &str,
    allowed_dns_suffixes: &[String],
) -> bool {
    let target = normalize_host_label(target_host);
    if target.is_empty() {
        return false;
    }
    let host = normalize_host_label(hostname);
    let device = normalize_host_label(device_name);
    let uuid = agent_uuid.trim().to_ascii_lowercase();
    if !host.is_empty() && host == target {
        return true;
    }
    if !device.is_empty() && device == target {
        return true;
    }
    if !uuid.is_empty() && uuid == target {
        return true;
    }
    shorthand_binds_with_suffix(&host, &target, allowed_dns_suffixes)
        || shorthand_binds_with_suffix(&device, &target, allowed_dns_suffixes)
}

/// Parse `clients.domains` JSON or a comma-separated env list into suffix labels.
pub fn parse_liveness_dns_suffixes(raw: &str) -> Vec<String> {
    let t = raw.trim();
    if t.is_empty() {
        return Vec::new();
    }
    let items: Vec<String> = match serde_json::from_str::<Vec<serde_json::Value>>(t) {
        Ok(arr) => arr
            .into_iter()
            .filter_map(|v| match v {
                serde_json::Value::String(s) => Some(s),
                other => Some(other.to_string()),
            })
            .collect(),
        Err(_) => t
            .split([',', ';', '\n', '\t', ' '])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    };
    let mut out = Vec::new();
    for s in items {
        if let Some(n) = normalize_dns_suffix(&s) {
            if !out.iter().any(|e| e == &n) {
                out.push(n);
            }
        }
    }
    out
}

pub fn env_liveness_dns_suffixes() -> Vec<String> {
    match std::env::var("WEISSMAN_LIVENESS_DNS_SUFFIXES") {
        Ok(s) => parse_liveness_dns_suffixes(&s),
        Err(_) => Vec::new(),
    }
}

fn normalize_dns_suffix(s: &str) -> Option<String> {
    let mut t = s.trim().to_ascii_lowercase();
    if let Some(rest) = t.strip_prefix("*.") {
        t = rest.to_string();
    }
    t = t.trim_matches('.').to_string();
    if t.is_empty() || t.contains('/') || t.contains(':') {
        return None;
    }
    Some(t)
}

fn normalize_host_label(s: &str) -> String {
    s.trim()
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn left_label(s: &str) -> &str {
    s.split('.').next().unwrap_or(s)
}

fn is_single_label(s: &str) -> bool {
    !s.is_empty() && !s.contains('.')
}

fn shorthand_binds_with_suffix(hostname: &str, target: &str, suffixes: &[String]) -> bool {
    if hostname.is_empty() || target.is_empty() || suffixes.is_empty() {
        return false;
    }
    let h = left_label(hostname);
    let t = left_label(target);
    if h.is_empty() || h != t {
        return false;
    }
    let (short, fqdn) = if is_single_label(hostname) && !is_single_label(target) {
        (hostname, target)
    } else if is_single_label(target) && !is_single_label(hostname) {
        (target, hostname)
    } else {
        return false;
    };
    suffixes.iter().any(|sfx| fqdn == &format!("{short}.{sfx}"))
}

async fn agent_heartbeat_live(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    target_host: &str,
) -> bool {
    let Some(client_id) = client_id else {
        return false;
    };
    let target = normalize_host_label(target_host);
    if target.is_empty() {
        return false;
    }
    let mut tx = match crate::db::begin_tenant_tx(pool, tenant_id).await {
        Ok(t) => t,
        Err(_) => return false,
    };
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        r#"SELECT hostname, device_name, agent_uuid::text
             FROM endpoint_agents
            WHERE tenant_id = $1
              AND client_id = $2
              AND status = 'online'
              AND last_seen_at > now() - interval '3 minutes'"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let domains_raw: String = sqlx::query_scalar(
        r#"SELECT COALESCE(domains, '[]') FROM clients
            WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "[]".to_string());
    let _ = tx.commit().await;
    let mut suffixes = env_liveness_dns_suffixes();
    for s in parse_liveness_dns_suffixes(&domains_raw) {
        if !suffixes.iter().any(|e| e == &s) {
            suffixes.push(s);
        }
    }
    rows.iter()
        .any(|(hn, device, uuid)| agent_host_binds_target(hn, device, uuid, &target, &suffixes))
}

/// Resolve a host:port to a socket for tests and TLS connect.
#[allow(dead_code)]
pub fn first_socket_addr(host: &str, port: u16) -> Option<SocketAddr> {
    format!("{host}:{port}").to_socket_addrs().ok()?.next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_scan_without_signals_is_unproven() {
        assert_eq!(
            decide_live(false, false, false, false, false),
            HostLiveness::unproven()
        );
    }

    #[test]
    fn scan_findings_short_circuit() {
        let l = decide_live(true, false, false, false, false);
        assert!(l.live);
        assert_eq!(l.method, "scan_findings");
    }

    #[test]
    fn tls_or_http_or_banner_or_agent_proves_live() {
        assert_eq!(
            decide_live(false, true, false, false, false).method,
            "tls_handshake"
        );
        assert_eq!(
            decide_live(false, false, true, false, false).method,
            "http_response"
        );
        assert_eq!(
            decide_live(false, false, false, true, false).method,
            "tcp_banner"
        );
        assert_eq!(
            decide_live(false, false, false, false, true).method,
            "weissman_agent"
        );
    }

    #[test]
    fn parses_https_url() {
        let ep = parse_target_endpoint("https://grid.example.com:8443/status");
        assert_eq!(ep.host, "grid.example.com");
        assert_eq!(ep.port, 8443);
        assert!(ep.https);
    }

    #[test]
    fn parses_http_default_port() {
        let ep = parse_target_endpoint("http://10.0.0.9/login");
        assert_eq!(ep.host, "10.0.0.9");
        assert_eq!(ep.port, 80);
        assert!(!ep.https);
    }

    #[test]
    fn parses_bare_host_as_https_443() {
        let ep = parse_target_endpoint("app.internal.corp");
        assert_eq!(ep.host, "app.internal.corp");
        assert_eq!(ep.port, 443);
        assert!(ep.https);
    }

    #[test]
    fn userinfo_cannot_steal_host() {
        let ep = parse_target_endpoint("http://approved.example.com@evil.com:8080/x");
        assert_eq!(ep.host, "evil.com");
        assert_eq!(ep.port, 8080);
    }

    #[test]
    fn agent_heartbeat_window_is_three_minutes() {
        assert_eq!(AGENT_HEARTBEAT_MAX_AGE_SQL, "3 minutes");
    }

    #[test]
    fn sibling_host_on_same_client_is_not_liveness() {
        assert!(!agent_host_binds_target(
            "web-healthy.corp.local",
            "healthy",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "web-offline.corp.local",
            &[],
        ));
    }

    #[test]
    fn exact_hostname_or_uuid_binds_target() {
        assert!(agent_host_binds_target(
            "web-offline.corp.local",
            "",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "web-offline.corp.local",
            &[],
        ));
        assert!(agent_host_binds_target(
            "ignored",
            "",
            "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "cccccccc-cccc-cccc-cccc-cccccccccccc",
            &[],
        ));
        assert!(agent_host_binds_target("", "grid-01", "", "grid-01", &[]));
    }

    #[test]
    fn short_name_requires_tenant_suffix_allowlist() {
        let none: [String; 0] = [];
        assert!(!agent_host_binds_target(
            "web01",
            "",
            "",
            "web01.corp.local",
            &none,
        ));
        let corp = vec!["corp.local".to_string()];
        assert!(agent_host_binds_target(
            "web01",
            "",
            "",
            "web01.corp.local",
            &corp,
        ));
        assert!(agent_host_binds_target(
            "web01.corp.local",
            "",
            "",
            "web01",
            &corp,
        ));
    }

    #[test]
    fn same_short_name_dev_vs_prod_does_not_bind() {
        let prod = vec!["prod.local".to_string()];
        assert!(!agent_host_binds_target(
            "web01",
            "",
            "",
            "web01.dev.local",
            &prod,
        ));
        assert!(!agent_host_binds_target(
            "web01.dev.local",
            "",
            "",
            "web01.prod.local",
            &prod,
        ));
        assert!(agent_host_binds_target(
            "web01",
            "",
            "",
            "web01.prod.local",
            &prod,
        ));
    }

    #[test]
    fn same_left_label_different_domains_do_not_bind() {
        assert!(!agent_host_binds_target(
            "web01.a.example",
            "",
            "",
            "web01.b.example",
            &["example".to_string()],
        ));
    }

    #[test]
    fn empty_target_never_binds() {
        assert!(!agent_host_binds_target("web01", "web01", "uuid", "", &[]));
        assert!(!agent_host_binds_target("web01", "", "", "   ", &[]));
    }

    #[test]
    fn parses_client_domains_json_as_suffixes() {
        let s = parse_liveness_dns_suffixes(r#"["prod.local","*.dev.local"]"#);
        assert_eq!(s, vec!["prod.local", "dev.local"]);
    }
}
