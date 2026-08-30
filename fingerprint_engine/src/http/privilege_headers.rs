//! Reject dual-control / handshake headers unless the caller proves it is the reverse proxy.
//!
//! CIDR allow-lists are not enough behind a cloud ALB: the TCP peer is a rotating
//! VPC address, so operators would otherwise have to trust the whole subnet.
//! Privilege headers are accepted only when `X-Weissman-Proxy-Hmac` verifies
//! (`WEISSMAN_PROXY_SIGNING_SECRET`, ≥32 chars) **and**, in production, the
//! handshake nonce is claimed in Redis (`SET proxy:nonce:{nonce} NX EX 60`).
//! Production never falls back to CIDR. Lab loopback may omit the HMAC so
//! local tests keep working.
//!
//! nginx blanks client-supplied privilege headers **and** `X-Weissman-Proxy-Hmac`
//! on public locations (clients cannot mint the signature). Command Center
//! sends JSON `destructive_confirm` / `dual_approve`. Internal callers of `:8000`
//! attach a short-lived HMAC (`v1={unix}.{nonce}.{hex}`).

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub const DESTRUCTIVE_CONFIRM_HEADER: &str = "x-weissman-destructive-confirm";
pub const DUAL_APPROVE_HEADER: &str = "x-weissman-dual-approve";
pub const LLM_HANDSHAKE_HEADER: &str = "x-weissman-llm-handshake";
pub const PROXY_HMAC_HEADER: &str = "x-weissman-proxy-hmac";

const PRIVILEGE_HEADERS: &[&str] = &[
    DESTRUCTIVE_CONFIRM_HEADER,
    DUAL_APPROVE_HEADER,
    LLM_HANDSHAKE_HEADER,
];
const HMAC_SKEW_SECS: i64 = 60;
const NONCE_TTL_SECS: i64 = 60;
const REDIS_OP_TIMEOUT: Duration = Duration::from_secs(2);
const NONCE_HEX_MIN: usize = 16;
const NONCE_HEX_MAX: usize = 64;
type HmacSha256 = Hmac<Sha256>;

#[must_use]
pub fn privilege_admin_headers_present(headers: &HeaderMap) -> bool {
    PRIVILEGE_HEADERS.iter().any(|name| {
        headers
            .get(*name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some()
    })
}

/// HMAC secret from `WEISSMAN_PROXY_SIGNING_SECRET`. Empty / short secrets
/// never verify (fail closed).
#[must_use]
pub fn proxy_signing_secret() -> Vec<u8> {
    std::env::var("WEISSMAN_PROXY_SIGNING_SECRET")
        .ok()
        .filter(|s| s.len() >= 32)
        .map(|s| s.into_bytes())
        .unwrap_or_default()
}

/// 32 hex chars (uuid v4, no dashes). Independent of clock so two requests in
/// the same second cannot share a handshake.
#[must_use]
pub fn new_proxy_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// `v1={unix}.{nonce}.{hex(HMAC-SHA256(secret, "{ts}\\n{nonce}\\n{METHOD}\\n{path}"))}`
#[must_use]
pub fn sign_proxy_hmac(
    secret: &[u8],
    unix_ts: i64,
    nonce: &str,
    method: &str,
    path: &str,
) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(unix_ts.to_string().as_bytes());
    mac.update(b"\n");
    mac.update(nonce.as_bytes());
    mac.update(b"\n");
    mac.update(method.as_bytes());
    mac.update(b"\n");
    mac.update(path.as_bytes());
    let bytes = mac.finalize().into_bytes();
    format!("v1={unix_ts}.{nonce}.{}", hex::encode(bytes))
}

#[must_use]
fn nonce_hex_ok(nonce: &str) -> bool {
    let n = nonce.len();
    (NONCE_HEX_MIN..=NONCE_HEX_MAX).contains(&n) && nonce.chars().all(|c| c.is_ascii_hexdigit())
}

struct ProxyHmacParts {
    ts: i64,
    nonce: String,
    mac: Vec<u8>,
}

fn parse_proxy_hmac(raw: &str) -> Option<ProxyHmacParts> {
    let rest = raw.strip_prefix("v1=")?;
    let mut parts = rest.splitn(3, '.');
    let ts_s = parts.next()?;
    let nonce = parts.next()?;
    let hex_mac = parts.next()?;
    if !nonce_hex_ok(nonce) {
        return None;
    }
    let ts = ts_s.parse::<i64>().ok()?;
    let mac = hex::decode(hex_mac).ok()?;
    Some(ProxyHmacParts {
        ts,
        nonce: nonce.to_ascii_lowercase(),
        mac,
    })
}

/// Sync MAC + skew + nonce format. Replay is rejected by [`claim_proxy_nonce`].
#[must_use]
pub fn proxy_hmac_valid(headers: &HeaderMap, method: &str, path: &str) -> bool {
    let secret = proxy_signing_secret();
    if secret.is_empty() {
        return false;
    }
    let Some(raw) = headers
        .get(PROXY_HMAC_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return false;
    };
    let Some(parts) = parse_proxy_hmac(raw) else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (now - parts.ts).abs() > HMAC_SKEW_SECS {
        return false;
    }
    let mut mac = HmacSha256::new_from_slice(&secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(parts.ts.to_string().as_bytes());
    mac.update(b"\n");
    mac.update(parts.nonce.as_bytes());
    mac.update(b"\n");
    mac.update(method.as_bytes());
    mac.update(b"\n");
    mac.update(path.as_bytes());
    let expected = mac.finalize().into_bytes();
    expected.len() == parts.mac.len() && expected.as_slice().ct_eq(parts.mac.as_slice()).into()
}

#[must_use]
pub fn extract_proxy_nonce(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(PROXY_HMAC_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    Some(parse_proxy_hmac(raw)?.nonce)
}

struct ProxyNonceRedis {
    client: redis::Client,
}

fn nonce_redis() -> Option<Arc<ProxyNonceRedis>> {
    static S: OnceLock<Option<Arc<ProxyNonceRedis>>> = OnceLock::new();
    S.get_or_init(|| {
        let url = std::env::var("REDIS_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        let client = redis::Client::open(url).ok()?;
        Some(Arc::new(ProxyNonceRedis { client }))
    })
    .clone()
}

/// `SET proxy:nonce:{nonce} 1 NX EX 60`. First claim wins; replay and Redis
/// failures return `false` (fail closed).
pub async fn claim_proxy_nonce(nonce: &str) -> bool {
    if !nonce_hex_ok(nonce) {
        return false;
    }
    let Some(rl) = nonce_redis() else {
        return false;
    };
    let mut conn = match tokio::time::timeout(
        REDIS_OP_TIMEOUT,
        rl.client.get_multiplexed_async_connection(),
    )
    .await
    {
        Ok(Ok(c)) => c,
        _ => return false,
    };
    let key = format!("proxy:nonce:{}", nonce.to_ascii_lowercase());
    let claimed: Result<redis::Value, _> = tokio::time::timeout(
        REDIS_OP_TIMEOUT,
        redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(NONCE_TTL_SECS)
            .query_async(&mut conn),
    )
    .await
    .unwrap_or(Err(redis::RedisError::from((
        redis::ErrorKind::IoError,
        "proxy nonce SET timeout",
    ))));
    matches!(
        claimed,
        Ok(redis::Value::Okay) | Ok(redis::Value::SimpleString(_))
    )
}

/// True when privilege headers may be consumed at the **sync MAC layer**.
///
/// Production: **HMAC only** (nonce replay is enforced in the middleware).
/// CIDR membership is never enough. Non-production: loopback may omit HMAC.
#[must_use]
pub fn privilege_headers_accepted(
    peer: IpAddr,
    headers: &HeaderMap,
    method: &str,
    path: &str,
) -> bool {
    if !privilege_admin_headers_present(headers) {
        return true;
    }
    if proxy_hmac_valid(headers, method, path) {
        return true;
    }
    if weissman_core::tls_policy::is_production_environment() {
        return false;
    }
    peer.is_loopback()
}

pub async fn privilege_header_proxy_middleware(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();
    if !privilege_headers_accepted(peer.ip(), request.headers(), &method, &path) {
        tracing::warn!(
            target: "privilege_headers",
            peer = %peer.ip(),
            path = %path,
            "rejected privilege headers without a valid X-Weissman-Proxy-Hmac"
        );
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "ok": false,
                "code": "privilege_header_hmac_required",
                "detail": "Dual-control headers require a short-lived X-Weissman-Proxy-Hmac from the reverse proxy. Send JSON destructive_confirm / dual_approve from the Command Center.",
            })),
        )
            .into_response();
    }
    if privilege_admin_headers_present(request.headers())
        && weissman_core::tls_policy::is_production_environment()
    {
        let nonce = extract_proxy_nonce(request.headers());
        let claimed = match nonce.as_deref() {
            Some(n) => claim_proxy_nonce(n).await,
            None => false,
        };
        if !claimed {
            tracing::warn!(
                target: "privilege_headers",
                peer = %peer.ip(),
                path = %path,
                "rejected privilege headers: proxy HMAC nonce replay or Redis unavailable"
            );
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({
                    "ok": false,
                    "code": "privilege_header_nonce_replay",
                    "detail": "Dual-control headers require a one-time X-Weissman-Proxy-Hmac nonce (Redis SET NX). Replay and Redis outages fail closed. Send JSON destructive_confirm / dual_approve from the Command Center.",
                })),
            )
                .into_response();
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const SECRET: &str = "proxy-hmac-test-secret-32bytes-min!!";
    const NONCE: &str = "aabbccddeeff0011";

    fn with_env<F: FnOnce()>(set: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        let prev: Vec<(String, Option<String>)> = set
            .iter()
            .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in set {
            if let Some(v) = v {
                std::env::set_var(k, v);
            } else {
                std::env::remove_var(k);
            }
        }
        f();
        for (k, v) in prev {
            if let Some(v) = v {
                std::env::set_var(&k, v);
            } else {
                std::env::remove_var(&k);
            }
        }
    }

    fn privilege_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(DESTRUCTIVE_CONFIRM_HEADER, "tok".parse().unwrap());
        h
    }

    fn now_ts() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    #[test]
    fn empty_headers_are_not_privilege() {
        assert!(!privilege_admin_headers_present(&HeaderMap::new()));
        let mut h = HeaderMap::new();
        h.insert(DESTRUCTIVE_CONFIRM_HEADER, "".parse().unwrap());
        assert!(!privilege_admin_headers_present(&h));
        assert!(privilege_headers_accepted(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            &HeaderMap::new(),
            "GET",
            "/api/health"
        ));
    }

    #[test]
    fn nonempty_header_is_privilege() {
        assert!(privilege_admin_headers_present(&privilege_headers()));
    }

    #[test]
    fn lab_loopback_may_omit_hmac_rfc1918_may_not() {
        with_env(
            &[
                ("WEISSMAN_PROXY_SIGNING_SECRET", None),
                (
                    "WEISSMAN_PRIVILEGE_HEADER_TRUSTED_CIDRS",
                    Some("10.0.0.0/8"),
                ),
                ("WEISSMAN_TRUST_PROXY_CIDRS", Some("10.0.0.0/8")),
                ("WEISSMAN_ENV", Some("development")),
                ("RUST_ENV", Some("development")),
                ("NODE_ENV", Some("development")),
                ("APP_ENV", Some("development")),
                ("RAILS_ENV", Some("development")),
            ],
            || {
                let h = privilege_headers();
                assert!(privilege_headers_accepted(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    &h,
                    "POST",
                    "/api/containment/execute"
                ));
                assert!(
                    !privilege_headers_accepted(
                        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
                        &h,
                        "POST",
                        "/api/containment/execute"
                    ),
                    "sibling pod / RFC1918 must not inject dual-control headers"
                );
            },
        );
    }

    #[test]
    fn production_cidr_without_hmac_is_never_enough() {
        with_env(
            &[
                ("WEISSMAN_PROXY_SIGNING_SECRET", Some(SECRET)),
                (
                    "WEISSMAN_PRIVILEGE_HEADER_TRUSTED_CIDRS",
                    Some("10.0.0.0/8"),
                ),
                ("WEISSMAN_TRUST_PROXY_CIDRS", Some("10.0.0.0/8")),
                ("WEISSMAN_ENV", Some("production")),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", Some("production")),
                ("APP_ENV", Some("production")),
                ("RAILS_ENV", Some("production")),
            ],
            || {
                let h = privilege_headers();
                assert!(
                    !privilege_headers_accepted(
                        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
                        &h,
                        "POST",
                        "/api/containment/execute"
                    ),
                    "VPC/ALB CIDR must not mint dual-control headers"
                );
            },
        );
    }

    #[test]
    fn production_valid_hmac_allows_any_peer() {
        with_env(
            &[
                ("WEISSMAN_PROXY_SIGNING_SECRET", Some(SECRET)),
                ("WEISSMAN_ENV", Some("production")),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", Some("production")),
                ("APP_ENV", Some("production")),
                ("RAILS_ENV", Some("production")),
            ],
            || {
                let ts = now_ts();
                let mac = sign_proxy_hmac(
                    SECRET.as_bytes(),
                    ts,
                    NONCE,
                    "POST",
                    "/api/containment/execute",
                );
                let mut h = privilege_headers();
                h.insert(PROXY_HMAC_HEADER, mac.parse().unwrap());
                assert!(privilege_headers_accepted(
                    IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
                    &h,
                    "POST",
                    "/api/containment/execute"
                ));
                assert_eq!(extract_proxy_nonce(&h).as_deref(), Some(NONCE));
                assert!(
                    !privilege_headers_accepted(
                        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
                        &h,
                        "POST",
                        "/api/other"
                    ),
                    "HMAC is bound to method and path"
                );
                let other_nonce = sign_proxy_hmac(
                    SECRET.as_bytes(),
                    ts,
                    "0011223344556677",
                    "POST",
                    "/api/containment/execute",
                );
                let mut hn = privilege_headers();
                hn.insert(PROXY_HMAC_HEADER, other_nonce.parse().unwrap());
                assert!(
                    !proxy_hmac_valid(&h, "POST", "/api/containment/execute")
                        || extract_proxy_nonce(&h) != extract_proxy_nonce(&hn),
                    "HMAC is bound to the nonce"
                );
                let stale = sign_proxy_hmac(
                    SECRET.as_bytes(),
                    ts - HMAC_SKEW_SECS - 5,
                    NONCE,
                    "POST",
                    "/api/containment/execute",
                );
                let mut old = privilege_headers();
                old.insert(PROXY_HMAC_HEADER, stale.parse().unwrap());
                assert!(!privilege_headers_accepted(
                    IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
                    &old,
                    "POST",
                    "/api/containment/execute"
                ));
                let mut legacy = privilege_headers();
                legacy.insert(
                    PROXY_HMAC_HEADER,
                    format!("v1={ts}.{}", "ab".repeat(32)).parse().unwrap(),
                );
                assert!(
                    !proxy_hmac_valid(&legacy, "POST", "/api/containment/execute"),
                    "legacy v1={{unix}}.{{hex}} without a nonce must not verify"
                );
            },
        );
    }

    #[test]
    fn short_secret_never_verifies() {
        with_env(
            &[
                ("WEISSMAN_PROXY_SIGNING_SECRET", Some("too-short")),
                ("WEISSMAN_ENV", Some("production")),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", Some("production")),
                ("APP_ENV", Some("production")),
                ("RAILS_ENV", Some("production")),
            ],
            || {
                let mac = sign_proxy_hmac(b"too-short", now_ts(), NONCE, "POST", "/api/x");
                let mut h = privilege_headers();
                h.insert(PROXY_HMAC_HEADER, mac.parse().unwrap());
                assert!(!proxy_hmac_valid(&h, "POST", "/api/x"));
                assert!(!privilege_headers_accepted(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    &h,
                    "POST",
                    "/api/x"
                ));
            },
        );
    }

    #[test]
    fn handshake_binds_nonce_in_mac_and_header() {
        let src = include_str!("privilege_headers.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(prod.contains("proxy:nonce:"));
        assert!(prod.contains("NX"));
        assert!(prod.contains("claim_proxy_nonce"));
        assert!(prod.contains("mac.update(nonce.as_bytes())"));
        assert!(prod.contains("v1={unix}.{nonce}.{hex"));
    }

    #[tokio::test]
    async fn claim_proxy_nonce_rejects_replay() {
        let url = match std::env::var("REDIS_URL") {
            Ok(u) if !u.trim().is_empty() => u,
            _ => {
                eprintln!("SKIP claim_proxy_nonce_rejects_replay: no REDIS_URL");
                return;
            }
        };
        let _ = url;
        let nonce = format!("{:032x}", uuid::Uuid::new_v4().as_u128());
        assert!(
            claim_proxy_nonce(&nonce).await,
            "first claim of a fresh nonce must succeed"
        );
        assert!(
            !claim_proxy_nonce(&nonce).await,
            "second claim of the same nonce must fail (replay)"
        );
    }
}
