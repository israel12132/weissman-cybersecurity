//! Failed-login lockouts: per-email (account stuffing) and per-IP (credential stuffing).
//!
//! Successful / valid logins never increment these counters. Parallel CI, cockpit, and
//! cloud-agent auth from one NAT must not 429; only a burst of *failures* trips defense.

use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use dashmap::DashMap;
use serde_json::json;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Shared with Redis distributed lockout (`rate_limit_redis.rs`).
pub const LOCKOUT_MAX_FAILURES: u64 = 10;
pub const LOCKOUT_SECS: u64 = 15 * 60;
const LOCKOUT_DURATION: Duration = Duration::from_secs(LOCKOUT_SECS);

/// Per-IP stuffing window. Short on purpose: a shared NAT must recover quickly after
/// an attacker stops, while still blocking a spray of distinct emails from one address.
pub const IP_LOCKOUT_SECS: u64 = 60;
const IP_LOCKOUT_DURATION: Duration = Duration::from_secs(IP_LOCKOUT_SECS);

/// Default failed-login budget per IP per window. Above the per-email threshold so a
/// single operator mistyping hits the account lockout first, not the whole NAT.
pub const IP_FAIL_MAX_DEFAULT: u64 = 20;

/// POST paths subject to per-email lockout (shared with [`super::login_rate_limit`]).
pub const ACCOUNT_LOCKOUT_PATHS: &[&str] = &["/api/login", "/api/auth/mfa/verify"];

#[must_use]
pub fn is_account_lockout_post(method: &axum::http::Method, path: &str) -> bool {
    method == axum::http::Method::POST && ACCOUNT_LOCKOUT_PATHS.contains(&path)
}

#[derive(Default)]
struct LockoutEntry {
    failures: u32,
    locked_until: Option<Instant>,
}

fn store() -> &'static DashMap<String, Mutex<LockoutEntry>> {
    static S: OnceLock<DashMap<String, Mutex<LockoutEntry>>> = OnceLock::new();
    S.get_or_init(DashMap::new)
}

fn ip_store() -> &'static DashMap<String, Mutex<LockoutEntry>> {
    static S: OnceLock<DashMap<String, Mutex<LockoutEntry>>> = OnceLock::new();
    S.get_or_init(DashMap::new)
}

fn key(tenant_id: i64, email: &str) -> String {
    format!("{}:{}", tenant_id, email.trim().to_lowercase())
}

fn ip_key(client_ip: &str) -> String {
    client_ip.trim().to_string()
}

/// Failed-login budget per client IP (env `WEISSMAN_LOGIN_FAIL_PER_MINUTE`).
#[must_use]
pub fn ip_fail_max() -> u64 {
    u64::from(super::rate_limit_metrics::login_fail_per_minute())
}

// ── In-memory fallback (single replica / no REDIS_URL) ─────────────────────────

fn check_lockout_mem(tenant_id: i64, email: &str) -> Option<u64> {
    let k = key(tenant_id, email);
    let cell = store().get(&k)?;
    let mut entry = cell.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(until) = entry.locked_until {
        if Instant::now() < until {
            return Some(
                until
                    .checked_duration_since(Instant::now())
                    .unwrap_or(Duration::from_secs(1))
                    .as_secs()
                    .max(1),
            );
        }
        entry.locked_until = None;
        entry.failures = 0;
    }
    None
}

fn record_failure_mem(tenant_id: i64, email: &str) {
    let k = key(tenant_id, email);
    let cell = store().entry(k).or_default();
    let mut entry = cell.lock().unwrap_or_else(|poison| poison.into_inner());
    entry.failures = entry.failures.saturating_add(1);
    if u64::from(entry.failures) >= LOCKOUT_MAX_FAILURES {
        entry.locked_until = Some(Instant::now() + LOCKOUT_DURATION);
    }
}

fn clear_failures_mem(tenant_id: i64, email: &str) {
    store().remove(&key(tenant_id, email));
}

fn check_ip_lockout_mem(client_ip: &str) -> Option<u64> {
    let k = ip_key(client_ip);
    let cell = ip_store().get(&k)?;
    let mut entry = cell.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(until) = entry.locked_until {
        if Instant::now() < until {
            return Some(
                until
                    .checked_duration_since(Instant::now())
                    .unwrap_or(Duration::from_secs(1))
                    .as_secs()
                    .max(1),
            );
        }
        entry.locked_until = None;
        entry.failures = 0;
    }
    None
}

fn record_ip_failure_mem(client_ip: &str) {
    let k = ip_key(client_ip);
    let cell = ip_store().entry(k).or_default();
    let mut entry = cell.lock().unwrap_or_else(|poison| poison.into_inner());
    entry.failures = entry.failures.saturating_add(1);
    if u64::from(entry.failures) >= ip_fail_max() {
        entry.locked_until = Some(Instant::now() + IP_LOCKOUT_DURATION);
    }
}

fn clear_ip_failures_mem(client_ip: &str) {
    ip_store().remove(&ip_key(client_ip));
}

// ── Public API: distributed via Redis when REDIS_URL is set, else in-memory ────

/// Outcome of a lockout probe (fail-closed when Redis is required but down).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockoutStatus {
    Allowed,
    Locked(u64),
    DistributedStoreUnavailable,
}

/// Full lockout status including Redis outage detection.
pub async fn check_lockout_status(tenant_id: i64, email: &str) -> LockoutStatus {
    if crate::http::rate_limit_redis::is_enabled() {
        match crate::http::rate_limit_redis::lockout_check_strict(tenant_id, email).await {
            crate::http::rate_limit_redis::StrictOp::Ok(Some(secs)) => LockoutStatus::Locked(secs),
            crate::http::rate_limit_redis::StrictOp::Ok(None) => LockoutStatus::Allowed,
            crate::http::rate_limit_redis::StrictOp::Unavailable => {
                if crate::http::rate_limit_redis::distributed_state_required() {
                    LockoutStatus::DistributedStoreUnavailable
                } else {
                    LockoutStatus::Allowed
                }
            }
        }
    } else if crate::http::rate_limit_redis::distributed_state_required() {
        LockoutStatus::DistributedStoreUnavailable
    } else if let Some(secs) = check_lockout_mem(tenant_id, email) {
        LockoutStatus::Locked(secs)
    } else {
        LockoutStatus::Allowed
    }
}

/// Returns seconds until retry when locked, or `None` if login may proceed.
/// Distributed across replicas via Redis when `REDIS_URL` is configured.
pub async fn check_lockout(tenant_id: i64, email: &str) -> Option<u64> {
    match check_lockout_status(tenant_id, email).await {
        LockoutStatus::Locked(secs) => Some(secs),
        LockoutStatus::Allowed | LockoutStatus::DistributedStoreUnavailable => None,
    }
}

pub async fn record_failure(tenant_id: i64, email: &str) {
    if crate::http::rate_limit_redis::is_enabled() {
        crate::http::rate_limit_redis::lockout_record_failure(tenant_id, email).await;
        return;
    }
    record_failure_mem(tenant_id, email);
}

pub async fn clear_failures(tenant_id: i64, email: &str) {
    if crate::http::rate_limit_redis::is_enabled() {
        crate::http::rate_limit_redis::lockout_clear(tenant_id, email).await;
        return;
    }
    clear_failures_mem(tenant_id, email);
}

/// Per-IP stuffing probe (fail-closed when Redis is required but down).
pub async fn check_ip_failure_status(client_ip: &str) -> LockoutStatus {
    if crate::http::rate_limit_redis::is_enabled() {
        match crate::http::rate_limit_redis::ip_lockout_check_strict(client_ip).await {
            crate::http::rate_limit_redis::StrictOp::Ok(Some(secs)) => LockoutStatus::Locked(secs),
            crate::http::rate_limit_redis::StrictOp::Ok(None) => LockoutStatus::Allowed,
            crate::http::rate_limit_redis::StrictOp::Unavailable => {
                if crate::http::rate_limit_redis::distributed_state_required() {
                    LockoutStatus::DistributedStoreUnavailable
                } else {
                    LockoutStatus::Allowed
                }
            }
        }
    } else if crate::http::rate_limit_redis::distributed_state_required() {
        LockoutStatus::DistributedStoreUnavailable
    } else if let Some(secs) = check_ip_lockout_mem(client_ip) {
        LockoutStatus::Locked(secs)
    } else {
        LockoutStatus::Allowed
    }
}

/// Record a *failed* login/MFA attempt against the client IP. Successes must not call this.
pub async fn record_ip_failure(client_ip: &str) {
    if crate::http::rate_limit_redis::is_enabled() {
        crate::http::rate_limit_redis::ip_lockout_record_failure(client_ip).await;
        return;
    }
    record_ip_failure_mem(client_ip);
}

/// Record both per-email and per-IP failures for a rejected login/MFA verify.
pub async fn record_login_failure(tenant_id: i64, email: &str, client_ip: &str) {
    record_failure(tenant_id, email).await;
    record_ip_failure(client_ip).await;
}

/// Clear per-IP failure state (tests / explicit unlock). Successful logins do not
/// clear this — one stolen credential must not reset a stuffing campaign on the NAT.
pub async fn clear_ip_failures(client_ip: &str) {
    if crate::http::rate_limit_redis::is_enabled() {
        crate::http::rate_limit_redis::ip_lockout_clear(client_ip).await;
        return;
    }
    clear_ip_failures_mem(client_ip);
}

/// 429 response with `Retry-After` for a locked account.
#[must_use]
pub fn locked_response(retry_after_secs: u64) -> Response {
    let retry_after_secs = retry_after_secs.max(1);
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "ok": false,
            "code": "login_locked",
            "detail": format!(
                "Too many failed login attempts. Retry in {retry_after_secs}s."
            ),
            "retry_after_seconds": retry_after_secs,
        })),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert("Retry-After", v);
    }
    resp
}

/// 429 response for per-IP credential-stuffing lockout (failures only).
#[must_use]
pub fn ip_locked_response(retry_after_secs: u64) -> Response {
    let retry_after_secs = retry_after_secs.max(1);
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "ok": false,
            "code": "login_ip_locked",
            "detail": format!(
                "Too many failed login attempts from this address. Retry in {retry_after_secs}s."
            ),
            "retry_after_seconds": retry_after_secs,
        })),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert("Retry-After", v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn locks_after_max_failures() {
        let tenant = 99_001_i64;
        let email = "lockout-test@example.com";
        // In-memory path is exercised directly (no REDIS_URL in unit tests).
        clear_failures_mem(tenant, email);
        for _ in 0..LOCKOUT_MAX_FAILURES as u32 {
            record_failure_mem(tenant, email);
        }
        let retry = check_lockout_mem(tenant, email);
        assert!(retry.is_some());
        assert!(retry.unwrap() > 0);
        clear_failures_mem(tenant, email);
        assert!(check_lockout_mem(tenant, email).is_none());
        // Public async API routes to the same in-memory store when Redis is off.
        record_failure(tenant, email).await;
        assert!(
            check_lockout(tenant, email).await.is_none(),
            "1 failure must not lock"
        );
        clear_failures(tenant, email).await;
    }

    #[test]
    fn ip_stuffing_locks_after_fail_budget_successes_do_not_count() {
        let ip = "198.51.100.61";
        clear_ip_failures_mem(ip);
        let budget = ip_fail_max();
        assert_eq!(IP_FAIL_MAX_DEFAULT, 20);
        assert!(
            budget >= 8,
            "IP fail budget must stay high enough for a few mistypes on a shared NAT"
        );
        for _ in 0..(budget - 1) {
            record_ip_failure_mem(ip);
            assert!(
                check_ip_lockout_mem(ip).is_none(),
                "must not lock before the failure budget"
            );
        }
        record_ip_failure_mem(ip);
        let retry = check_ip_lockout_mem(ip);
        assert!(
            retry.is_some(),
            "stuffing burst of failures must lock the IP"
        );
        assert!(retry.unwrap() > 0);
        clear_ip_failures_mem(ip);
        assert!(check_ip_lockout_mem(ip).is_none());
    }

    #[tokio::test]
    async fn ip_failure_status_allows_clean_address() {
        let ip = "198.51.100.62";
        clear_ip_failures(ip).await;
        assert_eq!(check_ip_failure_status(ip).await, LockoutStatus::Allowed);
    }
}
