//! Per-email failed login lockout (in-memory, keyed by tenant + normalized email).

use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use dashmap::DashMap;
use serde_json::json;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const MAX_FAILURES: u32 = 10;
const LOCKOUT_DURATION: Duration = Duration::from_secs(15 * 60);

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

fn key(tenant_id: i64, email: &str) -> String {
    format!("{}:{}", tenant_id, email.trim().to_lowercase())
}

// ── In-memory fallback (single replica / no REDIS_URL) ─────────────────────────

fn check_lockout_mem(tenant_id: i64, email: &str) -> Option<u64> {
    let k = key(tenant_id, email);
    let cell = store().get(&k)?;
    let mut entry = cell.lock().expect("login lockout lock");
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
    let mut entry = cell.lock().expect("login lockout lock");
    entry.failures = entry.failures.saturating_add(1);
    if entry.failures >= MAX_FAILURES {
        entry.locked_until = Some(Instant::now() + LOCKOUT_DURATION);
    }
}

fn clear_failures_mem(tenant_id: i64, email: &str) {
    store().remove(&key(tenant_id, email));
}

// ── Public API: distributed via Redis when REDIS_URL is set, else in-memory ────

/// Returns seconds until retry when locked, or `None` if login may proceed.
/// Distributed across replicas via Redis when `REDIS_URL` is configured.
pub async fn check_lockout(tenant_id: i64, email: &str) -> Option<u64> {
    if crate::http::rate_limit_redis::is_enabled() {
        return crate::http::rate_limit_redis::lockout_check(tenant_id, email).await;
    }
    check_lockout_mem(tenant_id, email)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn locks_after_max_failures() {
        let tenant = 99_001_i64;
        let email = "lockout-test@example.com";
        // In-memory path is exercised directly (no REDIS_URL in unit tests).
        clear_failures_mem(tenant, email);
        for _ in 0..MAX_FAILURES {
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
}
