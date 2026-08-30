//! Distributed rate-limit counters via Redis (`REDIS_URL`). Falls back to in-process governor when unset.
//!
//! In production multi-replica mode (`REDIS_URL` set, `WEISSMAN_ALLOW_SINGLE_NODE` unset), Redis
//! failures are **fail-closed** — callers must not silently degrade to per-replica memory.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use redis::AsyncCommands;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Bound every Redis acquire/op. Without this, a Redis black-hole (packets dropped, no RST)
/// makes each op await forever and wedges the whole API on the per-request rate-limit path —
/// and the fail-closed paths (`StrictOp::Unavailable`) never fire because the await never returns.
const REDIS_OP_TIMEOUT: Duration = Duration::from_secs(2);
/// Ask Weissman acquire+command cap. A hung Redis must not pin Tokio workers.
pub const ASK_REDIS_ACQUIRE_TIMEOUT_MS: u64 = 50;

pub struct RedisRateLimiter {
    client: redis::Client,
}

impl RedisRateLimiter {
    /// Multiplexed connection whose acquire and every command are bounded by
    /// [`REDIS_OP_TIMEOUT`]; a hung Redis surfaces as an error (→ fail-closed) instead of a hang.
    async fn conn(&self) -> redis::RedisResult<redis::aio::MultiplexedConnection> {
        // Bound the acquire with tokio::timeout, and bound every subsequent command with the
        // connection's own response timeout — together these turn a hung Redis into an error
        // (→ fail-closed) instead of an unbounded await on the per-request hot path.
        let mut conn = tokio::time::timeout(
            REDIS_OP_TIMEOUT,
            self.client.get_multiplexed_async_connection(),
        )
        .await
        .map_err(|_| {
            redis::RedisError::from((redis::ErrorKind::IoError, "redis connect timeout"))
        })??;
        conn.set_response_timeout(REDIS_OP_TIMEOUT);
        Ok(conn)
    }

    async fn conn_with_timeout(
        &self,
        timeout: Duration,
    ) -> redis::RedisResult<redis::aio::MultiplexedConnection> {
        let mut conn =
            tokio::time::timeout(timeout, self.client.get_multiplexed_async_connection())
                .await
                .map_err(|_| {
                    redis::RedisError::from((redis::ErrorKind::IoError, "redis acquire timeout"))
                })??;
        conn.set_response_timeout(timeout);
        Ok(conn)
    }
}

fn shared() -> Option<Arc<RedisRateLimiter>> {
    static S: OnceLock<Option<Arc<RedisRateLimiter>>> = OnceLock::new();
    S.get_or_init(|| {
        let url = std::env::var("REDIS_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        let client = redis::Client::open(url).ok()?;
        tracing::info!(target: "rate_limit_redis", "Distributed rate limits enabled");
        Some(Arc::new(RedisRateLimiter { client }))
    })
    .clone()
}

async fn incr_window(key: &str, window: Duration) -> Option<u64> {
    // Self-healing fast-fail: if the Redis dependency circuit is open (sustained outage detected by
    // the recovery engine), skip the connect+INCR — which would otherwise each pay REDIS_OP_TIMEOUT
    // — and fall straight to the local limiter. `None` already means "Redis unavailable → local
    // fallback", so this only makes the outage path faster; it is a no-op while Redis is healthy (or
    // when self-heal recovery is disabled), and the circuit auto-probes back to closed on recovery.
    if !crate::self_heal_recovery::dependency_available(
        crate::self_heal_recovery::Dependency::Redis,
    ) {
        return None;
    }
    let rl = shared()?;
    let mut conn = rl.conn().await.ok()?;
    let count: u64 = conn.incr(key, 1u64).await.ok()?;
    if count == 1 {
        let _: Result<(), _> = conn.expire(key, window.as_secs() as i64).await;
    }
    Some(count)
}

/// Tenant scan POST counter (60s window). `None` when Redis unavailable.
pub async fn incr_tenant_scan(tenant_id: i64) -> Option<u64> {
    incr_window(
        &format!("weissman:rl:scan:{tenant_id}"),
        Duration::from_secs(60),
    )
    .await
}

/// Login attempt counter per IP (60s window).
pub async fn incr_login_ip(client_ip: &str) -> Option<u64> {
    incr_window(
        &format!("weissman:rl:login:{client_ip}"),
        Duration::from_secs(60),
    )
    .await
}

/// API request counter per IP (1s window).
pub async fn incr_api_ip(client_ip: &str) -> Option<u64> {
    incr_window(
        &format!("weissman:rl:api:{client_ip}"),
        Duration::from_secs(1),
    )
    .await
}

/// Agent enrollment counter per IP (60s window).
pub async fn incr_enroll_ip(client_ip: &str) -> Option<u64> {
    incr_window(
        &format!("weissman:rl:enroll:{client_ip}"),
        Duration::from_secs(60),
    )
    .await
}

async fn get_count_and_ttl(key: &str) -> Option<(u64, u64)> {
    let rl = shared()?;
    let mut conn = rl.conn().await.ok()?;
    let count: u64 = conn.get::<_, Option<u64>>(key).await.ok()?.unwrap_or(0);
    let ttl: i64 = conn.ttl(key).await.ok()?;
    let reset_in = if ttl > 0 { ttl as u64 } else { 0 };
    Some((count, reset_in))
}

/// Current tenant scan count (read-only, 60s window).
pub async fn current_tenant_scan(tenant_id: i64) -> Option<(u64, u64)> {
    get_count_and_ttl(&format!("weissman:rl:scan:{tenant_id}")).await
}

/// Current login count per IP (read-only).
pub async fn current_login_ip(client_ip: &str) -> Option<(u64, u64)> {
    get_count_and_ttl(&format!("weissman:rl:login:{client_ip}")).await
}

/// Current API count per IP (read-only).
pub async fn current_api_ip(client_ip: &str) -> Option<(u64, u64)> {
    get_count_and_ttl(&format!("weissman:rl:api:{client_ip}")).await
}

/// Record violation JSON line in tenant-scoped Redis list (trimmed).
pub async fn push_violation(tenant_id: i64, kind: &str, endpoint: &str) {
    let Some(rl) = shared() else {
        return;
    };
    let key = format!("weissman:rl:violations:{tenant_id}");
    let payload = serde_json::json!({
        "type": kind,
        "endpoint": endpoint,
        "time": chrono::Utc::now().to_rfc3339(),
        "attempts": 1,
    })
    .to_string();
    if let Ok(mut conn) = rl.conn().await {
        let _: Result<(), _> = conn.lpush(&key, payload).await;
        let _: Result<(), _> = conn.ltrim(&key, 0, 49).await;
        let _: Result<(), _> = conn.expire(&key, 7 * 24 * 3600).await;
    }
}

/// Endpoint hit counter per tenant.
pub async fn incr_endpoint_hit(tenant_id: i64, path: &str) {
    let Some(rl) = shared() else {
        return;
    };
    let key = format!("weissman:rl:endpoints:{tenant_id}");
    if let Ok(mut conn) = rl.conn().await {
        let _: Result<(), _> = conn.hincr(&key, path, 1i64).await;
        let _: Result<(), _> = conn.expire(&key, 7 * 24 * 3600).await;
    }
}

/// Recent violations for analytics (newest first).
pub async fn list_violations(tenant_id: i64, limit: usize) -> Vec<serde_json::Value> {
    let Some(rl) = shared() else {
        return Vec::new();
    };
    let key = format!("weissman:rl:violations:{tenant_id}");
    let Ok(mut conn) = rl.conn().await else {
        return Vec::new();
    };
    let rows: Vec<String> = conn
        .lrange(&key, 0, limit as isize - 1)
        .await
        .unwrap_or_default();
    rows.into_iter()
        .filter_map(|s| serde_json::from_str(&s).ok())
        .collect()
}

/// Top endpoint hits for tenant.
pub async fn top_endpoints(tenant_id: i64, cap: usize) -> Vec<(String, u32)> {
    let Some(rl) = shared() else {
        return Vec::new();
    };
    let key = format!("weissman:rl:endpoints:{tenant_id}");
    let Ok(mut conn) = rl.conn().await else {
        return Vec::new();
    };
    let map: std::collections::HashMap<String, i64> = conn.hgetall(&key).await.unwrap_or_default();
    let mut out: Vec<(String, u32)> = map.into_iter().map(|(k, v)| (k, v.max(0) as u32)).collect();
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out.truncate(cap);
    out
}

// ── Distributed login lockout (keyed by tenant + normalized email) ─────────────
use super::login_lockout::{LOCKOUT_MAX_FAILURES, LOCKOUT_SECS};

fn lockout_fail_key(tenant_id: i64, email: &str) -> String {
    format!(
        "weissman:lockout:fail:{tenant_id}:{}",
        email.trim().to_lowercase()
    )
}
fn lockout_until_key(tenant_id: i64, email: &str) -> String {
    format!(
        "weissman:lockout:until:{tenant_id}:{}",
        email.trim().to_lowercase()
    )
}

/// Returns `Some(retry_after_secs)` when the account is locked. `None` means not locked.
pub async fn lockout_check(tenant_id: i64, email: &str) -> Option<u64> {
    match lockout_check_strict(tenant_id, email).await {
        StrictOp::Ok(v) => v,
        StrictOp::Unavailable => None,
    }
}

/// Strict lockout check — surfaces Redis outage separately from "not locked".
pub async fn lockout_check_strict(tenant_id: i64, email: &str) -> StrictOp<Option<u64>> {
    let Some(rl) = shared() else {
        return if distributed_state_required() {
            StrictOp::Unavailable
        } else {
            StrictOp::Ok(None)
        };
    };
    let Ok(mut conn) = rl.conn().await else {
        return StrictOp::Unavailable;
    };
    let ttl: i64 = match conn.ttl(lockout_until_key(tenant_id, email)).await {
        Ok(t) => t,
        Err(_) => return StrictOp::Unavailable,
    };
    if ttl > 0 {
        StrictOp::Ok(Some(ttl as u64))
    } else {
        StrictOp::Ok(None)
    }
}

/// Record a failed attempt; locks the account for `LOCKOUT_SECS` once the failure
/// counter reaches the threshold. The counter auto-expires after the lock window.
pub async fn lockout_record_failure(tenant_id: i64, email: &str) {
    let Some(rl) = shared() else {
        return;
    };
    let Ok(mut conn) = rl.conn().await else {
        return;
    };
    let fk = lockout_fail_key(tenant_id, email);
    let count: u64 = conn.incr(&fk, 1u64).await.unwrap_or(0);
    if count == 1 {
        let _: Result<(), _> = conn.expire(&fk, LOCKOUT_SECS as i64).await;
    }
    if count >= LOCKOUT_MAX_FAILURES {
        let _: Result<(), _> = conn
            .set_ex(lockout_until_key(tenant_id, email), 1i64, LOCKOUT_SECS)
            .await;
    }
}

/// Clear the failure counter + lock on successful authentication.
pub async fn lockout_clear(tenant_id: i64, email: &str) {
    let Some(rl) = shared() else {
        return;
    };
    let Ok(mut conn) = rl.conn().await else {
        return;
    };
    let _: Result<(), _> = conn.del(lockout_fail_key(tenant_id, email)).await;
    let _: Result<(), _> = conn.del(lockout_until_key(tenant_id, email)).await;
}

#[must_use]
pub fn is_enabled() -> bool {
    shared().is_some()
}

/// True when `REDIS_URL` is set — Ask Weissman treats this as "Redis is the rate store"
/// and must fail-closed if the client is missing or a command times out.
#[must_use]
pub fn redis_url_configured() -> bool {
    std::env::var("REDIS_URL")
        .ok()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

/// Production multi-replica deployments require Redis-backed distributed state.
#[must_use]
pub fn distributed_state_required() -> bool {
    crate::security_startup::production_distributed_state_required()
}

/// Timeout-bounded Redis PING. `true` iff Redis answered — used by readiness and the
/// dependency-health gauge. Never hangs (the connection is bounded by [`REDIS_OP_TIMEOUT`]).
pub async fn ping_ok() -> bool {
    let Some(rl) = shared() else {
        return false;
    };
    let Ok(mut conn) = rl.conn().await else {
        return false;
    };
    redis::cmd("PING")
        .query_async::<String>(&mut conn)
        .await
        .is_ok()
}

/// Tri-state result for strict distributed ops (distinguishes Redis outage from "not locked").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictOp<T> {
    Ok(T),
    Unavailable,
}

/// Verify Redis connectivity at boot when distributed state is mandatory.
pub async fn verify_redis_at_startup() -> Result<(), String> {
    if !distributed_state_required() {
        return Ok(());
    }
    let Some(rl) = shared() else {
        return Err(
            "REDIS_URL is set but Redis client could not be initialized; distributed lockout/rate limits unavailable"
                .into(),
        );
    };
    let mut conn = rl
        .conn()
        .await
        .map_err(|e| format!("Redis PING failed at startup: {e}"))?;
    redis::cmd("PING")
        .query_async::<String>(&mut conn)
        .await
        .map_err(|e| format!("Redis PING failed at startup: {e}"))?;
    Ok(())
}

/// Standard 503 when Redis is required but unreachable (fail-closed).
#[must_use]
pub fn distributed_store_unavailable_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "ok": false,
            "code": "distributed_store_unavailable",
            "detail": "Distributed security store (Redis) is unavailable; request rejected (fail-closed).",
        })),
    )
        .into_response()
}

async fn incr_window_strict(key: &str, window: Duration) -> StrictOp<u64> {
    let Some(rl) = shared() else {
        return if distributed_state_required() {
            StrictOp::Unavailable
        } else {
            StrictOp::Ok(0)
        };
    };
    let Ok(mut conn) = rl.conn().await else {
        return StrictOp::Unavailable;
    };
    let count: u64 = match conn.incr(key, 1u64).await {
        Ok(c) => c,
        Err(_) => return StrictOp::Unavailable,
    };
    if count == 1 {
        let _: Result<(), _> = conn.expire(key, window.as_secs() as i64).await;
    }
    StrictOp::Ok(count)
}

/// Like [`incr_login_ip`] but fail-closed aware for middleware.
pub async fn incr_login_ip_strict(client_ip: &str) -> StrictOp<u64> {
    incr_window_strict(
        &format!("weissman:rl:login:{client_ip}"),
        Duration::from_secs(60),
    )
    .await
}

/// Like [`incr_enroll_ip`] but fail-closed aware for middleware.
pub async fn incr_enroll_ip_strict(client_ip: &str) -> StrictOp<u64> {
    incr_window_strict(
        &format!("weissman:rl:enroll:{client_ip}"),
        Duration::from_secs(60),
    )
    .await
}

/// Like [`incr_api_ip`] but fail-closed aware for middleware.
pub async fn incr_api_ip_strict(client_ip: &str) -> StrictOp<u64> {
    incr_window_strict(
        &format!("weissman:rl:api:{client_ip}"),
        Duration::from_secs(1),
    )
    .await
}

/// Ask Weissman per-user counter (60s window). Acquire and INCR are capped at
/// [`ASK_REDIS_ACQUIRE_TIMEOUT_MS`] so a stalled Redis cannot lock the Tokio pool.
pub async fn incr_ask_user_strict(user_id: i64) -> StrictOp<u64> {
    incr_window_strict_timeout(
        &format!("weissman:rl:ask:{user_id}"),
        Duration::from_secs(60),
        Duration::from_millis(ASK_REDIS_ACQUIRE_TIMEOUT_MS),
    )
    .await
}

async fn incr_window_strict_timeout(
    key: &str,
    window: Duration,
    timeout: Duration,
) -> StrictOp<u64> {
    let Some(rl) = shared() else {
        return if distributed_state_required() {
            StrictOp::Unavailable
        } else {
            StrictOp::Ok(0)
        };
    };
    let mut conn = match rl.conn_with_timeout(timeout).await {
        Ok(c) => c,
        Err(_) => return StrictOp::Unavailable,
    };
    let incr = async {
        let count: u64 = conn.incr(key, 1u64).await?;
        if count == 1 {
            let _: Result<(), _> = conn.expire(key, window.as_secs() as i64).await;
        }
        Ok::<u64, redis::RedisError>(count)
    };
    match tokio::time::timeout(timeout, incr).await {
        Ok(Ok(count)) => StrictOp::Ok(count),
        _ => StrictOp::Unavailable,
    }
}
