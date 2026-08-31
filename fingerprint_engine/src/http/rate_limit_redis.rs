//! Distributed rate-limit counters via Redis (`REDIS_URL`). Falls back to in-process governor when unset.
//!
//! In production multi-replica mode (`REDIS_URL` set, `WEISSMAN_ALLOW_SINGLE_NODE` unset), Redis
//! outages **degrade** the request-path governor to a stricter in-memory cap
//! (`50% / WEISSMAN_REPLICA_COUNT`) and emit a SOC signal — they do **not** 503
//! legitimate logins (self-inflicted DoS). MFA lockout and other stores that still
//! require Redis keep [`distributed_store_unavailable_response`].

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use dashmap::DashMap;
use redis::AsyncCommands;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Bound every Redis acquire/op. Without this, a Redis black-hole (packets dropped, no RST)
/// makes each op await forever and wedges the whole API on the per-request rate-limit path —
/// and the fail-closed paths (`StrictOp::Unavailable`) never fire because the await never returns.
const REDIS_OP_TIMEOUT: Duration = Duration::from_secs(2);

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
    incr_and_bound_ttl(&mut conn, key, window).await.ok()
}

/// Atomic `INCR` + `PEXPIRE` when the key has no TTL.
///
/// Split `INCR` then `EXPIRE` only when `count == 1` races: a dropped EXPIRE
/// leaves a 1-second API window immortal, counts climb past the limit, and
/// live E2E job polls on 127.0.0.1 are 429'd until they look like a job timeout.
/// A follow-up `TTL` + `EXPIRE` still has a lost-EXPIRE window. One Lua eval
/// cannot drop the expire independently of the increment.
const INCR_BOUND_TTL_LUA: &str = r#"
local n = redis.call('INCR', KEYS[1])
local ttl_ms = tonumber(ARGV[1])
if redis.call('PTTL', KEYS[1]) < 0 then
  redis.call('PEXPIRE', KEYS[1], ttl_ms)
end
return n
"#;

async fn incr_and_bound_ttl(
    conn: &mut redis::aio::MultiplexedConnection,
    key: &str,
    window: Duration,
) -> redis::RedisResult<u64> {
    let ttl_ms = window.as_millis().max(1) as i64;
    redis::cmd("EVAL")
        .arg(INCR_BOUND_TTL_LUA)
        .arg(1i64)
        .arg(key)
        .arg(ttl_ms)
        .query_async(conn)
        .await
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

/// True when Redis is required for cluster coherence but the client is missing
/// or the last async INCR failed. Request-path governors must degrade locally
/// (`50% / replica_count`) instead of returning 503.
#[must_use]
pub fn redis_degraded() -> bool {
    distributed_state_required() && (!is_enabled() || redis_sync_unhealthy())
}

/// Replica count for sharded local caps. Production must set
/// `WEISSMAN_REPLICA_COUNT` to the Deployment size. Unset defaults to 8 so an
/// omitted var cannot widen the per-pod flood window. Single-node / E2E stacks
/// default to 1.
#[must_use]
pub fn replica_count() -> NonZeroU32 {
    if let Ok(s) = std::env::var("WEISSMAN_REPLICA_COUNT") {
        if let Ok(n) = s.trim().parse::<u32>() {
            if let Some(nz) = NonZeroU32::new(n) {
                return nz;
            }
        }
    }
    if crate::security_startup::env_truthy_pub("WEISSMAN_E2E_STACK")
        || crate::security_startup::env_truthy_pub("WEISSMAN_ALLOW_SINGLE_NODE")
    {
        return NonZeroU32::MIN;
    }
    NonZeroU32::new(8).expect("8 is non-zero")
}

/// Local cap when Redis is down: half the global quota, split across replicas.
/// Floor of 1 so a huge replica count cannot disable the governor entirely.
#[must_use]
pub fn degraded_local_quota(global: NonZeroU32) -> NonZeroU32 {
    degraded_local_quota_with_replicas(global, replica_count())
}

#[must_use]
pub fn degraded_local_quota_with_replicas(global: NonZeroU32, replicas: NonZeroU32) -> NonZeroU32 {
    let half = (global.get() / 2).max(1);
    NonZeroU32::new((half / replicas.get()).max(1)).unwrap_or(NonZeroU32::MIN)
}

/// SOC-visible Redis outage. Rate-limited to once per 60s so a spray cannot flood logs.
pub fn notify_redis_degraded(component: &'static str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    static LAST: AtomicU64 = AtomicU64::new(0);
    let prev = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(prev) < 60 {
        return;
    }
    if LAST
        .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    tracing::error!(
        target: "weissman_soc",
        component,
        "Redis unavailable or sync unhealthy — governor degraded to 50%/replica in-memory cap (not fail-closed 503)"
    );
}

/// Standard 503 when Redis is required but unreachable (fail-closed).
/// Used by MFA/sqlx paths that cannot degrade; login/API governors must not call this.
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
    match incr_and_bound_ttl(&mut conn, key, window).await {
        Ok(count) => StrictOp::Ok(count),
        Err(_) => StrictOp::Unavailable,
    }
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

static REDIS_SYNC_UNHEALTHY: AtomicBool = AtomicBool::new(false);

fn deny_until() -> &'static DashMap<String, Instant> {
    static M: OnceLock<DashMap<String, Instant>> = OnceLock::new();
    M.get_or_init(DashMap::new)
}

fn deny_map_key(kind: &str, ip: &str) -> String {
    format!("{kind}:{ip}")
}

/// True when a prior async Redis INCR observed this IP over the global burst.
#[must_use]
pub fn distributed_ip_denied(kind: &str, ip: &str) -> bool {
    let key = deny_map_key(kind, ip);
    match deny_until().get(&key) {
        Some(until) if *until > Instant::now() => true,
        Some(_) => {
            deny_until().remove(&key);
            false
        }
        None => false,
    }
}

/// True when the last async Redis INCR failed (outage). Request path must not await Redis.
#[must_use]
pub fn redis_sync_unhealthy() -> bool {
    REDIS_SYNC_UNHEALTHY.load(Ordering::Relaxed)
}

fn record_async_incr(kind: &str, ip: &str, max: u64, window: Duration, op: StrictOp<u64>) {
    match op {
        StrictOp::Ok(n) if n > max => {
            deny_until().insert(deny_map_key(kind, ip), Instant::now() + window);
            REDIS_SYNC_UNHEALTHY.store(false, Ordering::Relaxed);
        }
        StrictOp::Ok(_) => {
            REDIS_SYNC_UNHEALTHY.store(false, Ordering::Relaxed);
        }
        StrictOp::Unavailable => {
            REDIS_SYNC_UNHEALTHY.store(true, Ordering::Relaxed);
        }
    }
}

/// Fire-and-forget Redis token-bucket INCR for login. Does not run on the request task.
pub fn spawn_incr_login_ip(ip: String, max: u64) {
    tokio::spawn(async move {
        let op = incr_login_ip_strict(&ip).await;
        record_async_incr("login", &ip, max, Duration::from_secs(60), op);
    });
}

/// Fire-and-forget Redis token-bucket INCR for agent enroll.
pub fn spawn_incr_enroll_ip(ip: String, max: u64) {
    tokio::spawn(async move {
        let op = incr_enroll_ip_strict(&ip).await;
        record_async_incr("enroll", &ip, max, Duration::from_secs(60), op);
    });
}

/// Fire-and-forget Redis token-bucket INCR for authenticated API traffic.
pub fn spawn_incr_api_ip(ip: String, max: u64) {
    tokio::spawn(async move {
        let op = incr_api_ip_strict(&ip).await;
        record_async_incr("api", &ip, max, Duration::from_secs(1), op);
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn request_path_governors_must_degrade_not_503() {
        let src = include_str!("rate_limit_redis.rs");
        let prod = src.split("#[cfg(test)]").next().expect("production source");
        assert!(prod.contains("redis_degraded"));
        assert!(prod.contains("degraded_local_quota"));
        assert!(prod.contains("WEISSMAN_REPLICA_COUNT"));
        assert!(prod.contains("weissman_soc"));
        assert!(prod.contains("50%"));
        let login = include_str!("login_rate_limit.rs");
        let login_prod = login.split("#[cfg(test)]").next().expect("login prod");
        assert!(
            !login_prod.contains("distributed_store_unavailable_response"),
            "login governor must not 503 when Redis is unhealthy"
        );
        assert!(login_prod.contains("redis_degraded"));
        assert!(
            login_prod.contains("weissman_soc") || login_prod.contains("notify_redis_degraded")
        );
        let api = include_str!("api_rate_limit.rs");
        let api_prod = api.split("#[cfg(test)]").next().expect("api prod");
        assert!(
            !api_prod.contains("distributed_store_unavailable_response"),
            "API governor must not 503 when Redis is unhealthy"
        );
        assert!(api_prod.contains("redis_degraded"));
    }

    #[test]
    fn degraded_quota_splits_half_across_replicas() {
        use super::degraded_local_quota_with_replicas;
        use std::num::NonZeroU32;
        let g = NonZeroU32::new(100).unwrap();
        let ten = NonZeroU32::new(10).unwrap();
        let hundred = NonZeroU32::new(100).unwrap();
        assert_eq!(degraded_local_quota_with_replicas(g, ten).get(), 5); // 50/10
        assert_eq!(degraded_local_quota_with_replicas(g, hundred).get(), 1); // floor
        let one = NonZeroU32::MIN;
        assert_eq!(degraded_local_quota_with_replicas(g, one).get(), 50); // single replica
    }

    #[test]
    fn incr_bound_ttl_lua_cannot_incr_without_expire_repair() {
        let lua = super::INCR_BOUND_TTL_LUA.replace(char::is_whitespace, "");
        assert!(
            lua.contains("redis.call('INCR',KEYS[1])"),
            "window counter must INCR inside Lua"
        );
        assert!(
            lua.contains("redis.call('PEXPIRE',KEYS[1],ttl_ms)"),
            "missing TTL must be repaired in the same eval as INCR"
        );
        assert!(
            lua.contains("redis.call('PTTL',KEYS[1])<0"),
            "heal path must look at PTTL, not a client-side count==1"
        );
        assert!(
            !lua.contains("ifn==1"),
            "must not gate EXPIRE on first INCR only"
        );
    }
}
