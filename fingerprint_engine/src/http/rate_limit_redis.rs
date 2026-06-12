//! Distributed rate-limit counters via Redis (`REDIS_URL`). Falls back to in-process governor when unset.

use redis::AsyncCommands;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub struct RedisRateLimiter {
    client: redis::Client,
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
    let rl = shared()?;
    let mut conn = rl.client.get_multiplexed_async_connection().await.ok()?;
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
    let mut conn = rl.client.get_multiplexed_async_connection().await.ok()?;
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
    if let Ok(mut conn) = rl.client.get_multiplexed_async_connection().await {
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
    if let Ok(mut conn) = rl.client.get_multiplexed_async_connection().await {
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
    let Ok(mut conn) = rl.client.get_multiplexed_async_connection().await else {
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
    let Ok(mut conn) = rl.client.get_multiplexed_async_connection().await else {
        return Vec::new();
    };
    let map: std::collections::HashMap<String, i64> = conn.hgetall(&key).await.unwrap_or_default();
    let mut out: Vec<(String, u32)> = map.into_iter().map(|(k, v)| (k, v.max(0) as u32)).collect();
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out.truncate(cap);
    out
}

#[must_use]
pub fn is_enabled() -> bool {
    shared().is_some()
}
