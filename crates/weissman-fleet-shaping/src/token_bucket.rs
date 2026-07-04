//! Atomic distributed token bucket — single Lua round-trip, zero read-modify-write races.

use crate::config::FleetShapingConfig;
use crate::error::FleetShapingError;
use redis::Script;
use std::sync::OnceLock;

/// Returns `(granted: 0|1, tokens_remaining_or_retry_ms)`.
const TOKEN_BUCKET_LUA: &str = r#"
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local need = tonumber(ARGV[2])
local capacity = tonumber(ARGV[3])
local rate = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

local tokens = tonumber(redis.call('HGET', key, 'tokens'))
local last_ms = tonumber(redis.call('HGET', key, 'last_ms'))

if tokens == nil then
  tokens = capacity
  last_ms = now_ms
end

local elapsed = math.max(0, (now_ms - last_ms) / 1000.0)
tokens = math.min(capacity, tokens + elapsed * rate)

if tokens >= need then
  tokens = tokens - need
  redis.call('HSET', key, 'tokens', tokens, 'last_ms', now_ms)
  redis.call('EXPIRE', key, ttl)
  return {1, tokens}
end

redis.call('HSET', key, 'tokens', tokens, 'last_ms', now_ms)
redis.call('EXPIRE', key, ttl)
local deficit = need - tokens
local wait_ms = math.ceil((deficit / rate) * 1000.0)
if wait_ms < 1 then wait_ms = 1 end
return {0, wait_ms}
"#;

fn token_script() -> &'static Script {
    static S: OnceLock<Script> = OnceLock::new();
    S.get_or_init(|| Script::new(TOKEN_BUCKET_LUA))
}

pub fn bucket_key(tenant_id: i64, target_host: &str) -> String {
    let host = target_host.trim().to_ascii_lowercase();
    format!("weissman:fleet:tb:{tenant_id}:{host}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireOutcome {
    Granted,
    Denied,
}

#[derive(Debug, Clone)]
pub struct AcquireResult {
    pub outcome: AcquireOutcome,
    pub tokens_remaining: Option<f64>,
    pub retry_after_ms: Option<u64>,
}

/// Atomically acquire `tokens` from the global bucket for `(tenant_id, target_host)`.
pub async fn acquire_tokens(
    redis: &mut redis::aio::ConnectionManager,
    tenant_id: i64,
    target_host: &str,
    tokens: f64,
    effective_rate: f64,
    cfg: &FleetShapingConfig,
) -> Result<AcquireResult, FleetShapingError> {
    let key = bucket_key(tenant_id, target_host);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let need = tokens.max(0.001);
    let rate = effective_rate.max(0.1);
    let capacity = cfg.burst_capacity.max(need);

    let (granted, value): (i32, f64) = token_script()
        .key(&key)
        .arg(now_ms)
        .arg(need)
        .arg(capacity)
        .arg(rate)
        .arg(cfg.bucket_ttl_secs as i64)
        .invoke_async(redis)
        .await
        .map_err(|e| FleetShapingError::Redis(e.to_string()))?;

    if granted == 1 {
        Ok(AcquireResult {
            outcome: AcquireOutcome::Granted,
            tokens_remaining: Some(value),
            retry_after_ms: None,
        })
    } else {
        Ok(AcquireResult {
            outcome: AcquireOutcome::Denied,
            tokens_remaining: None,
            retry_after_ms: Some(value.max(1.0) as u64),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_key_normalizes_host() {
        assert_eq!(
            bucket_key(42, "Example.COM"),
            "weissman:fleet:tb:42:example.com"
        );
    }
}
