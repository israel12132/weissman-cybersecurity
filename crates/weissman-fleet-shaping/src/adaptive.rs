//! Adaptive stealth: target pain signals shrink the global token bucket in real time.

use crate::error::FleetShapingError;
use redis::Script;
use std::sync::OnceLock;

/// Pain accumulator + adaptive multiplier — atomic EMA in one Lua script.
/// Returns effective rate multiplier in millis (divide by 1000 for f64).
const ADAPTIVE_LUA: &str = r#"
local key = KEYS[1]
local delta = tonumber(ARGV[1])
local decay = tonumber(ARGV[2])
local min_m = tonumber(ARGV[3])
local max_m = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

local pain = tonumber(redis.call('GET', key))
if pain == nil then pain = 0 end
pain = math.min(100, pain * decay + delta)
redis.call('SET', key, pain, 'EX', ttl)

local span = max_m - min_m
local mult = max_m - (pain / 100.0) * span
if mult < min_m then mult = min_m end
return math.floor(mult * 1000 + 0.5)
"#;

fn adaptive_script() -> &'static Script {
    static S: OnceLock<Script> = OnceLock::new();
    S.get_or_init(|| Script::new(ADAPTIVE_LUA))
}

pub fn pain_key(tenant_id: i64, target_host: &str) -> String {
    let host = target_host.trim().to_ascii_lowercase();
    format!("weissman:fleet:pain:{tenant_id}:{host}")
}

/// Signals observed on a live probe against a target.
#[derive(Debug, Clone, Default)]
pub struct TargetPainSignal {
    pub http_status: Option<u16>,
    pub ttfb_ms: Option<u64>,
    pub tcp_reset: bool,
    pub connection_error: bool,
}

impl TargetPainSignal {
    /// Map wire observations to a 0–40 pain delta for the EMA accumulator.
    #[must_use]
    pub fn pain_delta(&self) -> f64 {
        let mut d = 0.0f64;
        if let Some(status) = self.http_status {
            match status {
                429 => d += 35.0,
                503 | 502 | 504 => d += 28.0,
                403 if self.ttfb_ms.is_some_and(|t| t < 80) => d += 18.0,
                s if (500..=599).contains(&s) => d += 12.0,
                _ => {}
            }
        }
        if self.tcp_reset {
            d += 30.0;
        }
        if self.connection_error {
            d += 15.0;
        }
        if self.ttfb_ms.is_some_and(|t| t > 4_000) {
            d += 10.0;
        } else if self.ttfb_ms.is_some_and(|t| t > 2_000) {
            d += 5.0;
        }
        d.min(40.0)
    }
}

/// Record pain and return the new fleet-wide rate multiplier (0.1 – 1.0).
pub async fn record_pain_and_multiplier(
    redis: &mut redis::aio::ConnectionManager,
    tenant_id: i64,
    target_host: &str,
    signal: &TargetPainSignal,
) -> Result<f64, FleetShapingError> {
    let delta = signal.pain_delta();
    if delta <= 0.0 {
        return read_multiplier(redis, tenant_id, target_host).await;
    }
    let key = pain_key(tenant_id, target_host);
    let mult_millis: i64 = adaptive_script()
        .key(&key)
        .arg(delta)
        .arg(0.82_f64) // EMA decay — recent pain dominates
        .arg(0.10_f64) // floor multiplier
        .arg(1.0_f64) // ceiling multiplier
        .arg(300_i64) // TTL seconds
        .invoke_async(redis)
        .await
        .map_err(|e| FleetShapingError::Redis(e.to_string()))?;
    Ok((mult_millis as f64 / 1000.0).clamp(0.10, 1.0))
}

/// Read current multiplier without recording new pain.
pub async fn read_multiplier(
    redis: &mut redis::aio::ConnectionManager,
    tenant_id: i64,
    target_host: &str,
) -> Result<f64, FleetShapingError> {
    let key = pain_key(tenant_id, target_host);
    let pain_raw: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(redis)
        .await
        .map_err(|e| FleetShapingError::Redis(e.to_string()))?;
    let pain = pain_raw
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0)
        .clamp(0.0, 100.0);
    let mult = 1.0 - (pain / 100.0) * 0.90;
    Ok(mult.clamp(0.10, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pain_delta_429_is_severe() {
        let s = TargetPainSignal {
            http_status: Some(429),
            ..Default::default()
        };
        assert!(s.pain_delta() >= 30.0);
    }

    #[test]
    fn pain_delta_clean_is_zero() {
        let s = TargetPainSignal {
            http_status: Some(200),
            ttfb_ms: Some(120),
            ..Default::default()
        };
        assert_eq!(s.pain_delta(), 0.0);
    }
}
