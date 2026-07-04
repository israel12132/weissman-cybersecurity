//! Graceful degradation — local token buckets when Redis is slow or unavailable.

use crate::config::FleetShapingConfig;
use crate::token_bucket::{AcquireOutcome, AcquireResult};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapingMode {
    /// Global Redis Lua token bucket (fleet-coordinated).
    Global,
    /// Redis latency high — heavily throttled per-worker local bucket.
    Degraded,
    /// Redis unavailable at boot — local only, never unrestricted.
    LocalOnly,
}

impl ShapingMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Degraded => "degraded",
            Self::LocalOnly => "local_only",
        }
    }
}

struct LocalBucketState {
    tokens: f64,
    last: Instant,
}

/// Per-(tenant, host) local buckets for degraded mode — never allows burst above fraction of global.
pub struct DegradedLocalShaper {
    buckets: DashMap<(i64, String), LocalBucketState>,
    redis_latency_ema_us: AtomicU64,
    degrade_threshold_us: u64,
}

impl DegradedLocalShaper {
    #[must_use]
    pub fn new(degrade_threshold_ms: u64) -> Self {
        Self {
            buckets: DashMap::new(),
            redis_latency_ema_us: AtomicU64::new(0),
            degrade_threshold_us: degrade_threshold_ms.saturating_mul(1000).max(10_000),
        }
    }

    pub fn record_redis_latency(&self, latency: std::time::Duration) {
        let us = latency.as_micros().min(u128::from(u64::MAX)) as u64;
        let prev = self.redis_latency_ema_us.load(Ordering::Relaxed);
        let ema = if prev == 0 {
            us
        } else {
            (prev * 7 + us * 3) / 10
        };
        self.redis_latency_ema_us.store(ema, Ordering::Relaxed);
    }

    #[must_use]
    pub fn redis_latency_ema_ms(&self) -> u64 {
        self.redis_latency_ema_us.load(Ordering::Relaxed) / 1000
    }

    #[must_use]
    pub fn should_degrade(&self) -> bool {
        self.redis_latency_ema_us.load(Ordering::Relaxed) > self.degrade_threshold_us
    }

    /// Try acquire from local bucket (used in degraded / local-only modes).
    pub fn try_acquire(
        &self,
        tenant_id: i64,
        target_host: &str,
        tokens: f64,
        cfg: &FleetShapingConfig,
        mode: ShapingMode,
    ) -> AcquireResult {
        let host = target_host.trim().to_ascii_lowercase();
        let fraction = match mode {
            ShapingMode::Degraded => cfg.degraded_rate_fraction,
            ShapingMode::LocalOnly => cfg.degraded_rate_fraction * 0.75,
            ShapingMode::Global => cfg.degraded_rate_fraction,
        };
        let rate = (cfg.base_rate_per_sec * fraction).max(0.05);
        let capacity = (cfg.burst_capacity * fraction).max(1.0);
        let need = tokens.max(0.001);

        let mut entry = self
            .buckets
            .entry((tenant_id, host))
            .or_insert_with(|| LocalBucketState {
                tokens: capacity,
                last: Instant::now(),
            });

        let now = Instant::now();
        let elapsed = now.duration_since(entry.last).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * rate).min(capacity);
        entry.last = now;

        if entry.tokens >= need {
            entry.tokens -= need;
            AcquireResult {
                outcome: AcquireOutcome::Granted,
                tokens_remaining: Some(entry.tokens),
                retry_after_ms: None,
            }
        } else {
            let deficit = need - entry.tokens;
            let wait_ms = ((deficit / rate) * 1000.0).ceil().max(1.0) as u64;
            AcquireResult {
                outcome: AcquireOutcome::Denied,
                tokens_remaining: None,
                retry_after_ms: Some(wait_ms),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn degraded_mode_throttles_heavily() {
        let cfg = FleetShapingConfig {
            base_rate_per_sec: 10.0,
            burst_capacity: 10.0,
            degraded_rate_fraction: 0.1,
            ..FleetShapingConfig::default()
        };
        let shaper = DegradedLocalShaper::new(50);
        let r1 = shaper.try_acquire(1, "target.test", 1.0, &cfg, ShapingMode::Degraded);
        assert_eq!(r1.outcome, AcquireOutcome::Granted);
        let r2 = shaper.try_acquire(1, "target.test", 100.0, &cfg, ShapingMode::Degraded);
        assert_eq!(r2.outcome, AcquireOutcome::Denied);
    }
}
