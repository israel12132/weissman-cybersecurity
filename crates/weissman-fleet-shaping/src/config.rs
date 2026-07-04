use serde::{Deserialize, Serialize};

/// Fleet-wide traffic shaping configuration (env-overridable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetShapingConfig {
    /// Base sustained request rate per target host (tokens/sec) across the entire fleet.
    pub base_rate_per_sec: f64,
    /// Maximum burst capacity per target bucket.
    pub burst_capacity: f64,
    /// Redis round-trip EMA above this threshold triggers degraded local shaping.
    pub redis_degrade_latency_ms: u64,
    /// Local degraded mode uses this fraction of the configured rate.
    pub degraded_rate_fraction: f64,
    /// Telemetry micro-batch flush interval.
    pub telemetry_flush_ms: u64,
    /// Time bucket width for CRDT counters (seconds).
    pub telemetry_bucket_secs: u64,
    /// Redis key TTL for token buckets (seconds).
    pub bucket_ttl_secs: u64,
    /// Worker identity label for telemetry attribution.
    pub worker_id: String,
}

impl Default for FleetShapingConfig {
    fn default() -> Self {
        Self {
            base_rate_per_sec: 8.0,
            burst_capacity: 16.0,
            redis_degrade_latency_ms: 75,
            degraded_rate_fraction: 0.12,
            telemetry_flush_ms: 250,
            telemetry_bucket_secs: 10,
            bucket_ttl_secs: 600,
            worker_id: "unknown".into(),
        }
    }
}

impl FleetShapingConfig {
    /// Load from environment with sane defaults.
    #[must_use]
    pub fn from_env(worker_id: impl Into<String>) -> Self {
        let mut cfg = Self {
            worker_id: worker_id.into(),
            ..Self::default()
        };
        if let Ok(v) = std::env::var("WEISSMAN_FLEET_BASE_RATE") {
            if let Ok(n) = v.parse::<f64>() {
                if n > 0.0 {
                    cfg.base_rate_per_sec = n;
                }
            }
        }
        if let Ok(v) = std::env::var("WEISSMAN_FLEET_BURST") {
            if let Ok(n) = v.parse::<f64>() {
                if n > 0.0 {
                    cfg.burst_capacity = n;
                }
            }
        }
        if let Ok(v) = std::env::var("WEISSMAN_FLEET_REDIS_DEGRADE_MS") {
            if let Ok(n) = v.parse::<u64>() {
                cfg.redis_degrade_latency_ms = n.max(10);
            }
        }
        if let Ok(v) = std::env::var("WEISSMAN_FLEET_DEGRADED_FRACTION") {
            if let Ok(n) = v.parse::<f64>() {
                if (0.01..=1.0).contains(&n) {
                    cfg.degraded_rate_fraction = n;
                }
            }
        }
        cfg
    }
}
