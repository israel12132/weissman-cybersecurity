//! Fleet coordinator — orchestrates global token bucket, adaptive stealth, telemetry, and degradation.

use crate::adaptive::{read_multiplier, record_pain_and_multiplier, TargetPainSignal};
use crate::config::FleetShapingConfig;
use crate::degraded::{DegradedLocalShaper, ShapingMode};
use crate::error::FleetShapingError;
use crate::telemetry::{TelemetryAggregator, TelemetryMetric};
use crate::token_bucket::{acquire_tokens, AcquireOutcome, AcquireResult};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

pub struct FleetCoordinator {
    cfg: FleetShapingConfig,
    redis: Option<redis::aio::ConnectionManager>,
    local: DegradedLocalShaper,
    telemetry: Arc<TelemetryAggregator>,
}

impl FleetCoordinator {
    /// Connect from `REDIS_URL`. When unset, operates in local-only degraded mode.
    pub async fn from_env(worker_id: impl Into<String>) -> Self {
        let cfg = FleetShapingConfig::from_env(worker_id);
        let redis = redis_manager_from_env().await;
        let mode = if redis.is_some() {
            ShapingMode::Global
        } else {
            ShapingMode::LocalOnly
        };
        let degrade_ms = cfg.redis_degrade_latency_ms;
        let telemetry = TelemetryAggregator::new(cfg.clone(), redis.clone());
        if redis.is_some() {
            telemetry.clone().spawn_flush_loop().await;
        }
        tracing::info!(
            target: "fleet_shaping",
            mode = mode.as_str(),
            base_rate = cfg.base_rate_per_sec,
            burst = cfg.burst_capacity,
            "fleet traffic shaper online"
        );
        Self {
            cfg,
            redis,
            local: DegradedLocalShaper::new(degrade_ms),
            telemetry,
        }
    }

    #[must_use]
    pub fn is_redis_enabled(&self) -> bool {
        self.redis.is_some()
    }

    pub fn telemetry(&self) -> Arc<TelemetryAggregator> {
        Arc::clone(&self.telemetry)
    }

    #[must_use]
    pub fn shaping_mode(&self) -> ShapingMode {
        if self.redis.is_none() {
            return ShapingMode::LocalOnly;
        }
        if self.local.should_degrade() {
            ShapingMode::Degraded
        } else {
            ShapingMode::Global
        }
    }

    /// Acquire one probe token for `(tenant_id, target_host)`. Blocks with async sleep until granted.
    pub async fn acquire_probe(
        &self,
        tenant_id: i64,
        target_host: &str,
    ) -> Result<(), FleetShapingError> {
        loop {
            let result = self.try_acquire_probe(tenant_id, target_host, 1.0).await?;
            match result.outcome {
                AcquireOutcome::Granted => return Ok(()),
                AcquireOutcome::Denied => {
                    let wait = result.retry_after_ms.unwrap_or(50).min(5_000);
                    self.telemetry
                        .incr(tenant_id, TelemetryMetric::ProbesDenied, 1);
                    sleep(Duration::from_millis(wait)).await;
                }
            }
        }
    }

    /// Non-blocking acquire attempt.
    pub async fn try_acquire_probe(
        &self,
        tenant_id: i64,
        target_host: &str,
        tokens: f64,
    ) -> Result<AcquireResult, FleetShapingError> {
        self.telemetry
            .incr(tenant_id, TelemetryMetric::ProbesTotal, 1);
        let mode = self.shaping_mode();

        let result = match mode {
            ShapingMode::Global => {
                let Some(ref redis) = self.redis else {
                    return Ok(self.local.try_acquire(
                        tenant_id,
                        target_host,
                        tokens,
                        &self.cfg,
                        ShapingMode::LocalOnly,
                    ));
                };
                let start = Instant::now();
                let mut conn = redis.clone();
                let multiplier = read_multiplier(&mut conn, tenant_id, target_host).await?;
                let effective_rate = self.cfg.base_rate_per_sec * multiplier;
                let acquired = acquire_tokens(
                    &mut conn,
                    tenant_id,
                    target_host,
                    tokens,
                    effective_rate,
                    &self.cfg,
                )
                .await;
                self.local.record_redis_latency(start.elapsed());
                match acquired {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(target: "fleet_shaping", error = %e, "redis acquire failed — degraded local");
                        self.telemetry
                            .incr(tenant_id, TelemetryMetric::ProbesDegraded, 1);
                        self.local.try_acquire(
                            tenant_id,
                            target_host,
                            tokens,
                            &self.cfg,
                            ShapingMode::Degraded,
                        )
                    }
                }
            }
            ShapingMode::Degraded | ShapingMode::LocalOnly => {
                self.telemetry
                    .incr(tenant_id, TelemetryMetric::ProbesDegraded, 1);
                self.local
                    .try_acquire(tenant_id, target_host, tokens, &self.cfg, mode)
            }
        };

        match result.outcome {
            AcquireOutcome::Granted => {
                self.telemetry
                    .incr(tenant_id, TelemetryMetric::ProbesGranted, 1);
            }
            AcquireOutcome::Denied => {}
        }
        Ok(result)
    }

    /// Report target pain after a probe — shrinks global bucket for the fleet.
    pub async fn report_probe_outcome(
        &self,
        tenant_id: i64,
        target_host: &str,
        signal: TargetPainSignal,
    ) {
        if signal.pain_delta() > 0.0 {
            self.telemetry
                .incr(tenant_id, TelemetryMetric::PainEvents, 1);
            if signal.http_status == Some(429) {
                self.telemetry.incr(tenant_id, TelemetryMetric::Http429, 1);
            }
            if matches!(signal.http_status, Some(503 | 502 | 504)) {
                self.telemetry.incr(tenant_id, TelemetryMetric::Http503, 1);
            }
            if signal.tcp_reset {
                self.telemetry
                    .incr(tenant_id, TelemetryMetric::TcpResets, 1);
            }
        }
        if let Some(ref redis) = self.redis {
            if self.shaping_mode() == ShapingMode::Global {
                let start = Instant::now();
                let mut conn = redis.clone();
                if let Err(e) =
                    record_pain_and_multiplier(&mut conn, tenant_id, target_host, &signal).await
                {
                    tracing::debug!(target: "fleet_shaping", error = %e, "pain record failed");
                }
                self.local.record_redis_latency(start.elapsed());
            }
        }
    }

    pub fn record_findings(&self, tenant_id: i64, count: i64) {
        if count > 0 {
            self.telemetry
                .incr(tenant_id, TelemetryMetric::FindingsEmitted, count);
        }
    }

    pub fn record_engine_error(&self, tenant_id: i64) {
        self.telemetry
            .incr(tenant_id, TelemetryMetric::EngineErrors, 1);
    }

    /// Command Center snapshot.
    pub async fn snapshot(&self, tenant_id: i64) -> Value {
        let counters = self
            .telemetry
            .snapshot_tenant(tenant_id, 12)
            .await
            .unwrap_or_else(|e| serde_json::json!({ "enabled": false, "error": e.to_string() }));
        serde_json::json!({
            "shaping_mode": self.shaping_mode().as_str(),
            "redis_enabled": self.is_redis_enabled(),
            "redis_latency_ema_ms": self.local.redis_latency_ema_ms(),
            "base_rate_per_sec": self.cfg.base_rate_per_sec,
            "burst_capacity": self.cfg.burst_capacity,
            "worker_id": self.cfg.worker_id,
            "telemetry": counters,
        })
    }
}

pub async fn redis_manager_from_env() -> Option<redis::aio::ConnectionManager> {
    let url = std::env::var("REDIS_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())?;
    let client = redis::Client::open(url).ok()?;
    client.get_connection_manager().await.ok()
}
