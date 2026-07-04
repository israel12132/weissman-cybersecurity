//! Lock-free CRDT telemetry — commutative HINCRBY merges across N workers without locks.

use crate::config::FleetShapingConfig;
use crate::error::FleetShapingError;
use dashmap::DashMap;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::interval;

const TELEM_CRDT_PREFIX: &str = "weissman:fleet:crdt";

/// Commutative counter names merged fleet-wide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TelemetryMetric {
    ProbesTotal,
    ProbesGranted,
    ProbesDenied,
    ProbesDegraded,
    PainEvents,
    Http429,
    Http503,
    TcpResets,
    FindingsEmitted,
    EngineErrors,
}

impl TelemetryMetric {
    fn as_str(self) -> &'static str {
        match self {
            Self::ProbesTotal => "probes_total",
            Self::ProbesGranted => "probes_granted",
            Self::ProbesDenied => "probes_denied",
            Self::ProbesDegraded => "probes_degraded",
            Self::PainEvents => "pain_events",
            Self::Http429 => "http_429",
            Self::Http503 => "http_503",
            Self::TcpResets => "tcp_resets",
            Self::FindingsEmitted => "findings_emitted",
            Self::EngineErrors => "engine_errors",
        }
    }
}

fn bucket_ts(cfg: &FleetShapingConfig) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let w = cfg.telemetry_bucket_secs.max(1);
    (now / w) * w
}

fn crdt_key(tenant_id: i64, bucket: u64) -> String {
    format!("{TELEM_CRDT_PREFIX}:{tenant_id}:{bucket}")
}
/// In-process micro-batch buffer — flushed to Redis via HINCRBY (CRDT-safe).
pub struct TelemetryAggregator {
    cfg: FleetShapingConfig,
    redis: Option<redis::aio::ConnectionManager>,
    pending: DashMap<(i64, u64, &'static str), i64>,
    flush_errors: AtomicU64,
    flusher: Mutex<Option<JoinHandle<()>>>,
}

impl TelemetryAggregator {
    pub fn new(cfg: FleetShapingConfig, redis: Option<redis::aio::ConnectionManager>) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            redis,
            pending: DashMap::new(),
            flush_errors: AtomicU64::new(0),
            flusher: Mutex::new(None),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.redis.is_some()
    }

    /// Record a commutative increment (lock-free local merge).
    pub fn incr(&self, tenant_id: i64, metric: TelemetryMetric, delta: i64) {
        if delta == 0 {
            return;
        }
        let bucket = bucket_ts(&self.cfg);
        let field = metric.as_str();
        self.pending
            .entry((tenant_id, bucket, field))
            .and_modify(|v| *v += delta)
            .or_insert(delta);
    }

    /// Spawn background flush loop.
    pub async fn spawn_flush_loop(self: &Arc<Self>) {
        let Some(redis) = self.redis.clone() else {
            return;
        };
        let agg = Arc::clone(self);
        let period = Duration::from_millis(self.cfg.telemetry_flush_ms.max(50));
        let handle = tokio::spawn(async move {
            let mut tick = interval(period);
            loop {
                tick.tick().await;
                if let Err(e) = agg.flush_once(redis.clone()).await {
                    tracing::warn!(target: "fleet_telemetry", error = %e, "flush failed");
                    agg.flush_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        let mut guard = self.flusher.lock().await;
        *guard = Some(handle);
    }

    async fn flush_once(
        &self,
        mut redis: redis::aio::ConnectionManager,
    ) -> Result<(), FleetShapingError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let snapshot: Vec<((i64, u64, &'static str), i64)> = self
            .pending
            .iter()
            .map(|e| (*e.key(), *e.value()))
            .collect();
        if snapshot.is_empty() {
            return Ok(());
        }
        for ((tenant_id, bucket, field), count) in &snapshot {
            if *count == 0 {
                continue;
            }
            let key = crdt_key(*tenant_id, *bucket);
            let _: i64 = redis
                .hincr(&key, *field, *count)
                .await
                .map_err(|e| FleetShapingError::Redis(e.to_string()))?;
            let _: bool = redis
                .expire(&key, 3600)
                .await
                .map_err(|e| FleetShapingError::Redis(e.to_string()))?;
        }
        for ((tenant_id, bucket, field), count) in snapshot {
            self.pending
                .entry((tenant_id, bucket, field))
                .and_modify(|v| *v -= count);
        }
        self.pending.retain(|_, v| *v != 0);
        Ok(())
    }

    /// Read merged CRDT counters for Command Center (last N buckets).
    pub async fn snapshot_tenant(
        &self,
        tenant_id: i64,
        buckets: u32,
    ) -> Result<Value, FleetShapingError> {
        let Some(ref redis) = self.redis else {
            return Ok(json!({ "enabled": false }));
        };
        let mut conn = redis.clone();
        let w = self.cfg.telemetry_bucket_secs.max(1);
        let now_bucket = bucket_ts(&self.cfg);
        let mut series = Vec::new();
        let n = buckets.max(1).min(60);
        for i in 0..n {
            let b = now_bucket.saturating_sub(u64::from(i) * w);
            let key = crdt_key(tenant_id, b);
            let map: std::collections::HashMap<String, i64> = conn
                .hgetall(&key)
                .await
                .map_err(|e| FleetShapingError::Redis(e.to_string()))?;
            if !map.is_empty() {
                series.push(json!({ "bucket_ts": b, "counters": map }));
            }
        }
        Ok(json!({
            "enabled": true,
            "tenant_id": tenant_id,
            "bucket_width_secs": w,
            "series": series,
            "flush_errors": self.flush_errors.load(Ordering::Relaxed),
            "worker_id": self.cfg.worker_id,
        }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetTelemetrySnapshot {
    pub enabled: bool,
    pub shaping_mode: String,
    pub redis_latency_ema_ms: u64,
    pub tenant_id: i64,
    pub counters: Value,
}
