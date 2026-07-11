//! Self-healing worker swarm — sub-second liveness, gossip, instant orphan triage.

use crate::error::JobBusError;
use crate::JobBus;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::Row;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use uuid::Uuid;

const SWARM_REGISTRY_PREFIX: &str = "weissman:swarm:worker:";
const SWARM_GOSSIP_STREAM: &str = "weissman:swarm:gossip";
/// Approximate cap on retained gossip-stream entries so it can't grow without bound.
const SWARM_GOSSIP_MAXLEN: i64 = 10_000;
const LIVENESS_TTL_SECS: u64 = 2;
const LIVENESS_REFRESH_MS: u64 = 400;

pub async fn redis_manager_from_env() -> Option<redis::aio::ConnectionManager> {
    let url = std::env::var("REDIS_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())?;
    let client = redis::Client::open(url.as_str()).ok()?;
    redis::aio::ConnectionManager::new(client).await.ok()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmMessage {
    Heartbeat {
        worker_id: String,
        pid: u32,
        jobs_active: u32,
    },
    JobClaimed {
        worker_id: String,
        job_id: Uuid,
    },
    WorkerDown {
        worker_id: String,
        reason: String,
    },
}

/// Per-worker swarm actor: aggressive liveness + gossip publication.
pub struct WorkerSwarm {
    redis: redis::aio::ConnectionManager,
    worker_id: String,
    stop: Arc<AtomicBool>,
}

impl WorkerSwarm {
    pub fn new(redis: redis::aio::ConnectionManager, worker_id: String) -> Self {
        Self {
            redis,
            worker_id,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Refresh liveness key every 400ms (2s TTL) — death detected within ~2s, not 30min.
    pub fn spawn_liveness_loop(self: Arc<Self>) {
        let worker_id = self.worker_id.clone();
        let redis = self.redis.clone();
        let stop = self.stop.clone();
        tokio::spawn(async move {
            let key = format!("{}{}", SWARM_REGISTRY_PREFIX, worker_id);
            let mut interval = tokio::time::interval(Duration::from_millis(LIVENESS_REFRESH_MS));
            let pid = std::process::id();
            while !stop.load(Ordering::SeqCst) {
                interval.tick().await;
                let mut conn = redis.clone();
                let payload = serde_json::to_string(&SwarmMessage::Heartbeat {
                    worker_id: worker_id.clone(),
                    pid,
                    jobs_active: 0,
                })
                .unwrap_or_default();
                let _: Result<(), _> = conn.set_ex(&key, &payload, LIVENESS_TTL_SECS).await;
                let mut xadd = redis::cmd("XADD");
                xadd.arg(SWARM_GOSSIP_STREAM)
                    .arg("MAXLEN")
                    .arg("~")
                    .arg(SWARM_GOSSIP_MAXLEN)
                    .arg("*")
                    .arg("kind")
                    .arg("heartbeat")
                    .arg("worker_id")
                    .arg(&worker_id)
                    .arg("pid")
                    .arg(pid.to_string());
                let _: Result<(), _> = xadd.query_async(&mut conn).await;
            }
            let mut conn = redis.clone();
            let _: Result<(), _> = conn.del(&key).await;
        });
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub async fn gossip_job_claimed(&self, job_id: Uuid) {
        let mut conn = self.redis.clone();
        let mut xadd = redis::cmd("XADD");
        xadd.arg(SWARM_GOSSIP_STREAM)
            .arg("MAXLEN")
            .arg("~")
            .arg(SWARM_GOSSIP_MAXLEN)
            .arg("*")
            .arg("kind")
            .arg("job_claimed")
            .arg("worker_id")
            .arg(&self.worker_id)
            .arg("job_id")
            .arg(job_id.to_string());
        let _: Result<(), _> = xadd.query_async(&mut conn).await;
    }
}

/// Leader-side coordinator: scan registry, orphan jobs on worker death instantly.
pub struct SwarmCoordinator {
    bus: Arc<JobBus>,
    redis: redis::aio::ConnectionManager,
}

impl SwarmCoordinator {
    pub fn new(bus: Arc<JobBus>, redis: redis::aio::ConnectionManager) -> Self {
        Self { bus, redis }
    }

    pub fn spawn(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(800));
            loop {
                interval.tick().await;
                if let Err(e) = self.tick().await {
                    tracing::warn!(target: "job_bus_swarm", error = %e, "coordinator tick failed");
                }
            }
        });
    }

    async fn tick(&self) -> Result<(), JobBusError> {
        let pool = self.bus.pool();
        let rows = sqlx::query(
            r#"SELECT id, tenant_id, COALESCE(worker_id, '') AS worker_id
               FROM weissman_async_jobs WHERE status = 'running'"#,
        )
        .fetch_all(pool)
        .await?;

        for row in rows {
            let job_id: Uuid = row.try_get("id")?;
            let tenant_id: i64 = row.try_get("tenant_id")?;
            let worker_id: String = row.try_get("worker_id")?;
            if worker_id.is_empty() {
                continue;
            }
            let key = format!("{}{}", SWARM_REGISTRY_PREFIX, worker_id);
            let mut conn = self.redis.clone();
            let alive: bool = conn.exists(&key).await.unwrap_or(false);
            if alive {
                continue;
            }
            tracing::warn!(
                target: "job_bus_swarm",
                %job_id,
                worker_id = %worker_id,
                "worker liveness expired — orphaning job instantly"
            );
            let _ = DistributedLease::force_release(&self.redis, job_id).await;
            self.bus
                .on_worker_terminated(&worker_id, "liveness_expired")
                .await?;
            self.bus
                .on_job_orphaned(job_id, tenant_id, &worker_id, "swarm_liveness_expired")
                .await?;
            self.publish_worker_down(&worker_id).await;
        }
        Ok(())
    }

    async fn publish_worker_down(&self, worker_id: &str) {
        let mut conn = self.redis.clone();
        let mut xadd = redis::cmd("XADD");
        xadd.arg(SWARM_GOSSIP_STREAM)
            .arg("MAXLEN")
            .arg("~")
            .arg(SWARM_GOSSIP_MAXLEN)
            .arg("*")
            .arg("kind")
            .arg("worker_down")
            .arg("worker_id")
            .arg(worker_id)
            .arg("reason")
            .arg("liveness_expired");
        let _: Result<(), _> = xadd.query_async(&mut conn).await;
    }
}

use crate::lease::DistributedLease;

/// Spawn coordinator when Redis + job bus enabled (server leader).
pub fn spawn_coordinator_if_enabled(pool: PgPool) {
    tokio::spawn(async move {
        let bus = Arc::new(JobBus::from_env(pool).await);
        if !bus.is_enabled() {
            tracing::info!(target: "job_bus_swarm", "swarm coordinator disabled (no Redis/secret)");
            return;
        }
        let redis = bus.redis().cloned().expect("enabled bus has redis");
        let coord = Arc::new(SwarmCoordinator::new(bus, redis));
        coord.spawn();
        tracing::info!(target: "job_bus_swarm", "swarm coordinator active");
    });
}

// Silence unused import warning for broadcast in future gossip subscribers
#[allow(dead_code)]
type GossipRx = broadcast::Receiver<SwarmMessage>;
