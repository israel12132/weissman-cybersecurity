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
    /// In-flight job count published in the heartbeat.
    ///
    /// This was hardcoded to `0` in the payload, so the only non-identity field the "gossip"
    /// stream carried was a constant — it advertised fleet load telemetry and shipped a fixed
    /// lie. The worker now keeps it current, so a consumer of the stream has something true to
    /// read whenever one is written.
    jobs_active: Arc<std::sync::atomic::AtomicU32>,
}

impl WorkerSwarm {
    pub fn new(redis: redis::aio::ConnectionManager, worker_id: String) -> Self {
        Self {
            redis,
            worker_id,
            stop: Arc::new(AtomicBool::new(false)),
            jobs_active: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    /// Publish the current in-flight job count in subsequent heartbeats.
    pub fn set_jobs_active(&self, n: u32) {
        self.jobs_active.store(n, Ordering::Relaxed);
    }

    /// Refresh liveness key every 400ms (2s TTL) — death detected within ~2s, not 30min.
    pub fn spawn_liveness_loop(self: Arc<Self>) {
        let worker_id = self.worker_id.clone();
        let redis = self.redis.clone();
        let stop = self.stop.clone();
        let jobs_active = self.jobs_active.clone();
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
                    jobs_active: jobs_active.load(Ordering::Relaxed),
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
    /// Consecutive ticks each worker has been observed missing.
    ///
    /// The liveness key has a 2s TTL refreshed every 400ms, so a single >2s runtime stall — a GC
    /// pause, a slow syscall, a brief Redis blip — makes a perfectly healthy worker look dead for
    /// one tick. Acting on one observation meant every job that worker held (26 in a single 77ms
    /// tick, live) was orphaned and re-dispatched while it was still running them. Requiring
    /// several consecutive misses costs at most a couple of seconds of extra recovery latency and
    /// removes the entire class of blip-triggered double execution.
    missed: tokio::sync::Mutex<std::collections::HashMap<String, u32>>,
}

impl SwarmCoordinator {
    /// Consecutive missed liveness observations before a worker is declared dead.
    const MISSES_BEFORE_ORPHAN: u32 = 3;

    pub fn new(bus: Arc<JobBus>, redis: redis::aio::ConnectionManager) -> Self {
        Self {
            bus,
            redis,
            missed: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn spawn(self: Arc<Self>) {
        tokio::spawn(async move {
            // A total, permanent outage of this subsystem used to be reported as a WARN — the
            // same WARN, every 800 ms, forever. It ran for 27,001 consecutive failures in six
            // hours without one tick ever succeeding, and nothing escalated: no ERROR, no metric,
            // no health degradation. Sub-second orphan detection (the crate's headline guarantee)
            // was dead from boot and the only trace was ~108,000 identical log lines a day.
            //
            // Two changes. Escalate on a run of failures, so "briefly flaky" and "has never
            // worked" are not the same log line. And back off, so a permanently broken
            // coordinator degrades to a trickle instead of drowning the log pipeline — which is
            // itself what filled the disk on 2026-07-03.
            const BASE_INTERVAL: Duration = Duration::from_millis(800);
            const MAX_INTERVAL: Duration = Duration::from_secs(30);
            const ESCALATE_AFTER: u32 = 5;

            let mut consecutive_failures: u32 = 0;
            let mut delay = BASE_INTERVAL;
            loop {
                tokio::time::sleep(delay).await;
                match self.tick().await {
                    Ok(()) => {
                        if consecutive_failures >= ESCALATE_AFTER {
                            tracing::info!(
                                target: "job_bus_swarm",
                                after_failures = consecutive_failures,
                                "coordinator recovered"
                            );
                        }
                        consecutive_failures = 0;
                        delay = BASE_INTERVAL;
                    }
                    Err(e) => {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        if consecutive_failures == ESCALATE_AFTER {
                            tracing::error!(
                                target: "job_bus_swarm",
                                error = %e,
                                consecutive_failures,
                                "swarm coordinator is DOWN — orphan detection is not running; \
                                 jobs from a crashed worker will only be recovered by the 300-420s \
                                 stale-lock fallback, not sub-second"
                            );
                        } else if consecutive_failures < ESCALATE_AFTER {
                            tracing::warn!(
                                target: "job_bus_swarm", error = %e, consecutive_failures,
                                "coordinator tick failed"
                            );
                        } else if consecutive_failures % 300 == 0 {
                            // Still broken: one line every ~300 ticks so the condition stays
                            // visible without reproducing the 108k-lines/day firehose.
                            tracing::error!(
                                target: "job_bus_swarm", error = %e, consecutive_failures,
                                "swarm coordinator still down"
                            );
                        }
                        // Exponential backoff, capped. Ticks are cheap but a hard-failing one is
                        // pure cost.
                        delay = (delay * 2).min(MAX_INTERVAL);
                    }
                }
            }
        });
    }

    async fn tick(&self) -> Result<(), JobBusError> {
        let pool = self.bus.pool();
        // Cross-tenant scan: set the RLS GUC to '' (the policy's unrestricted branch) so the
        // coordinator sees every tenant's running jobs. On a NOBYPASSRLS pool the database default
        // GUC '0' would otherwise limit this to tenant 0, leaving all real jobs un-monitored.
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('app.current_tenant_id', '', true)")
            .execute(&mut *tx)
            .await?;
        let rows = sqlx::query(
            r#"SELECT id, tenant_id, COALESCE(worker_id, '') AS worker_id
               FROM weissman_async_jobs WHERE status = 'running'"#,
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let mut seen_workers: std::collections::HashSet<String> = std::collections::HashSet::new();
        for row in rows {
            // Handle each row independently: a failure on one job must not skip the rest of the pass
            // (head-of-line blocking would keep the same failing row wedging the tail every tick).
            let (job_id, tenant_id, worker_id): (Uuid, i64, String) =
                match (row.try_get("id"), row.try_get("tenant_id"), row.try_get("worker_id")) {
                    (Ok(a), Ok(b), Ok(c)) => (a, b, c),
                    _ => continue,
                };
            seen_workers.insert(worker_id.clone());
            if worker_id.is_empty() {
                continue;
            }
            let key = format!("{}{}", SWARM_REGISTRY_PREFIX, worker_id);
            let mut conn = self.redis.clone();
            // A Redis error is NOT evidence the worker is dead. `unwrap_or(false)` treated an outage
            // as "everyone is dead" and orphaned the entire in-flight fleet — skip the row instead.
            let alive: bool = match conn.exists(&key).await {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(target: "job_bus_swarm", worker_id = %worker_id, error = %e, "liveness check failed; skipping");
                    continue;
                }
            };
            if alive {
                self.missed.lock().await.remove(&worker_id);
                continue;
            }
            // Require several consecutive misses. One missed observation is not evidence of
            // death — see the `missed` field.
            let misses = {
                let mut m = self.missed.lock().await;
                let e = m.entry(worker_id.clone()).or_insert(0);
                *e = e.saturating_add(1);
                *e
            };
            if misses < Self::MISSES_BEFORE_ORPHAN {
                tracing::debug!(
                    target: "job_bus_swarm", worker_id = %worker_id, misses,
                    "worker liveness missing; waiting for confirmation before orphaning"
                );
                continue;
            }
            tracing::warn!(
                target: "job_bus_swarm",
                %job_id,
                worker_id = %worker_id,
                misses,
                "worker liveness expired across consecutive ticks — orphaning job"
            );
            // Append the orphan events FIRST; only force-release the lease once the job has actually
            // been re-queued, so a failed projection never leaves a job lease-less AND un-orphaned
            // (any worker could otherwise grab it while the re-queue never ran).
            if let Err(e) = self
                .bus
                .on_worker_terminated(tenant_id, &worker_id, "liveness_expired")
                .await
            {
                tracing::warn!(target: "job_bus_swarm", %job_id, error = %e, "worker_terminated append failed; retrying next tick");
                continue;
            }
            if let Err(e) = self
                .bus
                .on_job_orphaned(job_id, tenant_id, &worker_id, "swarm_liveness_expired")
                .await
            {
                tracing::warn!(target: "job_bus_swarm", %job_id, error = %e, "job_orphaned projection failed; retrying next tick");
                continue;
            }
            // Compare-and-delete against the worker we declared dead: never destroy a lease
            // that has since been re-acquired.
            let _ = DistributedLease::force_release_owned(&self.redis, job_id, &worker_id).await;
            self.publish_worker_down(&worker_id).await;
        }

        // Drop miss counters for workers that hold no `running` rows any more. Without this the
        // map keeps an entry for every worker id ever seen — including the dead ones whose jobs
        // this tick just orphaned, which by definition never appear again — and grows for the
        // life of the process.
        self.missed
            .lock()
            .await
            .retain(|w, _| seen_workers.contains(w));
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
