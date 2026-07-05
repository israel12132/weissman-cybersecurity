//! Consumes `weissman_async_jobs` with military-grade zero-trust orchestration when enabled:
//! cryptographic claims, distributed leases, event sourcing, forensic DLQ, swarm liveness.

use fingerprint_engine::async_job_executor::{execute_job, AsyncJobChannels};
use fingerprint_engine::job_orchestration::{extract_signed_envelope, strip_bus_metadata};
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use weissman_db::job_queue::{self, AsyncJob};
use weissman_job_bus::{ForensicBundle, JobBus, LeaseHandle, WorkerSwarm};

const POLL_IDLE_MS: u64 = 750;
const LOCK_SECS: i64 = 300;
const LEASE_EXTEND_INTERVAL_SECS: u64 = 15;
const BASE_BACKOFF_SECS: i64 = 5;

fn worker_id() -> String {
    let host = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-host".into());
    format!("{}:{}", host, std::process::id())
}

fn job_kind_timeout(kind: &str) -> Duration {
    match kind {
        "tenant_full_scan" | "onboarding_tenant_scan" => Duration::from_secs(60 * 60),
        "auto_heal" | "deep_fuzz" | "feedback_fuzz" | "ai_redteam" => Duration::from_secs(30 * 60),
        "command_center_engine" => Duration::from_secs(15 * 60),
        "scan_all_engines" | "scan_discovered_domains" => Duration::from_secs(45 * 60),
        "pipeline_scan" | "threat_intel_run" | "council_debate" => Duration::from_secs(20 * 60),
        "noop" | "ping" => Duration::from_secs(30),
        _ => Duration::from_secs(5 * 60),
    }
}

fn job_is_heavy(kind: &str) -> bool {
    matches!(
        kind,
        "tenant_full_scan"
            | "onboarding_tenant_scan"
            | "auto_heal"
            | "pipeline_scan"
            | "threat_intel_run"
            | "deep_fuzz"
            | "ai_redteam"
            | "timing_scan"
            | "llm_fuzz_run"
            | "cloud_scan_run"
            | "payload_sync"
            | "threat_ingest_run"
            | "deception_cloud_deploy"
            | "poe_synthesis_run"
            | "feedback_fuzz"
            | "sovereign_learning_feedback"
            | "genesis_eternal_fuzz"
            | "genesis_knowledge_match"
            | "command_center_engine"
            | "scan_all_engines"
            | "scan_discovered_domains"
    )
}

fn worker_concurrency_cap(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

async fn process_one(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    channels: AsyncJobChannels,
    bus: Arc<JobBus>,
    swarm: Option<Arc<WorkerSwarm>>,
    wid: String,
    job: AsyncJob,
) {
    let pool = app_pool.as_ref();
    let bus_on = bus.is_enabled();
    info!(
        target: "weissman_worker",
        job_id = %job.id,
        trace_id = ?job.trace_id,
        tenant_id = job.tenant_id,
        kind = %job.kind,
        attempt = job.attempt_count,
        zero_trust = bus_on,
        "processing job"
    );

    let envelope = extract_signed_envelope(&job.payload);
    let lease: Arc<Mutex<Option<LeaseHandle>>> = Arc::new(Mutex::new(None));

    if bus_on {
        match bus
            .on_worker_claimed(job.id, job.tenant_id, &wid, envelope.as_ref(), LOCK_SECS)
            .await
        {
            Ok(Some(handle)) => {
                *lease.lock().await = Some(handle);
            }
            Ok(None) => {}
            Err(e) => {
                error!(
                    target: "weissman_worker",
                    job_id = %job.id,
                    error = %e,
                    "zero-trust claim rejected"
                );
                let err_s = e.to_string();
                let permanent = err_s.contains("envelope expired")
                    || err_s.contains("signature mismatch")
                    || err_s.contains("missing signed envelope");
                if permanent {
                    let _ = job_queue::dead_letter_job(
                        pool,
                        job.id,
                        &format!("zero-trust claim rejected (permanent): {e}"),
                    )
                    .await;
                } else if job.attempt_count >= job.max_attempts {
                    let _ = job_queue::fail_job(
                        pool,
                        &job,
                        &format!("claim rejected: {e}"),
                        BASE_BACKOFF_SECS,
                    )
                    .await;
                } else {
                    let backoff =
                        (BASE_BACKOFF_SECS * (1_i64 << job.attempt_count.min(6).max(0))).min(120);
                    let _ = job_queue::release_reserved_job(
                        pool,
                        job.id,
                        &format!("claim rejected: {e}"),
                        backoff,
                    )
                    .await;
                }
                return;
            }
        }
        if let Some(ref s) = swarm {
            s.gossip_job_claimed(job.id).await;
        }
        if let Err(e) = bus
            .on_exploit_fired(job.id, job.tenant_id, &wid, &job.kind)
            .await
        {
            warn!(target: "weissman_worker", error = %e, "exploit_fired event failed");
        }
    }

    let lease_stop = Arc::new(AtomicBool::new(false));
    let lease_stop_bg = lease_stop.clone();
    let lease_bus = bus.clone();
    let lease_job_id = job.id;
    let lease_tid = job.tenant_id;
    let lease_arc = lease.clone();
    let hb_pool = app_pool.clone();
    let lease_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(LEASE_EXTEND_INTERVAL_SECS));
        while !lease_stop_bg.load(Ordering::SeqCst) {
            interval.tick().await;
            if lease_stop_bg.load(Ordering::SeqCst) {
                break;
            }
            if bus_on {
                let guard = lease_arc.lock().await;
                if let Some(ref handle) = *guard {
                    if let Err(e) = lease_bus
                        .on_lease_extended(lease_job_id, lease_tid, handle, LOCK_SECS)
                        .await
                    {
                        warn!(target: "weissman_worker", error = %e, "lease extend failed");
                    }
                }
            } else if let Err(e) =
                job_queue::heartbeat(hb_pool.as_ref(), lease_job_id, LOCK_SECS).await
            {
                warn!(target: "weissman_worker", job_id = %lease_job_id, error = %e, "heartbeat failed");
            }
        }
    });

    let exec_app = app_pool.clone();
    let exec_intel = intel_pool.clone();
    let exec_auth = auth_pool.clone();
    let exec_channels = channels.clone();
    let exec_job = job.clone();
    let job_kind_for_timeout = exec_job.kind.clone();
    let exec_heavy = job_is_heavy(job_kind_for_timeout.as_str());
    let exec_handle = tokio::spawn(async move {
        let fut = async move {
            match exec_job.kind.as_str() {
                "noop" | "ping" => Ok(serde_json::json!({"ok": true, "message": "noop"})),
                _ => execute_job(exec_app, exec_intel, exec_auth, &exec_channels, exec_job).await,
            }
        };
        if exec_heavy {
            fingerprint_engine::engine_stack_runtime::run_on_large_stack(|| fut).await
        } else {
            fut.await
        }
    });

    let timeout = job_kind_timeout(&job_kind_for_timeout);
    let exec_abort = exec_handle.abort_handle();
    let outcome: Result<serde_json::Value, String> =
        match tokio::time::timeout(timeout, exec_handle).await {
            Ok(Ok(inner)) => inner,
            Ok(Err(join_err)) => Err(if join_err.is_cancelled() {
                "job task cancelled".to_string()
            } else if join_err.is_panic() {
                format!("job task panicked: {join_err}")
            } else {
                format!("job task join error: {join_err}")
            }),
            Err(_) => {
                exec_abort.abort();
                Err(format!(
                    "job timed out after {}s ({})",
                    timeout.as_secs(),
                    job_kind_for_timeout
                ))
            }
        };

    lease_stop.store(true, Ordering::SeqCst);
    let _ = lease_task.await;

    let mut lease_out = lease.lock().await.take();

    match outcome {
        Ok(v) => {
            if bus_on {
                if let Err(e) = bus
                    .on_job_completed(job.id, job.tenant_id, &wid, &v, lease_out.take())
                    .await
                {
                    error!(target: "weissman_worker", job_id = %job.id, error = %e, "event-sourced complete failed");
                }
            } else if let Err(e) = job_queue::complete_job_with_result(pool, job.id, &v).await {
                error!(target: "weissman_worker", job_id = %job.id, error = %e, "complete failed");
                let _ = job_queue::fail_job(pool, &job, &e.to_string(), BASE_BACKOFF_SECS).await;
            }
        }
        Err(msg) => {
            let exhausted = job.attempt_count >= job.max_attempts;
            if bus_on && exhausted {
                let signing_key = std::env::var("WEISSMAN_JOB_ORCHESTRATOR_SECRET")
                    .ok()
                    .or_else(|| std::env::var("WEISSMAN_JWT_SECRET").ok());
                let key = signing_key.as_deref().map(|s| s.as_bytes());
                match ForensicBundle::build(
                    pool,
                    job.id,
                    job.tenant_id,
                    &wid,
                    if msg.contains("panic") {
                        "worker_panic"
                    } else if msg.contains("timed out") {
                        "execution_timeout"
                    } else {
                        "execution_failure"
                    },
                    &msg,
                    envelope,
                    strip_bus_metadata(&job.payload),
                    key,
                )
                .await
                {
                    Ok(bundle) => {
                        if let Err(e) = bus.on_forensic_dlq(bundle, lease_out.take()).await {
                            error!(target: "weissman_worker", job_id = %job.id, error = %e, "forensic DLQ failed");
                        }
                    }
                    Err(e) => {
                        error!(target: "weissman_worker", job_id = %job.id, error = %e, "forensic bundle build failed");
                    }
                }
            } else if bus_on {
                if let Err(e) = bus
                    .on_job_failed(
                        job.id,
                        job.tenant_id,
                        &wid,
                        &msg,
                        !exhausted,
                        lease_out.take(),
                    )
                    .await
                {
                    error!(target: "weissman_worker", job_id = %job.id, error = %e, "event-sourced fail");
                }
            } else if let Err(e) = job_queue::fail_job(pool, &job, &msg, BASE_BACKOFF_SECS).await {
                error!(target: "weissman_worker", job_id = %job.id, error = %e, "fail_job failed");
                let _ =
                    job_queue::force_requeue_running(pool, job.id, &format!("fail_job: {e}")).await;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    weissman_db::env_bootstrap::load_process_environment();
    fingerprint_engine::observability::init_tracing_from_env();
    fingerprint_engine::observability::init_prometheus_recorder();

    if let Err(msg) = weissman_core::tls_policy::enforce_production_tls_policy() {
        eprintln!("[startup] worker TLS policy refusal: {msg}");
        std::process::exit(2);
    }
    if let Err(msg) =
        fingerprint_engine::security_startup::enforce_worker_production_security_policy()
    {
        eprintln!("[startup] worker security policy refusal: {msg}");
        std::process::exit(2);
    }
    if let Err(msg) = fingerprint_engine::http::rate_limit_redis::verify_redis_at_startup().await {
        eprintln!("[startup] worker Redis distributed state refusal: {msg}");
        std::process::exit(2);
    }

    let database_url = match std::env::var("DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            eprintln!("weissman-worker: DATABASE_URL is required");
            std::process::exit(1);
        }
    };
    if let Err(msg) = weissman_db::env_bootstrap::validate_database_url(&database_url) {
        eprintln!("weissman-worker: {}", msg);
        std::process::exit(1);
    }

    let app_pool = match weissman_db::connect_app(database_url.trim()).await {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!("weissman-worker: database connect failed: {}", e);
            std::process::exit(1);
        }
    };
    fingerprint_engine::observability::register_llm_tenant_metering(app_pool.clone());

    let auth_url =
        std::env::var("WEISSMAN_AUTH_DATABASE_URL").unwrap_or_else(|_| database_url.clone());
    if let Err(msg) = weissman_db::env_bootstrap::validate_database_url(auth_url.trim()) {
        eprintln!("weissman-worker: WEISSMAN_AUTH_DATABASE_URL: {}", msg);
        std::process::exit(1);
    }
    let auth_pool = match weissman_db::connect_auth(auth_url.trim()).await {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!("weissman-worker: auth database connect failed: {}", e);
            std::process::exit(1);
        }
    };

    let intel_pool = match weissman_db::connect_intel_from_env().await {
        Ok(p) => Arc::new(p),
        Err(e) => {
            warn!(
                target: "weissman_worker",
                error = %e,
                "intel pool failed; using app pool"
            );
            app_pool.clone()
        }
    };

    if let Err(e) =
        weissman_db::job_queue::recover_stale_running_on_stack_boot(app_pool.as_ref()).await
    {
        warn!(target: "weissman_worker", error = %e, "stack recovery failed");
    } else {
        info!(target: "weissman_worker", "stack recovery complete");
    }

    let light_n = worker_concurrency_cap("WEISSMAN_WORKER_LIGHT_CONCURRENCY", 8);
    let heavy_n = worker_concurrency_cap("WEISSMAN_WORKER_HEAVY_CONCURRENCY", 2);
    let light_sem = Arc::new(tokio::sync::Semaphore::new(light_n));
    let heavy_sem = Arc::new(tokio::sync::Semaphore::new(heavy_n));

    let channels = AsyncJobChannels::from_env();
    let wid = worker_id();
    let bus = Arc::new(JobBus::from_env((*app_pool).clone()).await);

    let swarm: Option<Arc<WorkerSwarm>> = if bus.is_enabled() {
        let redis = bus.redis().cloned().expect("bus enabled implies redis");
        let s = Arc::new(WorkerSwarm::new(redis, wid.clone()));
        s.clone().spawn_liveness_loop();
        info!(target: "weissman_worker", "zero-trust job bus + swarm liveness active");
        Some(s)
    } else {
        warn!(
            target: "weissman_worker",
            "legacy claim mode (set REDIS_URL + WEISSMAN_JOB_ORCHESTRATOR_SECRET for zero-trust)"
        );
        None
    };

    let fleet = Arc::new(weissman_fleet_shaping::FleetCoordinator::from_env(wid.clone()).await);
    fingerprint_engine::fleet_shaping::install_global(fleet);
    info!(
        target: "weissman_worker",
        redis_shaping = fingerprint_engine::fleet_shaping::global()
            .is_some_and(|c| c.is_redis_enabled()),
        "fleet traffic shaping installed"
    );

    info!(
        target: "weissman_worker",
        worker_id = %wid,
        light_concurrency = light_n,
        heavy_concurrency = heavy_n,
        zero_trust = bus.is_enabled(),
        "started"
    );

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let swarm_shutdown = swarm.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        stop_clone.store(true, Ordering::SeqCst);
        if let Some(s) = swarm_shutdown {
            s.stop();
        }
    });

    // Reclaim jobs left `running` after worker crash / network partition (self-healing queue).
    let reclaim_pool = app_pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(120));
        loop {
            interval.tick().await;
            match job_queue::reclaim_stale_running_locks(reclaim_pool.as_ref()).await {
                Ok(n) if n > 0 => {
                    info!(
                        target: "weissman_worker",
                        reclaimed = n,
                        "stale running locks reclaimed to pending"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(target: "weissman_worker", error = %e, "stale lock reclaim failed");
                }
            }
        }
    });

    while !stop.load(Ordering::SeqCst) {
        let claim_result = if bus.is_enabled() {
            job_queue::reserve_next(app_pool.as_ref(), &wid, LOCK_SECS).await
        } else {
            job_queue::claim_next(app_pool.as_ref(), &wid, LOCK_SECS).await
        };

        match claim_result {
            Ok(Some(job)) => {
                let is_heavy = job_is_heavy(job.kind.as_str());
                let sem = if is_heavy {
                    heavy_sem.clone()
                } else {
                    light_sem.clone()
                };
                let permit = match sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let app_pool = app_pool.clone();
                let intel_pool = intel_pool.clone();
                let auth_pool = auth_pool.clone();
                let channels = channels.clone();
                let bus = bus.clone();
                let swarm = swarm.clone();
                let wid = wid.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    process_one(
                        app_pool, intel_pool, auth_pool, channels, bus, swarm, wid, job,
                    )
                    .await;
                });
            }
            Ok(None) => tokio::time::sleep(Duration::from_millis(POLL_IDLE_MS)).await,
            Err(e) => {
                error!(target: "weissman_worker", error = %e, "claim/reserve failed");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    info!(target: "weissman_worker", "shutdown");
}
