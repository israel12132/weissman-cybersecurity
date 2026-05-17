//! Consumes `weissman_async_jobs`: claim with `SKIP LOCKED`, heartbeat, complete or retry / dead-letter.
//!
//! Concurrency: separate semaphores for heavy vs light job kinds so Docker / full-tenant scans cannot
//! starve quick jobs.
//!
//! Note: `edge_swarm_nodes` heartbeats from regional WASM workers are **not** written here; the HTTP
//! API batches them every 30s (`edge_heartbeat_batch`) so this worker's job heartbeats stay separate
//! from edge registry traffic.

use fingerprint_engine::async_job_executor::{execute_job, AsyncJobChannels};
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use weissman_db::job_queue::{self, AsyncJob};

const POLL_IDLE_MS: u64 = 750;
const LOCK_SECS: i64 = 300;
const HEARTBEAT_INTERVAL_SECS: u64 = 30;
const BASE_BACKOFF_SECS: i64 = 5;

fn worker_id() -> String {
    let host = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-host".into());
    format!("{}:{}", host, std::process::id())
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
    job: AsyncJob,
) {
    let pool = app_pool.as_ref();
    info!(
        target: "weissman_worker",
        job_id = %job.id,
        trace_id = ?job.trace_id,
        tenant_id = job.tenant_id,
        kind = %job.kind,
        attempt = job.attempt_count,
        "processing job"
    );

    let hb_stop = Arc::new(AtomicBool::new(false));
    let hb_stop_bg = hb_stop.clone();
    let pool_clone = app_pool.clone();
    let jid = job.id;
    let hb_task = tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
        while !hb_stop_bg.load(Ordering::SeqCst) {
            interval.tick().await;
            if hb_stop_bg.load(Ordering::SeqCst) {
                break;
            }
            if let Err(e) = job_queue::heartbeat(pool_clone.as_ref(), jid).await {
                warn!(target: "weissman_worker", job_id = %jid, error = %e, "heartbeat failed");
            }
        }
    });

    // Isolate `execute_job` on its own JoinHandle so a panic cannot skip terminal SQL updates
    // (would otherwise leave the row stuck in `running` until lock expiry).
    let exec_app = app_pool.clone();
    let exec_intel = intel_pool.clone();
    let exec_auth = auth_pool.clone();
    let exec_channels = channels.clone();
    let exec_job = job.clone();
    let exec_handle = tokio::spawn(async move {
        match exec_job.kind.as_str() {
            "noop" | "ping" => Ok(serde_json::json!({"ok": true, "message": "noop"})),
            _ => {
                execute_job(
                    exec_app,
                    exec_intel,
                    exec_auth,
                    &exec_channels,
                    exec_job,
                )
                .await
            }
        }
    });

    let outcome: Result<serde_json::Value, String> = match exec_handle.await {
        Ok(inner) => inner,
        Err(join_err) => Err(if join_err.is_cancelled() {
            "job task cancelled".to_string()
        } else if join_err.is_panic() {
            "job task panicked".to_string()
        } else {
            format!("job task join error: {join_err}")
        }),
    };

    hb_stop.store(true, Ordering::SeqCst);
    let _ = hb_task.await;

    match outcome {
        Ok(v) => {
            if let Err(e) = job_queue::complete_job_with_result(pool, job.id, &v).await {
                error!(target: "weissman_worker", job_id = %job.id, error = %e, "complete_job_with_result failed");
                let detail = format!("complete_job_with_result failed: {e}");
                if let Err(e2) = job_queue::fail_job(pool, &job, &detail, BASE_BACKOFF_SECS).await {
                    error!(target: "weissman_worker", job_id = %job.id, error = %e2, "fail_job after complete failure");
                    let note = format!("complete+fail_job failed: {e2}");
                    match job_queue::force_requeue_running(pool, job.id, &note).await {
                        Ok(n) if n > 0 => {
                            warn!(target: "weissman_worker", job_id = %job.id, "force_requeue_running after persist errors");
                        }
                        Ok(_) => {}
                        Err(e3) => {
                            error!(target: "weissman_worker", job_id = %job.id, error = %e3, "force_requeue_running failed");
                        }
                    }
                }
            }
        }
        Err(msg) => {
            if let Err(e) = job_queue::fail_job(pool, &job, &msg, BASE_BACKOFF_SECS).await {
                error!(target: "weissman_worker", job_id = %job.id, error = %e, "fail_job failed");
                let note = format!("fail_job failed: {e}; original: {}", msg.chars().take(500).collect::<String>());
                let _ = job_queue::force_requeue_running(pool, job.id, &note).await;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    weissman_db::env_bootstrap::load_process_environment();
    fingerprint_engine::observability::init_tracing_from_env();
    fingerprint_engine::observability::init_prometheus_recorder();

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

    let auth_url = std::env::var("WEISSMAN_AUTH_DATABASE_URL")
        .unwrap_or_else(|_| database_url.clone());
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
                "intel pool failed; using app pool (set WEISSMAN_INTEL_DATABASE_URL)"
            );
            app_pool.clone()
        }
    };

    let light_n = worker_concurrency_cap("WEISSMAN_WORKER_LIGHT_CONCURRENCY", 8);
    let heavy_n = worker_concurrency_cap("WEISSMAN_WORKER_HEAVY_CONCURRENCY", 2);
    let light_sem = Arc::new(Semaphore::new(light_n));
    let heavy_sem = Arc::new(Semaphore::new(heavy_n));

    let channels = AsyncJobChannels::noop();
    let wid = worker_id();
    info!(
        target: "weissman_worker",
        worker_id = %wid,
        light_concurrency = light_n,
        heavy_concurrency = heavy_n,
        "started"
    );

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        stop_clone.store(true, Ordering::SeqCst);
    });

    while !stop.load(Ordering::SeqCst) {
        match job_queue::claim_next(app_pool.as_ref(), &wid, LOCK_SECS).await {
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
                tokio::spawn(async move {
                    let _permit = permit;
                    process_one(app_pool, intel_pool, auth_pool, channels, job).await;
                });
            }
            Ok(None) => tokio::time::sleep(Duration::from_millis(POLL_IDLE_MS)).await,
            Err(e) => {
                error!(target: "weissman_worker", error = %e, "claim_next failed");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    info!(target: "weissman_worker", "shutdown");
}
