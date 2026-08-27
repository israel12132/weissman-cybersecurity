//! Consumes `weissman_async_jobs` with military-grade zero-trust orchestration when enabled:
//! cryptographic claims, distributed leases, event sourcing, forensic DLQ, swarm liveness.

use fingerprint_engine::async_job_executor::{execute_job, AsyncJobChannels};
use fingerprint_engine::job_orchestration::{extract_signed_envelope, strip_bus_metadata};
use fingerprint_engine::{job_progress, scan_chunking};
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use weissman_db::job_queue::{self, AsyncJob};
use weissman_job_bus::keepalive::{
    evaluate_keepalive, stuck_error_message, stuck_reason_from_error, KeepAliveDecision,
};
use weissman_job_bus::{ForensicBundle, JobBus, LeaseHandle, WorkerSwarm};

const POLL_IDLE_MS: u64 = 750;
const LOCK_SECS: i64 = 300;
const BASE_BACKOFF_SECS: i64 = 5;

/// Path the worker touches after every dequeue round-trip that reached the database.
///
/// Overridable so the same binary works outside a container, where `/tmp` may be shared or
/// read-only.
fn liveness_beat_path() -> std::path::PathBuf {
    std::env::var_os("WEISSMAN_WORKER_LIVENESS_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/weissman-worker-alive"))
}

/// Force an exhausted job out of `running` when the forensic path could not do it.
///
/// The `bus_on && exhausted` arm is the ONLY route that terminalizes an exhausted job in
/// zero-trust mode, and both of its error branches used to change no state — they logged and
/// returned. The row stayed `running` with a frozen `locked_until`, so the stale-lock reclaim
/// flipped it back to `pending` minutes later, the worker re-claimed it, re-ran the poison
/// payload, exhausted again, and failed to build the bundle again. Forever, holding a heavy
/// semaphore slot the whole time.
///
/// `ForensicBundle::build` does DB work, so it fails exactly when the database is degraded —
/// which is precisely when a job is most likely to be exhausting its attempts. Losing forensics
/// is acceptable; losing the terminal transition is not, because that is what makes the loop
/// unbounded. The forensic failure is recorded alongside the original cause so the gap is visible.
async fn terminalize_exhausted(
    pool: &PgPool,
    job_id: sqlx::types::Uuid,
    cause: &str,
    forensic_err: &str,
) {
    let note = format!("{cause} [forensics unavailable: {forensic_err}]");
    if let Err(e) = job_queue::dead_letter_job(pool, job_id, &note).await {
        error!(
            target: "weissman_worker", %job_id, error = %e,
            "could not dead-letter an exhausted job after forensic failure — it will be reclaimed \
             and re-executed until this write succeeds"
        );
    } else {
        warn!(
            target: "weissman_worker", %job_id,
            "dead-lettered an exhausted job without a forensic bundle"
        );
    }
}

/// Record that the dequeue path is functioning.
///
/// Deliberately called only on `Ok` — including `Ok(None)`, an empty queue, which is a healthy
/// steady state. A failing claim leaves the file to go stale, which is the whole point: the
/// previous container healthcheck (`cat /proc/1/comm | grep -q weissman-worker`) could not tell a
/// working worker from one that was up and failing every single claim, and reported healthy
/// throughout the four-day 2026-08-06 outage.
///
/// Best-effort: a failure to write must never take down the worker, so this only logs. A
/// persistently unwritable path shows up as a failing healthcheck, which is the correct signal.
fn touch_liveness_beat() {
    let path = liveness_beat_path();
    if let Err(e) = std::fs::write(&path, b"ok") {
        warn!(
            target: "weissman_worker",
            path = %path.display(), error = %e,
            "could not write liveness beat file"
        );
    }
}

fn worker_id() -> String {
    let host = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-host".into());
    format!("{}:{}", host, std::process::id())
}

/// One table: a job kind's execution class and its time budget, together.
///
/// These used to be two independent `match` blocks — `job_kind_timeout` enumerated 12 kinds while
/// `job_is_heavy` listed 22 — so a kind could be classified heavy and still fall through to the
/// 5-minute default budget. Ten did: timing_scan, llm_fuzz_run, cloud_scan_run, payload_sync,
/// threat_ingest_run, deception_cloud_deploy, poe_synthesis_run, sovereign_learning_feedback,
/// genesis_eternal_fuzz and genesis_knowledge_match. The inconsistency is self-evident in the
/// executor: `council_debate` gets 1200s standalone, while `genesis_eternal_fuzz` — which runs a
/// full DFS fuzz cycle AND that same council war room — got 300s. Every attempt timed out at the
/// same point, was requeued with backoff, timed out again, and was eventually dead-lettered: a
/// permanently unrunnable job kind that burned one of only two heavy slots for 5 minutes per
/// doomed attempt.
///
/// A single table makes that drift impossible to express, and the test below asserts that every
/// heavy kind carries an explicit budget.
struct JobClass {
    /// Must run on the large engine stack (deep monolithic engine dispatch).
    heavy: bool,
    /// Wall-clock ceiling for the whole job, not per engine.
    timeout_secs: u64,
}

fn job_class(kind: &str) -> JobClass {
    let (heavy, timeout_secs) = match kind {
        // Coordinator only: fans out `tenant_scan_chunk` micro-batches and returns.
        // Must NOT occupy a heavy slot for an hour — that is the Queue Starvation Self-DoS.
        "tenant_full_scan" | "onboarding_tenant_scan" => (false, 5 * 60),
        // One client × small engine batch. Own lease, 10s heartbeat, 60s progress abort.
        "tenant_scan_chunk" => (true, 20 * 60),
        // ── Full-estate scans (legacy non-chunked kinds) ─────────────────────
        // Fans out to ~22 top-tier engines sequentially (each with its own 180s ceiling), so the
        // worst case is ~22x180 = 3960s. The previous 3600s budget was BELOW that, so when several
        // engines hang — exactly what a health probe exists to detect — the probe was killed with
        // a generic timeout instead of returning its per-engine pass/fail table.
        "top_tier_health_probe" => (true, 75 * 60),
        "scan_all_engines" | "scan_discovered_domains" => (true, 45 * 60),
        // ── Long-running engine work ─────────────────────────────────────────
        "auto_heal" | "deep_fuzz" | "feedback_fuzz" | "ai_redteam" => (true, 30 * 60),
        "pipeline_scan" | "threat_intel_run" => (true, 20 * 60),
        "command_center_engine" => (true, 15 * 60),
        // Was silently on the 300s default despite running a full DFS fuzz cycle followed by the
        // multi-agent council war room, which alone is budgeted 1200s.
        "genesis_eternal_fuzz" => (true, 40 * 60),
        "genesis_knowledge_match" | "poe_synthesis_run" | "sovereign_learning_feedback" => {
            (true, 20 * 60)
        }
        // Issues up to `baseline_sample_size` (500) timing samples plus payload probes.
        "timing_scan" | "llm_fuzz_run" => (true, 20 * 60),
        "cloud_scan_run" => (true, 30 * 60),
        "threat_ingest_run" | "payload_sync" | "deception_cloud_deploy" => (true, 15 * 60),
        // ── Light / control-plane ────────────────────────────────────────────
        // Not heavy (no deep engine dispatch) but genuinely slow, so it keeps its own budget.
        "council_debate" => (false, 20 * 60),
        "noop" | "ping" => (false, 30),
        _ => (false, 5 * 60),
    };
    JobClass {
        heavy,
        timeout_secs,
    }
}

fn job_kind_timeout(kind: &str) -> Duration {
    Duration::from_secs(job_class(kind).timeout_secs)
}

fn job_is_heavy(kind: &str) -> bool {
    job_class(kind).heavy
}

/// Every kind the table classifies heavy.
///
/// Also used at runtime to keep the queue moving when the heavy pool is saturated: the loop asks
/// the database to skip these kinds so light work can still be claimed. The guard test below
/// asserts this list and `job_class` cannot drift apart, which is what keeps the SQL filter and
/// the Rust classification the same thing rather than two lists that agree by luck.
const HEAVY_KINDS: &[&str] = &[
    "tenant_scan_chunk",
    "top_tier_health_probe",
    "scan_all_engines",
    "scan_discovered_domains",
    "auto_heal",
    "deep_fuzz",
    "feedback_fuzz",
    "ai_redteam",
    "pipeline_scan",
    "threat_intel_run",
    "command_center_engine",
    "genesis_eternal_fuzz",
    "genesis_knowledge_match",
    "poe_synthesis_run",
    "sovereign_learning_feedback",
    "timing_scan",
    "llm_fuzz_run",
    "cloud_scan_run",
    "threat_ingest_run",
    "payload_sync",
    "deception_cloud_deploy",
];

fn worker_concurrency_cap(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

// Distinct pools/handles the executor legitimately needs; splitting into a struct would only
// shuffle the same fields. app_pool = engine execution, ctrl_pool = job-state control plane.
#[allow(clippy::too_many_arguments)]
async fn process_one(
    app_pool: Arc<PgPool>,
    ctrl_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    channels: AsyncJobChannels,
    bus: Arc<JobBus>,
    swarm: Option<Arc<WorkerSwarm>>,
    wid: String,
    job: AsyncJob,
) {
    // Job-state writes (fail/complete/dead-letter/forensic) go through the control-plane pool so a
    // running scan holding every `app_pool` slot can never starve them. Engine execution below
    // still uses `app_pool`.
    let pool = ctrl_pool.as_ref();
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
                // These three used to be classified `permanent` and dead-lettered on the FIRST
                // occurrence. They are not properties of the job — they are properties of the
                // infrastructure around it:
                //
                //   missing signed envelope -> the enqueue-side attach failed (a bug or outage)
                //   envelope expired        -> the job sat in the queue too long (an outage)
                //   signature mismatch      -> the signing key differs or was rotated
                //
                // None means "this job can never succeed", and all three are fixed by operator
                // action, not by discarding customer work. Treating them as permanent destroyed
                // 3,319 tenant scans in this deployment — 3,266 of them to a single key
                // mismatch, irreversibly, with no retry and nothing alerting.
                //
                // They now fall through to the normal retry ladder: bounded by max_attempts,
                // backed off, and terminal only after the job has genuinely been given its
                // retries. A poison payload still dies — it just has to earn it.
                // The worker exposes no /metrics endpoint and has no scrape job, so a counter
                // here would be unscrapeable. Visibility comes from the backend instead, which
                // derives weissman_async_jobs_zero_trust_rejected from `last_error` on each
                // metrics tick — see fingerprint_engine/src/observability.rs.
                if err_s.contains("envelope expired")
                    || err_s.contains("signature mismatch")
                    || err_s.contains("missing signed envelope")
                {
                    error!(
                        target: "weissman_worker",
                        job_id = %job.id, attempt = job.attempt_count, max = job.max_attempts,
                        "zero-trust infrastructure rejection — retrying rather than dead-lettering; \
                         check the job-bus signing key and the enqueue-side envelope attach"
                    );
                }
                if job.attempt_count >= job.max_attempts {
                    let _ = job_queue::fail_job(
                        pool,
                        &job,
                        &wid,
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
                        &wid,
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

    let progress = job_progress::JobProgress::new();
    let lease_stop = Arc::new(AtomicBool::new(false));
    let lease_stop_bg = lease_stop.clone();
    // Wake the lease loop the instant the job finishes instead of only on the next interval tick —
    // otherwise the join below blocks up to the heartbeat interval while still holding the
    // concurrency permit and leaving the finished job looking `running`.
    let lease_notify = Arc::new(tokio::sync::Notify::new());
    let lease_notify_bg = lease_notify.clone();
    let lease_bus = bus.clone();
    let lease_job_id = job.id;
    let lease_tid = job.tenant_id;
    let lease_arc = lease.clone();
    let hb_pool = ctrl_pool.clone();
    let progress_bg = progress.clone();
    let (abort_tx, abort_rx) = tokio::sync::oneshot::channel();
    let abort_tx = Arc::new(Mutex::new(Some(abort_tx)));
    let abort_tx_bg = abort_tx.clone();
    let stall_secs = weissman_job_bus::keepalive::progress_stall().as_secs();
    let hb_interval = weissman_job_bus::keepalive::heartbeat_interval();
    let lease_task = tokio::spawn(async move {
        let mut last_flushed_ms = 0u64;
        let mut interval = tokio::time::interval(hb_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await; // consume the immediate first tick
        while !lease_stop_bg.load(Ordering::SeqCst) {
            tokio::select! {
                _ = interval.tick() => {}
                _ = lease_notify_bg.notified() => break,
            }
            if lease_stop_bg.load(Ordering::SeqCst) {
                break;
            }
            let extend_ok = if bus_on {
                let guard = lease_arc.lock().await;
                if let Some(ref handle) = *guard {
                    match lease_bus
                        .on_lease_extended(lease_job_id, lease_tid, handle, LOCK_SECS)
                        .await
                    {
                        Ok(()) => true,
                        Err(e) => {
                            warn!(
                                target: "weissman_worker",
                                job_id = %lease_job_id,
                                error = %e,
                                "lease extend failed"
                            );
                            false
                        }
                    }
                } else {
                    // Bus on but no handle: still heart-beat Postgres so reclaim cannot steal us.
                    job_queue::heartbeat(hb_pool.as_ref(), lease_job_id, LOCK_SECS)
                        .await
                        .is_ok()
                }
            } else {
                match job_queue::heartbeat(hb_pool.as_ref(), lease_job_id, LOCK_SECS).await {
                    Ok(()) => true,
                    Err(e) => {
                        warn!(
                            target: "weissman_worker",
                            job_id = %lease_job_id,
                            error = %e,
                            "heartbeat failed"
                        );
                        false
                    }
                }
            };
            let mark_ms = progress_bg.last_mark_ms();
            if mark_ms != last_flushed_ms {
                last_flushed_ms = mark_ms;
                let _ = job_queue::record_progress(
                    hb_pool.as_ref(),
                    lease_job_id,
                    &progress_bg.last_note(),
                )
                .await;
            }
            match evaluate_keepalive(extend_ok, progress_bg.age_secs(), stall_secs) {
                KeepAliveDecision::Extend => {}
                KeepAliveDecision::Abort { stuck_reason } => {
                    error!(
                        target: "weissman_worker",
                        job_id = %lease_job_id,
                        stuck_reason = %stuck_reason,
                        last_progress = %progress_bg.last_note(),
                        "Force Abort — returning lease"
                    );
                    if let Some(tx) = abort_tx_bg.lock().await.take() {
                        let _ = tx.send(stuck_reason);
                    }
                    break;
                }
            }
        }
    });

    let exec_app = app_pool.clone();
    let exec_intel = intel_pool.clone();
    let exec_auth = auth_pool.clone();
    let exec_channels = channels.clone();
    let exec_job = job.clone();
    let exec_wid = wid.clone();
    let exec_progress = progress.clone();
    let job_kind_for_timeout = exec_job.kind.clone();
    let exec_heavy = job_is_heavy(job_kind_for_timeout.as_str());
    // Cancellation channel for the heavy path. A heavy job runs on a raw OS thread via
    // run_on_large_stack, and `abort()` on the awaiting tokio task does NOT stop that thread —
    // it just drops the receiver. On timeout the worker gave up waiting and requeued the job
    // while the original engine kept running, holding its DB connections and sockets, so a second
    // worker started the same scan against a copy that was still executing and could not be
    // stopped. Signalling the thread lets the future be dropped at its next await, which also
    // runs its destructors and releases those connections.
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
    let cancel_tx = std::sync::Mutex::new(Some(cancel_tx));
    let exec_handle = tokio::spawn(async move {
        let fut = async move {
            job_progress::scope(exec_progress, async move {
                match exec_job.kind.as_str() {
                    "noop" | "ping" => Ok(serde_json::json!({"ok": true, "message": "noop"})),
                    _ => {
                        execute_job(
                            exec_app,
                            exec_intel,
                            exec_auth,
                            &exec_channels,
                            exec_job,
                            &exec_wid,
                        )
                        .await
                    }
                }
            })
            .await
        };
        if exec_heavy {
            match fingerprint_engine::engine_stack_runtime::run_on_large_stack_cancellable(
                || fut,
                cancel_rx,
            )
            .await
            {
                Some(v) => v,
                None => Err("job cancelled after timeout".to_string()),
            }
        } else {
            fut.await
        }
    });

    let timeout = job_kind_timeout(&job_kind_for_timeout);
    let exec_abort = exec_handle.abort_handle();
    let outcome: Result<serde_json::Value, String> = tokio::select! {
        exec = exec_handle => match exec {
            Ok(inner) => inner,
            Err(join_err) => Err(if join_err.is_cancelled() {
                "job task cancelled".to_string()
            } else if join_err.is_panic() {
                format!("job task panicked: {join_err}")
            } else {
                format!("job task join error: {join_err}")
            }),
        },
        reason = abort_rx => {
            if let Ok(mut g) = cancel_tx.lock() {
                if let Some(tx) = g.take() {
                    let _ = tx.send(());
                }
            }
            exec_abort.abort();
            let reason = reason.unwrap_or(weissman_job_bus::StuckReason::NoProgress60s);
            Err(stuck_error_message(
                reason,
                &format!("last progress: {}", progress.last_note()),
            ))
        }
        _ = tokio::time::sleep(timeout) => {
            if let Ok(mut g) = cancel_tx.lock() {
                if let Some(tx) = g.take() {
                    let _ = tx.send(());
                }
            }
            exec_abort.abort();
            Err(format!(
                "job timed out after {}s ({})",
                timeout.as_secs(),
                job_kind_for_timeout
            ))
        }
    };

    lease_stop.store(true, Ordering::SeqCst);
    lease_notify.notify_one();
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
            } else {
                match job_queue::complete_job_with_result_owned(pool, job.id, &wid, &v).await {
                    Ok(true) => {}
                    // Lost the race: our lease lapsed, the row was reclaimed, and another worker
                    // owns it now. Writing our result anyway would orphan that worker's in-flight
                    // run and attribute our findings to a job the read model already closed.
                    Ok(false) => warn!(
                        target: "weissman_worker", job_id = %job.id,
                        "completion discarded — this worker no longer owns the job (lease lost \
                         and the row was reclaimed); the current owner will report the outcome"
                    ),
                    Err(e) => {
                        error!(target: "weissman_worker", job_id = %job.id, error = %e, "complete failed");
                        let _ = job_queue::fail_job(
                            pool,
                            &job,
                            &wid,
                            &e.to_string(),
                            BASE_BACKOFF_SECS,
                        )
                        .await;
                    }
                }
            }
        }
        Err(msg) => {
            if let Some(reason) = stuck_reason_from_error(&msg) {
                // Force Abort: return the lease, mark failed (not retry-pending), resume
                // remaining chunk engines so one hung probe cannot Self-DoS the fleet.
                let checkpoint = job_queue::get_job_for_tenant(pool, job.tenant_id, job.id)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|v| v.result);
                if let Err(e) =
                    job_queue::fail_job_stuck(pool, &job, &wid, reason.as_str(), &msg).await
                {
                    error!(
                        target: "weissman_worker",
                        job_id = %job.id,
                        error = %e,
                        "fail_job_stuck failed"
                    );
                }
                if bus_on {
                    if let Err(e) = bus
                        .on_job_failed(job.id, job.tenant_id, &wid, &msg, false, lease_out.take())
                        .await
                    {
                        error!(
                            target: "weissman_worker",
                            job_id = %job.id,
                            error = %e,
                            "event-sourced force-abort failed"
                        );
                    }
                } else if let Some(h) = lease_out.take() {
                    let _ = h.release().await;
                }
                if job.kind == scan_chunking::CHUNK_KIND {
                    match scan_chunking::enqueue_resume_after_abort(
                        app_pool.as_ref(),
                        &job,
                        checkpoint.as_ref(),
                    )
                    .await
                    {
                        Ok(Some(nid)) => info!(
                            target: "weissman_worker",
                            aborted = %job.id,
                            resume = %nid,
                            "successor chunk enqueued after Force Abort"
                        ),
                        Ok(None) => {}
                        Err(e) => error!(
                            target: "weissman_worker",
                            job_id = %job.id,
                            error = %e,
                            "could not enqueue successor chunk after Force Abort"
                        ),
                    }
                }
            } else {
                let exhausted = job.attempt_count >= job.max_attempts;
                if bus_on && exhausted {
                    // Resolve the forensic-seal key through the SAME shared, trimmed helper the bus uses
                    // to verify it (WEISSMAN_FORENSIC_SEAL_SECRET → orchestrator → JWT). Resolving it
                    // inline here — untrimmed, and with a different precedence than the bus — produced a
                    // "bundle seal mismatch" that stranded the job in an infinite re-execution loop.
                    let signing_key = weissman_job_bus::forensic_seal_key_from_env();
                    let key = signing_key.as_deref();
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
                                terminalize_exhausted(
                                    pool,
                                    job.id,
                                    &msg,
                                    &format!("forensic DLQ failed: {e}"),
                                )
                                .await;
                            }
                        }
                        Err(e) => {
                            error!(target: "weissman_worker", job_id = %job.id, error = %e, "forensic bundle build failed");
                            terminalize_exhausted(
                                pool,
                                job.id,
                                &msg,
                                &format!("forensic bundle build failed: {e}"),
                            )
                            .await;
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
                } else if let Err(e) =
                    job_queue::fail_job(pool, &job, &wid, &msg, BASE_BACKOFF_SECS).await
                {
                    error!(target: "weissman_worker", job_id = %job.id, error = %e, "fail_job failed");
                    let _ = job_queue::force_requeue_running(
                        pool,
                        job.id,
                        &wid,
                        &format!("fail_job: {e}"),
                    )
                    .await;
                }
                // Overlay the raw error onto the dead row AFTER the event-sourced DLQ
                // projection (which stores only the failure class). Runs last so the
                // human-readable cause survives on `GET /api/jobs/:id` for triage.
                if exhausted {
                    if let Err(e) = job_queue::annotate_last_error(pool, job.id, &msg).await {
                        error!(target: "weissman_worker", job_id = %job.id, error = %e, "annotate_last_error failed");
                    }
                }
            }
        }
    }
}

fn main() {
    // Scanning engines recurse over untrusted, arbitrarily-nested network data — HTML trees,
    // JSON / SBOM dependency graphs, redirect chains, protocol frames. Tokio's default 2 MiB
    // worker-thread stack can overflow on legitimately-deep (but finite) input and, because a
    // stack overflow ABORTS the whole process, that kills the entire worker and every in-flight
    // job (observed in the engine-wiring audit: one scan aborted the worker, all later scans
    // then failed unclaimed). Give the runtime threads a generous, env-tunable stack so
    // deep-but-finite recursion completes. A genuinely UNBOUNDED recursion would still overflow
    // here — the `run_engine` begin-log (see engine_dispatch) then names the last engine before
    // the abort in the worker log, so the specific engine can be given a depth guard.
    let stack_mb = std::env::var("WEISSMAN_WORKER_THREAD_STACK_MB")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n >= 2)
        .unwrap_or(64);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(stack_mb * 1024 * 1024)
        .build()
        .expect("build weissman-worker tokio runtime")
        .block_on(async_main());
}

async fn async_main() {
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

    let app_pool = match weissman_db::connect_worker_app(database_url.trim()).await {
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

    // Dedicated control-plane pool: claim/reserve, heartbeat and job-state completion writes go
    // here, isolated from the `app_pool` that a running engine scan can hold in full. Without this,
    // a connection-hungry scan checks out every app slot and the worker's own "mark this job
    // completed" write times out ("database: pool timed out"), so finished jobs never reach a
    // terminal state and pollers see them hang. A tiny separate pool keeps the control plane alive.
    let ctrl_pool = match weissman_db::connect_control(database_url.trim()).await {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!(
                "weissman-worker: control-plane database connect failed: {}",
                e
            );
            std::process::exit(1);
        }
    };

    // app 48 + auth 12 + intel 12 + control 8. Paired with the backend's own 72, this was 152
    // against a server max_connections of 100 — see warn_if_pool_budget_exceeds_server.
    weissman_db::warn_if_pool_budget_exceeds_server(ctrl_pool.as_ref(), "worker", 48 + 12 + 12 + 8)
        .await;

    let light_n = worker_concurrency_cap("WEISSMAN_WORKER_LIGHT_CONCURRENCY", 8);
    let heavy_n = worker_concurrency_cap("WEISSMAN_WORKER_HEAVY_CONCURRENCY", 2);
    let light_sem = Arc::new(tokio::sync::Semaphore::new(light_n));
    let heavy_sem = Arc::new(tokio::sync::Semaphore::new(heavy_n));

    let channels = AsyncJobChannels::from_env();
    let wid = worker_id();
    let bus = Arc::new(JobBus::from_env((*ctrl_pool).clone()).await);

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
    // SIGTERM as well as SIGINT. `docker stop`, a compose restart and a k8s rollout all send
    // SIGTERM; only SIGINT was handled, so every one of those killed in-flight scans outright
    // after the 10s grace period rather than letting them finish. The HTTP server in this same
    // repo already handles both, so this was a gap, not a platform limit.
    tokio::spawn(async move {
        let sigint = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        #[cfg(unix)]
        let sigterm = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut s) => {
                    s.recv().await;
                }
                Err(e) => {
                    warn!(target: "weissman_worker", error = %e, "cannot install SIGTERM handler");
                    std::future::pending::<()>().await;
                }
            }
        };
        #[cfg(not(unix))]
        let sigterm = std::future::pending::<()>();

        tokio::select! {
            _ = sigint => info!(target: "weissman_worker", "SIGINT received; draining"),
            _ = sigterm => info!(target: "weissman_worker", "SIGTERM received; draining"),
        }
        stop_clone.store(true, Ordering::SeqCst);
        if let Some(s) = swarm_shutdown {
            s.stop();
        }
    });

    // Reclaim jobs left `running` after worker crash / network partition (self-healing queue).
    let reclaim_pool = ctrl_pool.clone();
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

    // App-pool saturation telemetry. Engine scans acquire `app_pool` connections for the duration of
    // a run; if an engine holds them across long network I/O or leaks them, later scans time out
    // acquiring one ("pool timed out while waiting for an open connection"). Log pool occupancy every
    // few seconds so a saturating engine is pinpointed by correlating occupancy with the adjacent
    // `engine_exec` "run_engine begin engine=" breadcrumb. Tunable via
    // `WEISSMAN_WORKER_POOL_METRICS_SECS` (default 5; 0 disables).
    let pool_metrics_secs = std::env::var("WEISSMAN_WORKER_POOL_METRICS_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(5);
    if pool_metrics_secs > 0 {
        let m_app = app_pool.clone();
        let m_ctrl = ctrl_pool.clone();
        let m_intel = intel_pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(pool_metrics_secs));
            interval.tick().await; // consume the immediate first tick
            loop {
                interval.tick().await;
                let app_size = m_app.size();
                let app_idle = m_app.num_idle();
                // Active health-probe: time a trivial acquire+query on app_pool. When a scan's
                // begin_tenant_tx fails with "pool timed out" even though occupancy is ~0, the cause
                // is inability to acquire/OPEN a connection (runtime starvation or slow establishment),
                // not connections held. This probe records how long an acquire+SELECT 1 actually takes
                // and whether it fails within 8s, so the stall window is captured and correlated with
                // the running engine. It also keeps one connection hot, reducing cold-start churn.
                let probe_start = std::time::Instant::now();
                let probe = tokio::time::timeout(
                    Duration::from_secs(8),
                    sqlx::query("SELECT 1").execute(m_app.as_ref()),
                )
                .await;
                let probe_ms = probe_start.elapsed().as_millis() as u64;
                let probe_ok = matches!(probe, Ok(Ok(_)));
                info!(
                    target: "pool_metrics",
                    app_size,
                    app_idle,
                    app_in_use = app_size.saturating_sub(app_idle as u32),
                    probe_ms,
                    probe_ok,
                    ctrl_size = m_ctrl.size(),
                    ctrl_idle = m_ctrl.num_idle(),
                    intel_size = m_intel.size(),
                    intel_idle = m_intel.num_idle(),
                    "worker pool occupancy"
                );
            }
        });
    }

    while !stop.load(Ordering::SeqCst) {
        // When the heavy pool is saturated, ask the database to skip heavy kinds rather than
        // claiming one and then blocking on its permit. The loop deliberately blocks while
        // waiting for a permit (see below — it keeps exactly one job in that window so a single
        // pinned heartbeat suffices), which means a claimed heavy job stalls the ENTIRE queue:
        // idle light capacity sat unused behind a heavy job that could not start. Filtering at
        // the claim keeps that invariant intact and still drains light work.
        //
        // The exclusion list is HEAVY_KINDS, the same list `job_class` is asserted against, so
        // the SQL filter and the Rust classification cannot disagree.
        let heavy_full = heavy_sem.available_permits() == 0;
        let light_free = light_sem.available_permits() > 0;
        let exclude: &[&str] = if heavy_full && light_free {
            HEAVY_KINDS
        } else {
            &[]
        };
        let claim_result = if bus.is_enabled() {
            job_queue::reserve_next_excluding(ctrl_pool.as_ref(), &wid, LOCK_SECS, exclude).await
        } else {
            job_queue::claim_next_excluding(ctrl_pool.as_ref(), &wid, LOCK_SECS, exclude).await
        };

        // Keep the swarm heartbeat's advertised load true. It published a hardcoded 0, so the
        // only non-identity field in the gossip stream was a constant.
        if let Some(ref s) = swarm {
            let in_flight = (light_n - light_sem.available_permits())
                + (heavy_n - heavy_sem.available_permits());
            s.set_jobs_active(in_flight as u32);
        }

        // Liveness beat, written only when the dequeue round-trip actually worked — an empty
        // queue counts, a failed claim does not. The container healthcheck reads this file's
        // mtime, so "the process exists" and "the process can do its job" stop being the same
        // reading. They were not: the previous healthcheck was `cat /proc/1/comm | grep -q
        // weissman-worker`, which reported healthy for four days while every claim failed.
        if claim_result.is_ok() {
            touch_liveness_beat();
        }

        match claim_result {
            Ok(Some(job)) => {
                let is_heavy = job_is_heavy(job.kind.as_str());
                let sem = if is_heavy {
                    heavy_sem.clone()
                } else {
                    light_sem.clone()
                };
                // Keep the just-claimed job's lock alive while we wait for a
                // concurrency permit. If the pool is saturated and we block past
                // LOCK_SECS, locked_until would lapse and the reclaim task could
                // hand this job to a second worker — and legacy (non-bus) mode has
                // no post-claim re-check to catch the resulting double execution.
                // Only one job is ever in this window (the loop blocks here before
                // claiming the next), so a single pinned heartbeat suffices.
                let permit = {
                    let acquire = sem.acquire_owned();
                    tokio::pin!(acquire);
                    let mut hb =
                        tokio::time::interval(weissman_job_bus::keepalive::heartbeat_interval());
                    hb.tick().await; // consume the immediate first tick
                    loop {
                        tokio::select! {
                            p = &mut acquire => break p,
                            _ = hb.tick() => {
                                if let Err(e) = job_queue::heartbeat(
                                    ctrl_pool.as_ref(), job.id, LOCK_SECS,
                                ).await {
                                    warn!(
                                        target: "weissman_worker",
                                        job_id = %job.id, error = %e,
                                        "pre-exec heartbeat failed while awaiting permit"
                                    );
                                }
                            }
                        }
                    }
                };
                let permit = match permit {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let app_pool = app_pool.clone();
                let ctrl_pool = ctrl_pool.clone();
                let intel_pool = intel_pool.clone();
                let auth_pool = auth_pool.clone();
                let channels = channels.clone();
                let bus = bus.clone();
                let swarm = swarm.clone();
                let wid = wid.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    process_one(
                        app_pool, ctrl_pool, intel_pool, auth_pool, channels, bus, swarm, wid, job,
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
    // Drain. `process_one` runs in detached tasks, so simply returning here drops the runtime and
    // aborts every in-flight scan mid-write — leaving rows `running` for the stale-lock sweep to
    // reclaim minutes later, and losing whatever the engine had already found.
    //
    // The permit count is the live in-flight count: each running job holds one, so waiting for
    // both semaphores to return to full capacity is exactly "everything finished".
    let drain_deadline = std::time::Duration::from_secs(
        std::env::var("WEISSMAN_WORKER_DRAIN_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(25),
    );
    let drain_started = std::time::Instant::now();
    loop {
        let in_flight =
            (light_n - light_sem.available_permits()) + (heavy_n - heavy_sem.available_permits());
        if in_flight == 0 {
            break;
        }
        if drain_started.elapsed() >= drain_deadline {
            warn!(
                target: "weissman_worker", in_flight,
                "drain deadline reached; {in_flight} job(s) still running will be reclaimed by the \
                 stale-lock sweep"
            );
            break;
        }
        info!(target: "weissman_worker", in_flight, "draining in-flight jobs before shutdown");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    info!(target: "weissman_worker", drained_in = ?drain_started.elapsed(), "shutdown");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The container healthcheck and the k8s readiness probe both key off this file's mtime, so
    /// the beat must actually land at the configured path. A silent write failure here would
    /// restore exactly the blind spot the beat was added to close.
    #[test]
    fn liveness_beat_is_written_to_the_configured_path() {
        let dir = std::env::temp_dir().join(format!("weissman-beat-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("alive");
        // SAFETY: single-threaded test; no other thread reads the environment concurrently.
        unsafe { std::env::set_var("WEISSMAN_WORKER_LIVENESS_FILE", &path) };

        assert_eq!(liveness_beat_path(), path, "env override must win");
        assert!(!path.exists(), "precondition: beat file does not exist yet");

        touch_liveness_beat();
        assert!(
            path.exists(),
            "touch_liveness_beat must create the file the healthcheck stats"
        );

        // Writing again must refresh it rather than fail on an existing file — the worker calls
        // this on every poll for the lifetime of the process.
        touch_liveness_beat();
        assert!(path.exists(), "repeated beats must keep the file present");

        unsafe { std::env::remove_var("WEISSMAN_WORKER_LIVENESS_FILE") };
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unwritable path must degrade to a stale beat (and therefore a failing healthcheck),
    /// never take the worker process down.
    #[test]
    fn liveness_beat_failure_does_not_panic() {
        // SAFETY: single-threaded test.
        unsafe {
            std::env::set_var(
                "WEISSMAN_WORKER_LIVENESS_FILE",
                "/nonexistent-dir-weissman/alive",
            )
        };
        touch_liveness_beat(); // must not panic
        unsafe { std::env::remove_var("WEISSMAN_WORKER_LIVENESS_FILE") };
    }

    // Every job kind whose executor arm dispatches the deep monolithic engine future
    // (`engine_dispatch::run_engine` / `dispatch_engine_match`) MUST be classified heavy so
    // `process_one` drives it on the 32 MiB large stack. Running such a future inline on the
    // ~2 MiB Tokio worker stack overflows and aborts the whole worker process — a `fatal
    // runtime error: stack overflow` that then makes the swarm coordinator orphan every
    // in-flight job on that worker. `top_tier_health_probe` regressed exactly this way.
    #[test]
    fn deep_engine_dispatch_kinds_run_on_large_stack() {
        for kind in [
            "command_center_engine",
            "top_tier_health_probe",
            "scan_all_engines",
            "scan_discovered_domains",
            "tenant_scan_chunk",
        ] {
            assert!(
                job_is_heavy(kind),
                "{kind} dispatches deep engine futures and must be heavy (32 MiB large stack), \
                 else the worker stack-overflows and aborts"
            );
        }
    }

    // A 20-engine sequential fan-out must not be capped at the 5-minute default, which would
    // spuriously time out a legitimately long probe.
    #[test]
    fn top_tier_health_probe_has_generous_timeout() {
        let default_budget = job_kind_timeout("some_unknown_kind");
        assert!(
            job_kind_timeout("top_tier_health_probe") > default_budget,
            "top_tier_health_probe fans out to every top-tier engine and needs more than the \
             default per-job budget"
        );
    }

    #[test]
    fn heavy_jobs_get_long_timeouts() {
        assert_eq!(
            job_kind_timeout("tenant_full_scan"),
            Duration::from_secs(300)
        );
        assert_eq!(
            job_kind_timeout("onboarding_tenant_scan"),
            Duration::from_secs(300)
        );
        assert_eq!(
            job_kind_timeout("tenant_scan_chunk"),
            Duration::from_secs(1200)
        );
        assert_eq!(job_kind_timeout("auto_heal"), Duration::from_secs(1800));
        assert_eq!(
            job_kind_timeout("scan_all_engines"),
            Duration::from_secs(2700)
        );
        assert_eq!(job_kind_timeout("pipeline_scan"), Duration::from_secs(1200));
    }

    #[test]
    fn cheap_and_unknown_jobs_get_short_timeouts() {
        assert_eq!(job_kind_timeout("noop"), Duration::from_secs(30));
        assert_eq!(job_kind_timeout("ping"), Duration::from_secs(30));
        // Unknown kinds fall back to the 5-minute default.
        assert_eq!(job_kind_timeout("something_new"), Duration::from_secs(300));
    }

    #[test]
    fn job_is_heavy_classifies_known_kinds() {
        assert!(!job_is_heavy("tenant_full_scan"));
        assert!(job_is_heavy("tenant_scan_chunk"));
        assert!(job_is_heavy("ai_redteam"));
        assert!(job_is_heavy("scan_discovered_domains"));
        assert!(job_is_heavy("genesis_eternal_fuzz"));
        assert!(job_is_heavy("feedback_fuzz"));
    }

    #[test]
    fn job_is_heavy_rejects_light_and_unknown_kinds() {
        assert!(!job_is_heavy("noop"));
        assert!(!job_is_heavy("ping"));
        assert!(!job_is_heavy("unknown_kind"));
        assert!(!job_is_heavy(""));
    }

    #[test]
    fn concurrency_cap_parses_positive_env_value() {
        let key = "WEISSMAN_TEST_WORKER_CAP_POSITIVE";
        std::env::set_var(key, "12");
        assert_eq!(worker_concurrency_cap(key, 4), 12);
        std::env::remove_var(key);
    }

    #[test]
    fn concurrency_cap_falls_back_on_invalid_or_zero() {
        let key = "WEISSMAN_TEST_WORKER_CAP_INVALID";
        std::env::remove_var(key);
        // Unset -> default.
        assert_eq!(worker_concurrency_cap(key, 7), 7);
        // Zero rejected -> default.
        std::env::set_var(key, "0");
        assert_eq!(worker_concurrency_cap(key, 7), 7);
        // Non-numeric rejected -> default.
        std::env::set_var(key, "abc");
        assert_eq!(worker_concurrency_cap(key, 7), 7);
        std::env::remove_var(key);
    }

    #[test]
    fn worker_id_has_host_and_pid() {
        let id = worker_id();
        let (_host, pid) = id.rsplit_once(':').expect("worker id contains a colon");
        assert_eq!(pid.parse::<u32>().unwrap(), std::process::id());
    }

    /// A heavy kind must never fall through to the default budget.
    ///
    /// This is the invariant the two separate match blocks could not express: ten heavy kinds sat
    /// on the 300s default and timed out on every attempt until they were dead-lettered.
    #[test]
    fn every_heavy_kind_has_an_explicit_timeout() {
        const DEFAULT_SECS: u64 = 5 * 60;
        let offenders: Vec<&str> = HEAVY_KINDS
            .iter()
            .copied()
            .filter(|k| job_class(k).timeout_secs == DEFAULT_SECS)
            .collect();
        assert!(
            offenders.is_empty(),
            "these heavy kinds fall through to the {DEFAULT_SECS}s default budget and will time \
             out, retry and dead-letter on every attempt: {offenders:?}"
        );
    }

    /// The HEAVY_KINDS list and the table must not drift apart.
    #[test]
    fn heavy_kinds_list_matches_the_table() {
        for k in HEAVY_KINDS {
            assert!(
                job_class(k).heavy,
                "{k} is in HEAVY_KINDS but not heavy in job_class"
            );
        }
        // Spot-check the other direction with kinds that must stay light.
        for k in [
            "noop",
            "ping",
            "council_debate",
            "definitely_not_a_real_kind",
        ] {
            assert!(!job_class(k).heavy, "{k} must not be heavy");
        }
    }

    #[test]
    fn coordinator_full_scan_is_light_so_it_cannot_starve_soar() {
        assert!(!job_is_heavy("tenant_full_scan"));
        assert!(!job_is_heavy("onboarding_tenant_scan"));
        assert!(
            job_kind_timeout("tenant_full_scan") <= Duration::from_secs(300),
            "parent only fans out chunks; a 3600s budget on the coordinator is how the fleet Self-DoS'd"
        );
    }

    #[test]
    fn keepalive_interval_is_ten_seconds() {
        assert_eq!(
            weissman_job_bus::LEASE_HEARTBEAT_INTERVAL_SECS,
            10,
            "architect spec: extend the Redis lease every 10s"
        );
        assert_eq!(weissman_job_bus::PROGRESS_STALL_SECS, 60);
    }

    /// genesis_eternal_fuzz runs a full fuzz cycle AND the council war room, which alone is
    /// budgeted 1200s — its ceiling must exceed that, or it can never finish.
    #[test]
    fn genesis_eternal_fuzz_outlasts_the_council_war_room() {
        assert!(
            job_class("genesis_eternal_fuzz").timeout_secs
                > job_class("council_debate").timeout_secs,
            "genesis_eternal_fuzz must be budgeted above council_debate; it runs that war room \
             plus a full DFS fuzz cycle"
        );
    }
}
