//! Prometheus metrics (`/api/metrics`), HTTP request histograms, tracing bootstrap.

use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use serde_json::json;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;

static PROMETHEUS: OnceLock<Option<PrometheusHandle>> = OnceLock::new();
/// Must outlive the process: dropping it flushes then joins the non-blocking log thread.
static NON_BLOCKING_LOG_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> =
    OnceLock::new();

/// Logs panics through `tracing` (target `sovereign`) then chains the default hook.
/// Call after [`init_tracing_from_env`] so subscribers are installed.
fn panic_exit_acknowledged() -> bool {
    matches!(
        std::env::var("WEISSMAN_PANIC_EXIT_ON_FATAL").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    ) && matches!(
        std::env::var("WEISSMAN_PANIC_EXIT_I_ACKNOWLEDGE_RESTART").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

pub fn install_sovereign_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(target: "sovereign", "process panic: {}", info);
        default_hook(info);
        if panic_exit_acknowledged() {
            std::process::exit(1);
        }
    }));
}

/// The OTLP tracer provider, retained so spans buffered by the batch processor can be flushed on
/// exit. `None` until [`init_tracing_from_env`] runs with `WEISSMAN_OTLP_ENDPOINT` set.
static OTEL_PROVIDER: OnceLock<opentelemetry_sdk::trace::SdkTracerProvider> = OnceLock::new();

/// Flush and stop OTLP span export. Call as one of the LAST steps before process exit — 0.32
/// removed `global::shutdown_tracer_provider()`, and simply dropping the provider does not
/// guarantee buffered spans are exported.
///
/// No-op when OTLP export was never enabled. Blocking (the batch processor runs on its own thread),
/// so from async code call it via `spawn_blocking` rather than on a runtime worker.
pub fn shutdown_otel_tracing() {
    if let Some(provider) = OTEL_PROVIDER.get() {
        if let Err(e) = provider.shutdown() {
            eprintln!("[Weissman][otel] provider shutdown failed: {e}");
        }
    }
}

/// Build an OpenTelemetry OTLP tracing layer when `WEISSMAN_OTLP_ENDPOINT` is set
/// (e.g. `http://otel-collector:4318/v1/traces`). Exports spans over OTLP/HTTP using
/// the existing reqwest stack. Returns `None` when unset or on exporter build failure,
/// so default behaviour (fmt logs only) is unchanged.
fn build_otel_layer(
) -> Option<Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;
    use tracing_subscriber::Layer;

    let endpoint = std::env::var("WEISSMAN_OTLP_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())?;

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| eprintln!("[Weissman][otel] exporter build failed: {e}"))
        .ok()?;

    // Distinguish server vs worker (and env) in the trace backend. Each component sets
    // WEISSMAN_SERVICE_NAME (e.g. weissman-server / weissman-worker); defaults to "weissman".
    let service_name = std::env::var("WEISSMAN_SERVICE_NAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "weissman".to_string());
    let deployment_env = std::env::var("WEISSMAN_ENV")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "dev".to_string());
    // OTel 0.32 API (moved with tracing-opentelemetry 0.33):
    //  * `TracerProvider` is now `SdkTracerProvider` (the trait keeps the old name, so the
    //    `opentelemetry::trace::TracerProvider as _` import above still supplies `.tracer()`).
    //  * `with_batch_exporter` no longer takes a runtime — since 0.30 the batch span processor owns
    //    a dedicated background thread instead of being generic over an async runtime, so the old
    //    `opentelemetry_sdk::runtime::Tokio` argument is gone.
    //  * `Resource::new(vec![..])` is replaced by the builder, which also layers in the SDK's
    //    default resource detectors beneath our explicit attributes.
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_attributes(vec![
                    opentelemetry::KeyValue::new("service.name", service_name),
                    opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                    opentelemetry::KeyValue::new("deployment.environment", deployment_env),
                ])
                .build(),
        )
        .build();
    let tracer = provider.tracer("weissman");
    // Keep an owned handle in addition to registering globally. 0.32 removed
    // `global::shutdown_tracer_provider()`, so a flush on exit is only possible through a retained
    // `SdkTracerProvider` — see [`shutdown_otel_tracing`]. Dropping the last reference is NOT a
    // substitute: the batch processor's buffered spans are only guaranteed to be exported by an
    // explicit `shutdown()`.
    let _ = OTEL_PROVIDER.set(provider.clone());
    opentelemetry::global::set_tracer_provider(provider);

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    eprintln!("[Weissman][otel] OTLP span export enabled");
    Some(
        tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_filter(filter)
            .boxed(),
    )
}

/// Production JSON logs when `WEISSMAN_LOG_FORMAT=json` (plain text otherwise).
/// When `WEISSMAN_OTLP_ENDPOINT` is set, also exports OpenTelemetry spans via OTLP/HTTP.
///
/// General HTTP `fmt` logs use a **lossy** non-blocking stdout appender so a
/// stuck container log driver / NFS cannot stall Tokio workers.
///
/// Ask Weissman forensic pages (`nlqa1`) do **not** ride this lossy ring.
/// `nlqa_syslog` uses `NonBlockingBuilder { lossy: false }` + OS syslog.
pub fn init_tracing_from_env() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::Layer;

    crate::nlqa_syslog::init();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let json_logs = std::env::var("WEISSMAN_LOG_FORMAT")
        .map(|s| s.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    // Lossy is correct for HTTP/app logs. Audit overflow uses nlqa_syslog (lossy=false).
    let (nb_writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(true)
        .buffered_lines_limit(1024)
        .thread_name("weissman-fmt-logs".into())
        .finish(std::io::stdout());

    let mut layers: Vec<
        Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>,
    > = Vec::new();
    if json_logs {
        layers.push(
            tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_writer(nb_writer)
                .with_filter(filter)
                .boxed(),
        );
    } else {
        layers.push(
            tracing_subscriber::fmt::layer()
                .with_writer(nb_writer)
                .with_filter(filter)
                .boxed(),
        );
    }
    if let Some(otel) = build_otel_layer() {
        layers.push(otel);
    }
    if tracing_subscriber::registry()
        .with(layers)
        .try_init()
        .is_ok()
    {
        let _ = NON_BLOCKING_LOG_GUARD.set(guard);
    }
}

/// Spawns background inserts into `tenant_llm_usage` for each LLM completion (see `weissman_engines::openai_chat`).
///
/// Architectural law (same as `findings_persist`): fire-and-forget DB tasks must not
/// storm `pool.acquire()`. This reporter fires once per LLM/embedding completion, and
/// LLM-heavy engines (council debate, generative fuzz, red-team) emit many completions
/// concurrently — a raw `tokio::spawn` per call would spawn a burst of detached tasks
/// that each open a tenant tx (`log_tenant_llm_usage` → `begin_tenant_tx`) and
/// collectively drain the shared app pool, starving the worker's claim/reserve loop
/// ("pool timed out while waiting for an open connection"). Routing every metering
/// insert through the SAME global `spawn_bounded_db_task` semaphore as the persistence
/// background tasks makes total background pooled-connection demand `O(permits)`
/// (`WEISSMAN_BG_DB_CONCURRENCY`, default 8) regardless of LLM call volume — the storm
/// is queued on the semaphore instead of on the connection pool.
pub fn register_llm_tenant_metering(app_pool: Arc<sqlx::PgPool>) {
    weissman_engines::openai_chat::set_llm_usage_reporter(Arc::new(
        move |tenant_id, prompt_tokens, completion_tokens, model, operation| {
            crate::http::ai_quota_mem::add_usage(tenant_id, prompt_tokens, completion_tokens);
            let pool = app_pool.clone();
            crate::findings_persist::spawn_bounded_db_task(async move {
                if let Err(e) = weissman_db::llm_usage::log_tenant_llm_usage(
                    pool.as_ref(),
                    tenant_id,
                    prompt_tokens,
                    completion_tokens,
                    &model,
                    operation,
                )
                .await
                {
                    tracing::warn!(
                        target: "llm_meter",
                        error = %e,
                        tenant_id,
                        "tenant_llm_usage insert failed"
                    );
                }
            });
        },
    ));
}

pub fn init_prometheus_recorder() {
    let _ = PROMETHEUS.get_or_init(|| {
        // Without an explicit bucket override, metrics-exporter-prometheus renders a *summary*
        // (quantiles + _sum/_count), never `_bucket` series — so `histogram_quantile(... _bucket)`
        // dashboard/alert queries silently resolve to nothing. Register real histogram buckets
        // for every latency metric the dashboards query by bucket.
        let latency_buckets: &[(&str, &[f64])] = &[
            (
                "http_request_duration_seconds",
                &[
                    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ],
            ),
            (
                "weissman_scan_duration_seconds",
                &[1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0],
            ),
            (
                "weissman_heal_duration_seconds",
                &[1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0],
            ),
            (
                "weissman_llm_inference_seconds",
                &[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
            ),
        ];
        let mut b = PrometheusBuilder::new();
        for (metric, buckets) in latency_buckets {
            b = b
                .set_buckets_for_metric(Matcher::Full((*metric).to_string()), buckets)
                .unwrap_or_else(|_| PrometheusBuilder::new());
        }
        match b.install_recorder() {
            Ok(h) => Some(h),
            Err(e) => {
                tracing::warn!(
                    target: "metrics",
                    error = %e,
                    "prometheus install (custom buckets) failed; retrying default builder"
                );
                match PrometheusBuilder::new().install_recorder() {
                    Ok(h) => Some(h),
                    Err(e2) => {
                        tracing::error!(
                            target: "metrics",
                            error = %e2,
                            "/api/metrics disabled until process restart"
                        );
                        None
                    }
                }
            }
        }
    });
}

/// `None` if both Prometheus installs failed (process continues; `/api/metrics` returns a comment body).
pub fn prometheus_handle() -> Option<&'static PrometheusHandle> {
    PROMETHEUS.get().and_then(|x| x.as_ref())
}

pub fn compact_metrics_path(path: &str) -> String {
    if path.starts_with("/api/clients/") {
        return "/api/clients/*".to_string();
    }
    if path.starts_with("/api/verify-audit/") {
        return "/api/verify-audit/*".to_string();
    }
    if path.starts_with("/api/poe-scan/status/") || path.starts_with("/api/poe-scan/stream/") {
        return "/api/poe-scan/*".to_string();
    }
    if path.starts_with("/api/heal-verify/") {
        return "/api/heal-verify/*".to_string();
    }
    if path.starts_with("/ws/") {
        return "/ws/*".to_string();
    }
    if path.starts_with("/command-center/") {
        return "/command-center/*".to_string();
    }
    if path.starts_with("/api/") {
        return path.to_string();
    }
    "/other".to_string()
}

pub async fn http_metrics_middleware(
    request: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let bucket = compact_metrics_path(path.as_str());
    let start = Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    let elapsed = start.elapsed().as_secs_f64();
    let method_s = method.to_string();
    let status_s = status.to_string();
    metrics::histogram!(
        "http_request_duration_seconds",
        "method" => method_s.clone(),
        "path" => bucket.clone(),
        "status" => status_s.clone(),
    )
    .record(elapsed);
    metrics::counter!(
        "http_requests_total",
        "method" => method_s,
        "path" => bucket.clone(),
        "status" => status_s,
    )
    .increment(1);
    // Dedicated reliability/security signals consumed by the Grafana dashboards +
    // application alerts (5xx error rate, rate-limit pressure).
    if status >= 500 {
        metrics::counter!("weissman_errors_total", "path" => bucket.clone()).increment(1);
    }
    if status == 429 {
        metrics::counter!("weissman_rate_limit_violations_total", "path" => bucket).increment(1);
    }
    response
}

pub async fn api_prometheus_metrics() -> impl IntoResponse {
    let body = prometheus_handle()
        .map(|h| h.render())
        .unwrap_or_else(|| "# weissman: metrics recorder unavailable\n".to_string());
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    (headers, body)
}

pub async fn api_prometheus_metrics_endpoint(headers: HeaderMap) -> impl IntoResponse {
    if !metrics_auth_ok(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::CONTENT_TYPE, "text/plain")],
            "metrics token required\n",
        )
            .into_response();
    }
    api_prometheus_metrics().await.into_response()
}

pub fn spawn_pool_metrics_loop(
    app_pool: Arc<sqlx::PgPool>,
    auth_pool: Arc<sqlx::PgPool>,
    intel_pool: Arc<sqlx::PgPool>,
) {
    // Supervise the 10s health/self-heal loop (crate::supervised): a panic inside it would otherwise
    // silently kill platform self-diagnosis, bounded recovery, and every gauge on /api/metrics for
    // the rest of the process lifetime. Supervision restarts it with bounded backoff and a
    // `weissman_supervised_restart_total{task="pool_metrics_loop"}` signal. Panic/exit restart is on
    // by default (it needs no extra opt-in, unlike stuck-detection; the WEISSMAN_SUPERVISOR_ENABLED
    // kill switch runs the loop once, unsupervised) and safe: recovery state is re-derived every
    // round (the in-memory gates re-engage on the next diagnosis, and the durable fleet gate from
    // #225 survives a restart regardless), so a revived loop simply resumes diagnosing. Stuck-detection (abort+restart a tick wedged on e.g. a
    // `fetch_one` against an unreachable Postgres with no statement timeout) is OPT-IN via
    // WEISSMAN_SUPERVISOR_STUCK_DEADLINE_SECS — see the note in spawn_stale_lock_reclaim_loop on
    // sizing a single global deadline above the longest supervised loop's cadence.
    let cfg = crate::supervised::SupervisorConfig::from_env();
    let hb = crate::supervised::Heartbeat::new();
    tokio::spawn(async move {
        crate::supervised::supervise("pool_metrics_loop", cfg, Some(hb), move |hb| {
            let app_pool = app_pool.clone();
            let auth_pool = auth_pool.clone();
            let intel_pool = intel_pool.clone();
            async move {
                let self_heal_thresholds = crate::self_healing::Thresholds::from_env();
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
                tick.tick().await;
                // Cheap pool/dependency gauges run every 10s tick; the heavier heal_requests
                // aggregation (a full GROUP BY) runs at a slower cadence to keep it off the
                // /api/metrics hot path.
                let mut iter: u64 = 0;
                loop {
                    tick.tick().await;
                    // Liveness beat for the watchdog — every iteration, before any (potentially
                    // blocking) query, so a slow-but-progressing tick is not mistaken for a hang.
                    if let Some(ref h) = hb {
                        h.beat();
                    }
                    iter = iter.wrapping_add(1);
            metrics::gauge!("weissman_db_pool_size", "pool" => "app").set(app_pool.size() as f64);
            metrics::gauge!("weissman_db_pool_idle", "pool" => "app")
                .set(app_pool.num_idle() as f64);
            metrics::gauge!("weissman_db_pool_size", "pool" => "auth").set(auth_pool.size() as f64);
            metrics::gauge!("weissman_db_pool_idle", "pool" => "auth")
                .set(auth_pool.num_idle() as f64);
            metrics::gauge!("weissman_db_pool_size", "pool" => "intel")
                .set(intel_pool.size() as f64);
            metrics::gauge!("weissman_db_pool_idle", "pool" => "intel")
                .set(intel_pool.num_idle() as f64);

            // Job-pipeline liveness. A depth gauge alone cannot tell "busy" from "wedged": during
            // the 2026-08-06 outage `weissman_async_jobs_pending` climbed to 2111 and nothing
            // looked at it, because a large backlog reads the same as heavy load. The two
            // unambiguous signals are ages — how long the oldest pending job has waited, and how
            // long since anything last completed. Both were four days.
            //
            // The age must be measured over CLAIMABLE work, not every `pending` row. After the
            // outage the queue kept 2,973 rows that the claim path can provably never pick up:
            // 2,285 carry no zero-trust envelope (reserve_next's envelope gate skips them) and the
            // rest sit at their attempt ceiling (the claim's attempt cap skips them). Measured
            // over all pending rows, `oldest_pending_age` reads 448,085s — 5.2 days — on a
            // pipeline that is running scans normally, so JobQueueStalled fires forever and can
            // never be cleared by anything an operator does. An alert that is always on is an
            // alert nobody reads, which is precisely the failure this rule exists to prevent.
            //
            // The `claimable` predicate below mirrors the claim predicate in
            // crates/weissman-db/src/job_queue.rs. Same lesson as the coalescing deadlock: a
            // predicate must describe what the other half of the system actually does, not what
            // this half intended. The unrunnable remainder is not hidden — it gets its own gauge
            // so it stays visible without paging.
            if let Ok((
                pending,
                claimable,
                unrunnable,
                running,
                failed,
                dead,
                oldest_pending_age,
                last_completion_age,
            )) = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, Option<f64>, Option<f64>)>(
                r#"WITH j AS (
                       SELECT *,
                              (status = 'pending'
                               AND attempt_count < max_attempts
                               AND payload ? '_weissman_job_bus'
                               AND (run_after IS NULL OR run_after <= now())) AS is_claimable
                         FROM weissman_async_jobs
                   )
                   SELECT
                       count(*) FILTER (WHERE status = 'pending')::bigint,
                       count(*) FILTER (WHERE is_claimable)::bigint,
                       count(*) FILTER (WHERE status = 'pending' AND NOT is_claimable)::bigint,
                       count(*) FILTER (WHERE status = 'running')::bigint,
                       count(*) FILTER (WHERE status = 'failed')::bigint,
                       count(*) FILTER (WHERE status = 'dead')::bigint,
                       EXTRACT(EPOCH FROM (now() - min(created_at)
                           FILTER (WHERE is_claimable)))::float8,
                       EXTRACT(EPOCH FROM (now() - max(updated_at)
                           FILTER (WHERE status = 'completed')))::float8
                   FROM j"#,
            )
            .fetch_one(app_pool.as_ref())
            .await
            {
                metrics::gauge!("weissman_async_jobs_pending").set(pending as f64);
                // What the worker can actually pick up. This is the number the alert rules key
                // off; `weissman_async_jobs_pending` stays as the raw depth for dashboards.
                metrics::gauge!("weissman_async_jobs_claimable").set(claimable as f64);
                // Pending but provably un-runnable — no envelope, or out of attempts. Visible so
                // the backlog is not silently forgotten, but it must never page: no operator
                // action can drain it.
                metrics::gauge!("weissman_async_jobs_unrunnable").set(unrunnable as f64);
                metrics::gauge!("weissman_async_jobs_by_status", "status" => "pending")
                    .set(pending as f64);
                metrics::gauge!("weissman_async_jobs_by_status", "status" => "running")
                    .set(running as f64);
                metrics::gauge!("weissman_async_jobs_by_status", "status" => "failed")
                    .set(failed as f64);
                metrics::gauge!("weissman_async_jobs_by_status", "status" => "dead")
                    .set(dead as f64);
                // 0 when nothing is queued: that is the healthy reading, and an absent series
                // would make a `> threshold` rule silently vacuous rather than quiet-and-correct.
                metrics::gauge!("weissman_async_jobs_oldest_claimable_age_seconds")
                    .set(oldest_pending_age.unwrap_or(0.0));
                // -1 before the very first completion, so an alert can distinguish "never ran"
                // from "just completed" (0) and decide for itself whether that should page.
                metrics::gauge!("weissman_async_jobs_last_completion_age_seconds")
                    .set(last_completion_age.unwrap_or(-1.0));
            }

            // Zero-trust claim rejections, derived from last_error because the worker has no
            // /metrics endpoint of its own to count them. This is the signal that was absent
            // while a single job-bus signing-key mismatch destroyed 3,266 tenant scans: the
            // rejections were written to last_error on every row and nothing ever read them.
            if let Ok(rejected) = sqlx::query_scalar::<_, i64>(
                "SELECT count(*)::bigint FROM weissman_async_jobs \
                 WHERE last_error LIKE '%zero-trust claim rejected%' \
                    OR last_error LIKE '%envelope attach failed%'",
            )
            .fetch_one(app_pool.as_ref())
            .await
            {
                metrics::gauge!("weissman_async_jobs_zero_trust_rejected").set(rejected as f64);
            }

            if let Ok(registered) =
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM endpoint_agents")
                    .fetch_one(app_pool.as_ref())
                    .await
            {
                metrics::gauge!("weissman_agents_registered").set(registered as f64);
                if let Ok(online) = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*)::bigint FROM endpoint_agents WHERE last_seen_at > now() - interval '90 seconds'",
                )
                .fetch_one(app_pool.as_ref())
                .await
                {
                    metrics::gauge!("weissman_agents_online").set(online as f64);
                    metrics::gauge!("weissman_agents_stale")
                        .set((registered - online).max(0) as f64);
                }
            }

            metrics::gauge!("weissman_orchestrator_active_tenant_cycles")
                .set(crate::orchestrator::active_tenant_scan_count() as f64);
            metrics::gauge!("weissman_scanning_flag_active").set(
                if crate::orchestrator::is_scanning_active() {
                    1.0
                } else {
                    0.0
                },
            );

            // Auto-heal outcome distribution + success rate, from heal_requests. Run every ~60s
            // (and immediately on the first pass) rather than every 10s — a full GROUP BY scan is
            // too heavy for the metrics hot path as the table grows.
            if iter % 6 == 1 {
                if let Ok(rows) = sqlx::query_as::<_, (String, i64)>(
                    "SELECT COALESCE(verdict, 'unknown') AS verdict, count(*)::bigint \
                     FROM heal_requests GROUP BY 1",
                )
                .fetch_all(app_pool.as_ref())
                .await
                {
                    let mut total: i64 = 0;
                    let mut fixed: i64 = 0;
                    for (verdict, n) in &rows {
                        metrics::gauge!("weissman_heal_by_verdict", "verdict" => verdict.clone())
                            .set(*n as f64);
                        total += *n;
                        if verdict == "fixed" {
                            fixed += *n;
                        }
                    }
                    metrics::gauge!("weissman_heal_total_requests").set(total as f64);
                    let rate = if total > 0 {
                        fixed as f64 / total as f64
                    } else {
                        0.0
                    };
                    metrics::gauge!("weissman_heal_success_rate").set(rate);
                }
            }

            // Dependency-health gauges (up=1 / down=0) — a first-class signal for
            // SLO / error-budget alerting instead of inferring outages from request errors.
            let pg_up = sqlx::query_scalar::<_, i32>("SELECT 1")
                .fetch_one(app_pool.as_ref())
                .await
                .is_ok();
            metrics::gauge!("weissman_dependency_up", "dep" => "postgres").set(if pg_up {
                1.0
            } else {
                0.0
            });
            let redis_required = crate::http::rate_limit_redis::distributed_state_required();
            let redis_up = if redis_required {
                let up = crate::http::rate_limit_redis::ping_ok().await;
                metrics::gauge!("weissman_dependency_up", "dep" => "redis").set(if up {
                    1.0
                } else {
                    0.0
                });
                up
            } else {
                true
            };

            // Self-healing: fold the health signals into a diagnosis + recommended recovery,
            // recorded as `weissman_self_heal_diagnosis_total` for dashboards/alerts. Builds a
            // coherent single snapshot from the in-memory pool stats + the two small agent/backlog
            // COUNTs (indexed, cheap at the 10s cadence).
            let sh_async = sqlx::query_scalar::<_, i64>(
                "SELECT count(*)::bigint FROM weissman_async_jobs WHERE status = 'pending'",
            )
            .fetch_one(app_pool.as_ref())
            .await
            .unwrap_or(0);
            let sh_registered =
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM endpoint_agents")
                    .fetch_one(app_pool.as_ref())
                    .await
                    .unwrap_or(0);
            let sh_online = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*)::bigint FROM endpoint_agents WHERE last_seen_at > now() - interval '90 seconds'",
            )
            .fetch_one(app_pool.as_ref())
            .await
            .unwrap_or(sh_registered);
            let snapshot = crate::self_healing::HealthSnapshot {
                postgres_up: pg_up,
                redis_required,
                redis_up,
                db_pool_size: app_pool.size(),
                db_pool_idle: u32::try_from(app_pool.num_idle()).unwrap_or(u32::MAX),
                agents_registered: u32::try_from(sh_registered).unwrap_or(0),
                agents_online: u32::try_from(sh_online).unwrap_or(0),
                async_jobs_pending: u64::try_from(sh_async).unwrap_or(0),
            };
            let diagnoses = crate::self_healing::diagnose(&snapshot, &self_heal_thresholds);
            crate::self_healing::record_diagnoses(&diagnoses);
            // Recover: apply the bounded, cooldown-gated recovery effects the diagnoses recommend
            // (engage load-shed/backoff gates, drive dependency circuit breakers, raise a prune
            // signal) and record `weissman_self_heal_recovery_total`. Feeds dependency health from
            // the snapshot every round so the circuits also *close* when the platform recovers.
            crate::self_heal_recovery::run_recovery(&snapshot, &diagnoses);
            // Durable cross-replica coordination (opt-in: WEISSMAN_SELFHEAL_SHARED_STATE_ENABLED):
            // publish any locally-engaged load-shed/backoff gate to the shared store, then refresh
            // this replica's cached view of the fleet gate. Makes shedding/backoff apply fleet-wide
            // instead of only on the replica that diagnosed the fault. Both calls are best-effort
            // and fail-open — no-ops when the flag is off or Postgres is unreachable.
            crate::self_heal_shared::publish_gates(
                app_pool.as_ref(),
                crate::self_heal_recovery::local_shed_until(),
                crate::self_heal_recovery::local_backoff_until(),
            )
            .await;
            crate::self_heal_shared::refresh(app_pool.as_ref()).await;
                }
            }
        })
        .await;
    });
}

fn haversine_km(a: (f64, f64), b: (f64, f64)) -> f64 {
    let (lat1, lon1) = (a.0.to_radians(), a.1.to_radians());
    let (lat2, lon2) = (b.0.to_radians(), b.1.to_radians());
    let dlat = lat2 - lat1;
    let dlon = lon2 - lon1;
    let h = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * h.sqrt().clamp(-1.0, 1.0).asin();
    6371.0 * c
}

/// After edge heartbeats flush: if ≥2 nodes in the same `region_code` are stale, emit CRITICAL telemetry
/// and approximate geographic blast radius (km) from pairwise lat/lon when coordinates exist.
pub async fn evaluate_regional_edge_blast_radius(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    telemetry: Option<&Arc<tokio::sync::broadcast::Sender<String>>>,
) -> Result<(), sqlx::Error> {
    use chrono::Utc;
    use sqlx::Row;
    use std::collections::HashMap;

    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        "SELECT region_code, latitude, longitude, last_heartbeat FROM edge_swarm_nodes WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await?;

    let stale_before = Utc::now() - chrono::Duration::minutes(5);
    let mut by_region: HashMap<String, Vec<(Option<f64>, Option<f64>, bool)>> = HashMap::new();
    for r in rows {
        let reg = r.try_get::<String, _>("region_code").unwrap_or_default();
        let lat = r.try_get::<Option<f64>, _>("latitude").ok().flatten();
        let lon = r.try_get::<Option<f64>, _>("longitude").ok().flatten();
        let hb = r
            .try_get::<Option<chrono::DateTime<Utc>>, _>("last_heartbeat")
            .ok()
            .flatten();
        let stale = hb.map(|t| t < stale_before).unwrap_or(true);
        by_region.entry(reg).or_default().push((lat, lon, stale));
    }

    for (region, nodes) in by_region {
        if nodes.len() < 2 {
            continue;
        }
        let stale_n = nodes.iter().filter(|(_, _, s)| *s).count();
        if stale_n < 2 {
            continue;
        }
        let coords: Vec<(f64, f64)> = nodes
            .iter()
            .filter_map(|(la, lo, _)| match (la, lo) {
                (Some(a), Some(b)) => Some((*a, *b)),
                _ => None,
            })
            .collect();
        let mut max_km = 0.0_f64;
        for i in 0..coords.len() {
            for j in (i + 1)..coords.len() {
                max_km = max_km.max(haversine_km(coords[i], coords[j]));
            }
        }
        emit_critical_edge_region_alert(
            tenant_id,
            region.as_str(),
            stale_n,
            nodes.len(),
            max_km,
            telemetry,
        );
    }
    Ok(())
}

fn emit_critical_edge_region_alert(
    tenant_id: i64,
    region: &str,
    stale_count: usize,
    total: usize,
    blast_radius_km: f64,
    telemetry: Option<&Arc<tokio::sync::broadcast::Sender<String>>>,
) {
    let msg = format!(
        "CRITICAL: edge swarm regional degradation tenant={} region={} stale={}/{} approx_blast_radius_km={:.1}",
        tenant_id, region, stale_count, total, blast_radius_km
    );
    tracing::error!(
        target: "edge_swarm_blast",
        tenant_id,
        region,
        stale_count,
        total,
        blast_radius_km,
        "{}",
        msg
    );
    metrics::counter!(
        "weissman_edge_swarm_regional_critical_total",
        "region" => region.to_string()
    )
    .increment(1);
    if let Some(tx) = telemetry {
        let j = json!({
            "engine": "edge_swarm",
            "severity": "CRITICAL",
            "message": msg,
            "tenant_id": tenant_id,
            "region_code": region,
            "stale_nodes": stale_count,
            "region_nodes": total,
            "blast_radius_km": blast_radius_km,
        });
        let _ = tx.send(crate::http::tenant_stream::stamp_value(tenant_id, j));
    }
}

/// Constant-time equality for the static metrics bearer token, avoiding the byte-position
/// timing oracle that `str`/`String` `==` (memcmp) leaks.
fn metrics_token_matches(provided: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    a.len() == b.len() && a.ct_eq(b).into()
}

pub fn metrics_auth_ok(headers: &HeaderMap) -> bool {
    let token = std::env::var("WEISSMAN_METRICS_TOKEN")
        .unwrap_or_default()
        .trim()
        .to_string();
    if token.len() < 32 {
        return false;
    }
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let rest = auth.trim();
        if let Some(b) = rest.strip_prefix("Bearer ") {
            if metrics_token_matches(b.trim(), &token) {
                return true;
            }
        }
    }
    if let Some(cookie_h) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie_h.split(';') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("weissman_metrics_token=") {
                if metrics_token_matches(v.trim(), &token) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_metrics_path_collapses_client_ids() {
        assert_eq!(compact_metrics_path("/api/clients/12345"), "/api/clients/*");
        assert_eq!(compact_metrics_path("/api/clients/"), "/api/clients/*");
    }

    #[test]
    fn compact_metrics_path_collapses_known_prefixes() {
        assert_eq!(
            compact_metrics_path("/api/verify-audit/abc"),
            "/api/verify-audit/*"
        );
        assert_eq!(
            compact_metrics_path("/api/poe-scan/status/9"),
            "/api/poe-scan/*"
        );
        assert_eq!(
            compact_metrics_path("/api/poe-scan/stream/9"),
            "/api/poe-scan/*"
        );
        assert_eq!(
            compact_metrics_path("/api/heal-verify/x"),
            "/api/heal-verify/*"
        );
        assert_eq!(compact_metrics_path("/ws/tenant/1"), "/ws/*");
        assert_eq!(
            compact_metrics_path("/command-center/dash"),
            "/command-center/*"
        );
    }

    #[test]
    fn compact_metrics_path_passes_through_other_api_paths_verbatim() {
        // starts with /api/ but matches no specific bucket -> returned unchanged
        assert_eq!(compact_metrics_path("/api/health"), "/api/health");
        // /api/poe-scan without status|stream falls through to the generic /api/ branch
        assert_eq!(
            compact_metrics_path("/api/poe-scan/other"),
            "/api/poe-scan/other"
        );
    }

    #[test]
    fn compact_metrics_path_non_api_maps_to_other() {
        assert_eq!(compact_metrics_path("/health"), "/other");
        assert_eq!(compact_metrics_path("/"), "/other");
        assert_eq!(compact_metrics_path("/metrics"), "/other");
    }

    #[test]
    fn haversine_identical_points_is_zero() {
        assert_eq!(haversine_km((0.0, 0.0), (0.0, 0.0)), 0.0);
        assert_eq!(haversine_km((51.5, -0.12), (51.5, -0.12)), 0.0);
    }

    #[test]
    fn haversine_is_symmetric() {
        let a = (40.0, -74.0);
        let b = (34.0, -118.0);
        let d1 = haversine_km(a, b);
        let d2 = haversine_km(b, a);
        assert!((d1 - d2).abs() < 1e-9);
    }

    #[test]
    fn haversine_one_degree_at_equator_is_about_111km() {
        // one degree of longitude at the equator is ~111.19 km
        let d = haversine_km((0.0, 0.0), (0.0, 1.0));
        assert!((d - 111.19).abs() < 0.5, "got {d}");
    }

    #[test]
    fn haversine_quarter_circumference() {
        // equator to the pole-meridian 90 deg apart is a quarter of Earth's circumference
        let d = haversine_km((0.0, 0.0), (0.0, 90.0));
        assert!((d - 10007.5).abs() < 5.0, "got {d}");
    }
}
