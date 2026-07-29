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
    let provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(opentelemetry_sdk::Resource::new(vec![
            opentelemetry::KeyValue::new("service.name", service_name),
            opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            opentelemetry::KeyValue::new("deployment.environment", deployment_env),
        ]))
        .build();
    let tracer = provider.tracer("weissman");
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
pub fn init_tracing_from_env() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::Layer;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let json_logs = std::env::var("WEISSMAN_LOG_FORMAT")
        .map(|s| s.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    let mut layers: Vec<
        Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>,
    > = Vec::new();
    if json_logs {
        layers.push(
            tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_filter(filter)
                .boxed(),
        );
    } else {
        layers.push(tracing_subscriber::fmt::layer().with_filter(filter).boxed());
    }
    if let Some(otel) = build_otel_layer() {
        layers.push(otel);
    }
    let _ = tracing_subscriber::registry().with(layers).try_init();
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
        let b = match PrometheusBuilder::new().set_buckets_for_metric(
            Matcher::Full("http_request_duration_seconds".to_string()),
            &[
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ],
        ) {
            Ok(b) => b,
            Err(_) => PrometheusBuilder::new(),
        };
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
    // `weissman_supervised_restart_total{task="pool_metrics_loop"}` signal. Panic/exit restart is
    // always on and safe: recovery state is re-derived every round (the in-memory gates re-engage on
    // the next diagnosis, and the durable fleet gate from #225 survives a restart regardless), so a
    // revived loop simply resumes diagnosing. Stuck-detection (abort+restart a tick wedged on e.g. a
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

            if let Ok(n) = sqlx::query_scalar::<_, i64>(
                "SELECT count(*)::bigint FROM weissman_async_jobs WHERE status = 'pending'",
            )
            .fetch_one(app_pool.as_ref())
            .await
            {
                metrics::gauge!("weissman_async_jobs_pending").set(n as f64);
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
            if b.trim() == token {
                return true;
            }
        }
    }
    if let Some(cookie_h) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie_h.split(';') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("weissman_metrics_token=") {
                if v.trim() == token {
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
