//! Prometheus metrics (`/api/metrics`), HTTP request histograms, tracing bootstrap.

use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use serde_json::json;
use std::sync::OnceLock;
use std::sync::Arc;
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

/// Production JSON logs when `WEISSMAN_LOG_FORMAT=json` (plain text otherwise).
pub fn init_tracing_from_env() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let json_logs = std::env::var("WEISSMAN_LOG_FORMAT")
        .map(|s| s.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let _ = if json_logs {
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_env_filter(filter)
            .try_init()
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).try_init()
    };
}

/// Spawns background inserts into `tenant_llm_usage` for each LLM completion (see `weissman_engines::openai_chat`).
pub fn register_llm_tenant_metering(app_pool: Arc<sqlx::PgPool>) {
    weissman_engines::openai_chat::set_llm_usage_reporter(Arc::new(
        move |tenant_id, prompt_tokens, completion_tokens, model, operation| {
            let pool = app_pool.clone();
            tokio::spawn(async move {
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
    if path.starts_with("/api/poe-scan/status/")
        || path.starts_with("/api/poe-scan/stream/")
    {
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

pub async fn http_metrics_middleware(request: Request<Body>, next: Next) -> axum::response::Response {
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
        "path" => bucket,
        "status" => status_s,
    )
    .increment(1);
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
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
        tick.tick().await;
        loop {
            tick.tick().await;
            metrics::gauge!("weissman_db_pool_size", "pool" => "app").set(app_pool.size() as f64);
            metrics::gauge!("weissman_db_pool_idle", "pool" => "app")
                .set(app_pool.num_idle() as f64);
            metrics::gauge!("weissman_db_pool_size", "pool" => "auth")
                .set(auth_pool.size() as f64);
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

            metrics::gauge!("weissman_orchestrator_active_tenant_cycles").set(
                crate::orchestrator::active_tenant_scan_count() as f64,
            );
            metrics::gauge!("weissman_scanning_flag_active").set(
                if crate::orchestrator::is_scanning_active() {
                    1.0
                } else {
                    0.0
                },
            );
        }
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
        let _ = tx.send(j.to_string());
    }
}

pub fn metrics_auth_ok(headers: &HeaderMap) -> bool {
    let Ok(token) = std::env::var("WEISSMAN_METRICS_TOKEN") else {
        return true;
    };
    let token = token.trim();
    if token.is_empty() {
        return true;
    }
    if let Some(auth) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
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
