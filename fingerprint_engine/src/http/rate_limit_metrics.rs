//! In-memory rate-limit usage counters and analytics (scans / login / API).
//!
//! Scan limits mirror `tenant_scan_limit.rs` env vars; login/API limits mirror
//! `weissman-server` edge middleware env vars. Optional Redis is not wired in Rust
//! today — counters live in-process only.

use axum::extract::{ConnectInfo, Extension, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dashmap::DashMap;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::auth_jwt::AuthContext;

use super::client_ip::extract_client_ip;

const VIOLATION_CAP: usize = 200;
const ENDPOINT_CAP: usize = 50;
const HISTORY_RETAIN_SECS: i64 = 7 * 24 * 3600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BucketKind {
    Scans,
    Logins,
    Api,
}

#[derive(Default, Clone, Copy)]
struct MinuteCounts {
    scans: u32,
    logins: u32,
    api: u32,
}

struct ViolationRow {
    at: DateTime<Utc>,
    kind: &'static str,
    endpoint: String,
    attempts: u32,
}

struct MetricsStore {
    scan_windows: DashMap<i64, Mutex<VecDeque<Instant>>>,
    login_windows: DashMap<String, Mutex<VecDeque<Instant>>>,
    api_windows: DashMap<String, Mutex<VecDeque<Instant>>>,
    minute_buckets: DashMap<i64, MinuteCounts>,
    endpoint_hits: DashMap<String, u32>,
    violations: Mutex<VecDeque<ViolationRow>>,
}

fn store() -> &'static MetricsStore {
    static S: OnceLock<MetricsStore> = OnceLock::new();
    S.get_or_init(|| MetricsStore {
        scan_windows: DashMap::new(),
        login_windows: DashMap::new(),
        api_windows: DashMap::new(),
        minute_buckets: DashMap::new(),
        endpoint_hits: DashMap::new(),
        violations: Mutex::new(VecDeque::new()),
    })
}

fn nz_env(name: &str, default: u32, min: u32, max: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

#[must_use]
pub fn scan_limit_per_minute() -> u32 {
    nz_env("WEISSMAN_TENANT_SCAN_POSTS_PER_MINUTE", 24, 4, 240)
}

#[must_use]
pub fn scan_burst() -> u32 {
    nz_env("WEISSMAN_TENANT_SCAN_BURST", 12, 2, 120)
}

#[must_use]
pub fn login_limit_per_minute() -> u32 {
    nz_env("WEISSMAN_LOGIN_PER_MINUTE", 8, 2, 60)
}

#[must_use]
pub fn login_burst() -> u32 {
    nz_env("WEISSMAN_LOGIN_BURST", 12, 2, 120)
}

#[must_use]
pub fn enroll_limit_per_minute() -> u32 {
    nz_env("WEISSMAN_AGENT_ENROLL_PER_MINUTE", 6, 2, 60)
}

#[must_use]
pub fn enroll_burst() -> u32 {
    nz_env("WEISSMAN_AGENT_ENROLL_BURST", 10, 2, 120)
}

#[must_use]
pub fn api_limit_per_sec() -> u32 {
    nz_env("WEISSMAN_RATE_LIMIT_PER_SEC", 30, 5, 500)
}

#[must_use]
pub fn api_burst() -> u32 {
    nz_env("WEISSMAN_RATE_LIMIT_BURST", 60, 10, 2000)
}

fn unix_minute(now: DateTime<Utc>) -> i64 {
    now.timestamp() / 60
}

fn prune_old_buckets(now: DateTime<Utc>) {
    let cutoff = now.timestamp() - HISTORY_RETAIN_SECS;
    store().minute_buckets.retain(|k, _| *k >= cutoff / 60);
}

fn bump_minute(kind: BucketKind) {
    let now = Utc::now();
    prune_old_buckets(now);
    let key = unix_minute(now);
    let mut entry = store().minute_buckets.entry(key).or_default();
    match kind {
        BucketKind::Scans => entry.scans = entry.scans.saturating_add(1),
        BucketKind::Logins => entry.logins = entry.logins.saturating_add(1),
        BucketKind::Api => entry.api = entry.api.saturating_add(1),
    }
}

fn push_window(
    map: &DashMap<String, Mutex<VecDeque<Instant>>>,
    key: &str,
    window: Duration,
) -> (usize, u64) {
    let now = Instant::now();
    let cutoff = now.checked_sub(window).unwrap_or(now);
    let cell = map.entry(key.to_string()).or_default();
    let mut q = cell.lock().expect("rate_limit window lock");
    q.retain(|t| *t > cutoff);
    q.push_back(now);
    let count = q.len();
    let reset_in = q
        .front()
        .map(|oldest| {
            window
                .checked_sub(oldest.elapsed())
                .unwrap_or(Duration::ZERO)
                .as_secs()
                .max(if count > 0 { 1 } else { 0 })
        })
        .unwrap_or(0);
    (count, reset_in)
}

fn push_window_i64(
    map: &DashMap<i64, Mutex<VecDeque<Instant>>>,
    key: i64,
    window: Duration,
) -> (usize, u64) {
    let now = Instant::now();
    let cutoff = now.checked_sub(window).unwrap_or(now);
    let cell = map.entry(key).or_default();
    let mut q = cell.lock().expect("rate_limit window lock");
    q.retain(|t| *t > cutoff);
    q.push_back(now);
    let count = q.len();
    let reset_in = q
        .front()
        .map(|oldest| {
            window
                .checked_sub(oldest.elapsed())
                .unwrap_or(Duration::ZERO)
                .as_secs()
                .max(if count > 0 { 1 } else { 0 })
        })
        .unwrap_or(0);
    (count, reset_in)
}

fn window_count_i64(map: &DashMap<i64, Mutex<VecDeque<Instant>>>, key: i64, window: Duration) -> (usize, u64) {
    let now = Instant::now();
    let cutoff = now.checked_sub(window).unwrap_or(now);
    let Some(cell) = map.get(&key) else {
        return (0, 0);
    };
    let mut q = cell.lock().expect("rate_limit window lock");
    q.retain(|t| *t > cutoff);
    let count = q.len();
    let reset_in = q
        .front()
        .map(|oldest| {
            window
                .checked_sub(oldest.elapsed())
                .unwrap_or(Duration::ZERO)
                .as_secs()
                .max(if count > 0 { 1 } else { 0 })
        })
        .unwrap_or(0);
    (count, reset_in)
}

fn window_count(map: &DashMap<String, Mutex<VecDeque<Instant>>>, key: &str, window: Duration) -> (usize, u64) {
    let now = Instant::now();
    let cutoff = now.checked_sub(window).unwrap_or(now);
    let Some(cell) = map.get(key) else {
        return (0, 0);
    };
    let mut q = cell.lock().expect("rate_limit window lock");
    q.retain(|t| *t > cutoff);
    let count = q.len();
    let reset_in = q
        .front()
        .map(|oldest| {
            window
                .checked_sub(oldest.elapsed())
                .unwrap_or(Duration::ZERO)
                .as_secs()
                .max(if count > 0 { 1 } else { 0 })
        })
        .unwrap_or(0);
    (count, reset_in)
}

fn record_violation(kind: &'static str, endpoint: &str) {
    let mut v = store().violations.lock().expect("violations lock");
    v.push_back(ViolationRow {
        at: Utc::now(),
        kind,
        endpoint: endpoint.to_string(),
        attempts: 1,
    });
    while v.len() > VIOLATION_CAP {
        v.pop_front();
    }
}

fn record_endpoint(path: &str) {
    store()
        .endpoint_hits
        .entry(path.to_string())
        .and_modify(|c| *c = c.saturating_add(1))
        .or_insert(1);
}

/// Successful tenant scan POST (after governor allowed).
pub fn record_scan_allowed(tenant_id: i64, path: &str) {
    push_window_i64(&store().scan_windows, tenant_id, Duration::from_secs(60));
    bump_minute(BucketKind::Scans);
    record_endpoint(path);
}

/// Tenant scan POST rejected by governor.
pub fn record_scan_denied(tenant_id: i64, path: &str) {
    let _ = tenant_id;
    record_violation("scans", path);
    let _ = window_count_i64(&store().scan_windows, tenant_id, Duration::from_secs(60));
}

/// Edge login attempt allowed (per client IP).
pub fn record_login_allowed(client_ip: &str) {
    push_window(&store().login_windows, client_ip, Duration::from_secs(60));
    bump_minute(BucketKind::Logins);
}

/// Edge login attempt rejected.
pub fn record_login_denied(client_ip: &str) {
    record_violation("logins", "/api/login");
    let _ = window_count(&store().login_windows, client_ip, Duration::from_secs(60));
}

/// General API request allowed at edge (per client IP, 1s window).
pub fn record_api_allowed(client_ip: &str) {
    push_window(&store().api_windows, client_ip, Duration::from_secs(1));
    bump_minute(BucketKind::Api);
}

/// General API request rejected at edge.
pub fn record_api_denied(client_ip: &str) {
    record_violation("api", "edge");
    let _ = window_count(&store().api_windows, client_ip, Duration::from_secs(1));
}

fn limit_block(current: usize, max: u32, reset_in: u64) -> Value {
    json!({
        "current": current,
        "max": max,
        "resetIn": reset_in,
    })
}

pub fn status_for(tenant_id: i64, client_ip: &str) -> Value {
    let scan_max = scan_limit_per_minute();
    let (scan_cur, scan_reset) =
        window_count_i64(&store().scan_windows, tenant_id, Duration::from_secs(60));
    let login_max = login_limit_per_minute();
    let (login_cur, login_reset) =
        window_count(&store().login_windows, client_ip, Duration::from_secs(60));
    let api_max = api_limit_per_sec();
    let (api_cur, api_reset) = window_count(&store().api_windows, client_ip, Duration::from_secs(1));

    json!({
        "scans": limit_block(scan_cur, scan_max, scan_reset),
        "logins": limit_block(login_cur, login_max, login_reset),
        "api": limit_block(api_cur, api_max, api_reset),
    })
}

fn range_params(range: &str) -> (i64, i64, &'static str) {
    match range {
        "6h" => (6 * 3600, 300, "%H:%M"),
        "24h" => (24 * 3600, 900, "%H:%M"),
        "7d" => (7 * 24 * 3600, 3600, "%m/%d %H:%M"),
        _ => (3600, 60, "%H:%M"), // default 1h
    }
}

fn aggregate_history(range_secs: i64, bucket_secs: i64, time_fmt: &str) -> Vec<Value> {
    let now = Utc::now();
    let start = now - ChronoDuration::seconds(range_secs);
    let start_min = unix_minute(start);
    let end_min = unix_minute(now);
    let bucket_mins = (bucket_secs / 60).max(1);
    let mut out = Vec::new();
    let mut cursor = start_min - (start_min % bucket_mins);
    while cursor <= end_min {
        let mut scans = 0u32;
        let mut logins = 0u32;
        let mut api = 0u32;
        for offset in 0..bucket_mins {
            if let Some(c) = store().minute_buckets.get(&(cursor + offset)) {
                scans = scans.saturating_add(c.scans);
                logins = logins.saturating_add(c.logins);
                api = api.saturating_add(c.api);
            }
        }
        let ts = DateTime::<Utc>::from_timestamp(cursor * 60, 0).unwrap_or(now);
        out.push(json!({
            "time": ts.format(time_fmt).to_string(),
            "scans": scans,
            "logins": logins,
            "api": api,
        }));
        cursor += bucket_mins;
    }
    out
}

pub fn analytics_for(tenant_id: i64, client_ip: &str, range: &str) -> Value {
    let (scan_cur, _) = window_count_i64(&store().scan_windows, tenant_id, Duration::from_secs(60));
    let (login_cur, _) = window_count(&store().login_windows, client_ip, Duration::from_secs(60));
    let (api_cur, _) = window_count(&store().api_windows, client_ip, Duration::from_secs(1));

    let (range_secs, bucket_secs, time_fmt) = range_params(range);
    let history = aggregate_history(range_secs, bucket_secs, time_fmt);

    let violations: Vec<Value> = store()
        .violations
        .lock()
        .expect("violations lock")
        .iter()
        .rev()
        .take(50)
        .map(|v| {
            json!({
                "type": v.kind,
                "endpoint": v.endpoint,
                "time": v.at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                "attempts": v.attempts,
            })
        })
        .collect();

    let mut endpoints: Vec<(String, u32)> = store()
        .endpoint_hits
        .iter()
        .map(|e| (e.key().clone(), *e.value()))
        .collect();
    endpoints.sort_by(|a, b| b.1.cmp(&a.1));
    endpoints.truncate(ENDPOINT_CAP);
    let endpoints_json: Vec<Value> = endpoints
        .into_iter()
        .map(|(endpoint, count)| json!({ "endpoint": endpoint, "count": count }))
        .collect();

    json!({
        "current": {
            "scans": { "current": scan_cur, "max": scan_limit_per_minute() },
            "logins": { "current": login_cur, "max": login_limit_per_minute() },
            "api": { "current": api_cur, "max": api_limit_per_sec() },
        },
        "history": history,
        "violations": violations,
        "endpoints": endpoints_json,
        "range": range,
        "source": "in_memory",
    })
}

#[derive(Deserialize)]
pub struct RateLimitAnalyticsQuery {
    #[serde(default = "default_range")]
    range: String,
}

fn default_range() -> String {
    "1h".to_string()
}

/// GET /api/rate-limits/status — current tenant scan + edge login/API usage.
pub async fn api_rate_limits_status(
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = extract_client_ip(&headers, peer);
    let limits = status_for(auth.tenant_id, &ip);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "limits": limits,
            "burst": scan_burst(),
            "limit_per_minute": scan_limit_per_minute(),
            "source": "in_memory",
        })),
    )
        .into_response()
}

/// GET /api/rate-limits/analytics — historical buckets + violations (real counters only).
pub async fn api_rate_limits_analytics(
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<RateLimitAnalyticsQuery>,
) -> Response {
    let ip = extract_client_ip(&headers, peer);
    let body = analytics_for(auth.tenant_id, &ip, q.range.trim());
    (StatusCode::OK, Json(body)).into_response()
}
