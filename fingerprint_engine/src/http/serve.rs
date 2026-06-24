//! Full-stack live server: API + dashboard from Rust. Live data only; no dummy.
//! Auth: POST /api/login returns JWT in HttpOnly cookie (+ `access_token` in JSON for SPA Bearer fallback).
//! API/WS use cookie or `Authorization` header; query JWT is limited to SSE (`?access_token=`) and
//! `/ws/agent` agent sessions (`?token=` agent JWT only). See [`crate::auth_jwt`].
//! Set `WEISSMAN_COOKIE_SECURE=1` when serving only over HTTPS; default is off so `http://127.0.0.1` dev accepts cookies.
//!
//! Environment (Postgres):
//! - `DATABASE_URL` — pooled app role (`weissman_app`, RLS via `app.current_tenant_id`).
//! - `WEISSMAN_AUTH_DATABASE_URL` — optional; defaults to `DATABASE_URL`; use `weissman_auth` for login/bootstrap.
//! - `WEISSMAN_MIGRATE_URL` — optional superuser URL; `weissman-server` runs migrations at startup when set.
//! - `WEISSMAN_PG_BACKUP_DIR` + `WEISSMAN_PG_DUMP_PATH` — optional periodic / manual `pg_dump` backups.

use async_stream::stream;
use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Extension, Path, Query, Request, State,
    },
    http::{
        header::CONTENT_DISPOSITION, header::CONTENT_TYPE, HeaderMap, HeaderValue, Method,
        StatusCode,
    },
    middleware::{self, Next},
    response::sse::{Event, Sse},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{delete, get, patch, post, put},
    Router,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use chrono_tz::Asia::Jerusalem;
use dashmap::DashMap;
use flume::TrySendError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use sqlx::Row;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tower::util::ServiceExt;
use tower_http::services::ServeDir;

use crate::audit_log;
use crate::auth_jwt::{self, AuthContext};
use crate::auto_heal;
use crate::dag_engine;
use crate::dag_pipeline;
use crate::db;
use crate::deception_engine;
use crate::exploit_synthesis_engine;
use crate::risk_graph;
use crate::threat_intel_engine;

use super::client_ip::extract_client_ip;

/// Persisted in poe_jobs table; broadcast for SSE.
#[derive(Clone, Serialize)]
struct PoEJobState {
    job_id: String,
    status: String,
    run_id: Option<i64>,
    findings_count: Option<usize>,
    message: Option<String>,
    error: Option<String>,
}

/// Bounded central channel for PoE job updates; try_send prevents slow clients from exhausting RAM.
const POE_UPDATES_CHANNEL_CAPACITY: usize = 100;
type PoeJobRegistry = Arc<DashMap<String, Vec<flume::Sender<String>>>>;

/// Global error/telemetry broadcast: engine failures (timeout, DB lock, LLM unreachable, etc.) so UI can show Toast.
const TELEMETRY_BROADCAST_CAPACITY: usize = 128;

pub struct AppState {
    pub app_pool: Arc<PgPool>,
    pub intel_pool: Arc<PgPool>,
    pub auth_pool: Arc<PgPool>,
    /// Optional read-only pool (separate role with SELECT-only grants).
    /// When `Some`, `nl_query::ask` will use this for the compiled SQL execution
    /// step. Defense-in-depth: even if validation breaks, Postgres rejects writes.
    pub read_only_pool: Option<Arc<PgPool>>,
    started_at: Instant,
    #[allow(dead_code)]
    timing_broadcast_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    #[allow(dead_code)]
    redteam_broadcast_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    radar_broadcast_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    /// PoE SSE: registry job_id -> list of bounded client channels; updates_tx feeds distributor that sends only to that job's subscribers.
    poe_job_registry: PoeJobRegistry,
    poe_job_updates_tx: flume::Sender<(String, String)>,
    /// Global error telemetry: broadcast to all connected Cockpit clients for Toast. Payload: JSON { engine, message, severity }.
    telemetry_broadcast_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    /// Phase 5: multi-agent swarm events for `/ws/swarm`.
    pub swarm_broadcast_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    /// Batched edge swarm heartbeats (30s flush) to reduce Postgres churn.
    pub edge_heartbeat_batcher: crate::edge_heartbeat_batch::EdgeHeartbeatBatcher,
    /// Optional sovereign C2: outbound commands to in-process swarm consumers (`WEISSMAN_SOVEREIGN_MPSC_CAPACITY`).
    pub sovereign_swarm_tx:
        Option<Arc<tokio::sync::mpsc::Sender<crate::sovereign_c2::SovereignSwarmCmd>>>,
    sovereign_swarm_rx: std::sync::Mutex<
        Option<tokio::sync::mpsc::Receiver<crate::sovereign_c2::SovereignSwarmCmd>>,
    >,
    /// Endpoint-agent live session registry (one entry per online agent_uuid).
    pub endpoint_agents: Arc<crate::endpoint_agents::AgentRegistry>,
}

impl AppState {
    pub(crate) fn take_sovereign_swarm_rx(
        &self,
    ) -> Option<tokio::sync::mpsc::Receiver<crate::sovereign_c2::SovereignSwarmCmd>> {
        self.sovereign_swarm_rx
            .lock()
            .ok()
            .and_then(|mut g| g.take())
    }
}

/// Format UTC datetime string from DB to Israel time (Asia/Jerusalem).
fn utc_str_to_israel(utc_str: &str) -> String {
    let s = utc_str.trim();
    if s.is_empty() {
        return "—".to_string();
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        let utc = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
        let il = utc.with_timezone(&Jerusalem);
        return il.format("%d/%m/%Y %H:%M Israel").to_string();
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        let utc = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
        let il = utc.with_timezone(&Jerusalem);
        return il.format("%d/%m/%Y %H:%M Israel").to_string();
    }
    s.to_string()
}

/// Where a bearer token was read from (for path-specific validation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenSource {
    HeaderOrCookie,
    QuerySseAccessToken,
    QuerySseTicket,
    QueryAgentWsToken,
}

/// SSE routes where EventSource cannot send `Authorization` (user JWT in query is deprecated).
fn sse_accepts_query_access_token(path: &str) -> bool {
    path == "/api/telemetry/stream"
        || path == "/api/ceo/war-room/stream"
        || (path.starts_with("/api/ceo/council/sessions/") && path.ends_with("/stream"))
}

/// Extract JWT from Cookie (`weissman_token`), `Authorization: Bearer`, or path-scoped query params.
fn extract_token_from_request<B>(req: &Request<B>, path: &str) -> Option<(String, TokenSource)> {
    // Agent WS: prefer `?token=` so a human session cookie cannot shadow the agent JWT.
    if path == "/ws/agent" {
        if let Some(q) = req.uri().query() {
            for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
                if k == "token" {
                    let t = v.trim();
                    if !t.is_empty() {
                        return Some((t.to_owned(), TokenSource::QueryAgentWsToken));
                    }
                }
            }
        }
    }
    if let Some(cookie_h) = req.headers().get(axum::http::header::COOKIE) {
        if let Ok(s) = cookie_h.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                let prefix = format!("{}=", auth_jwt::WEISSMAN_COOKIE_NAME);
                if part.starts_with(&prefix) {
                    let t = part[prefix.len()..].trim();
                    if !t.is_empty() {
                        return Some((t.to_string(), TokenSource::HeaderOrCookie));
                    }
                }
            }
        }
    }
    if let Some(auth_h) = req.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = auth_h.to_str() {
            if let Some(t) = s.strip_prefix("Bearer ") {
                let t = t.trim();
                if !t.is_empty() {
                    return Some((t.to_string(), TokenSource::HeaderOrCookie));
                }
            }
        }
    }
    let Some(q) = req.uri().query() else {
        return None;
    };
    if sse_accepts_query_access_token(path) {
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            if k == "sse_ticket" {
                let t = v.trim();
                if !t.is_empty() {
                    return Some((t.to_owned(), TokenSource::QuerySseTicket));
                }
            }
        }
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            if k == "access_token" {
                let t = v.trim();
                if !t.is_empty() {
                    return Some((t.to_owned(), TokenSource::QuerySseAccessToken));
                }
            }
        }
    }
    None
}

fn verify_token_for_request(token: &str, path: &str, source: TokenSource) -> Option<AuthContext> {
    match source {
        TokenSource::HeaderOrCookie => {
            if path == "/ws/agent" {
                auth_jwt::verify_agent_session_token(token)
            } else {
                auth_jwt::verify_access_token(token).filter(auth_jwt::is_user_access_context)
            }
        }
        TokenSource::QueryAgentWsToken => {
            if path != "/ws/agent" {
                return None;
            }
            auth_jwt::verify_agent_session_token(token)
        }
        TokenSource::QuerySseAccessToken => {
            if !sse_accepts_query_access_token(path) {
                return None;
            }
            // In production, refuse JWTs in the query string: they leak via access logs,
            // Referer headers, and browser history. Clients must use a short-lived
            // `sse_ticket` (or cookie auth) instead.
            if weissman_core::tls_policy::is_production_environment() {
                tracing::warn!(
                    target: "auth_guard",
                    path = %path,
                    "Rejected ?access_token= in production (use sse_ticket or cookie auth)"
                );
                return None;
            }
            tracing::warn!(
                target: "auth_guard",
                path = %path,
                "Deprecated: JWT passed via ?access_token= query (EventSource only; prefer cookie auth or sse_ticket)"
            );
            auth_jwt::verify_access_token(token).filter(auth_jwt::is_user_access_context)
        }
        TokenSource::QuerySseTicket => {
            if !sse_accepts_query_access_token(path) {
                return None;
            }
            auth_jwt::verify_sse_ticket(token)
        }
    }
}

/// Auth middleware: allow only POST /api/login; all other /api/* require valid JWT.
async fn auth_guard(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let method = request.method();
    if path == "/api/health" && method == Method::GET {
        return next.run(request).await;
    }
    // Unauthenticated login + MFA verify (per-IP rate limit + per-email lockout in handlers).
    if crate::http::is_account_lockout_post(method, path) {
        return next.run(request).await;
    }
    if path == "/api/logout" && method == Method::POST {
        return next.run(request).await;
    }
    if path == "/api/auth/refresh" && method == Method::POST {
        return next.run(request).await;
    }
    if path == "/api/onboarding/register" && method == Method::POST {
        return next.run(request).await;
    }
    if path == "/api/webhooks/paddle" && method == Method::POST {
        return next.run(request).await;
    }
    if path == "/api/auth/oidc/begin" && method == Method::GET {
        return next.run(request).await;
    }
    if path == "/api/auth/oidc/callback" && method == Method::GET {
        return next.run(request).await;
    }
    if path == "/api/auth/saml/acs" && method == Method::POST {
        return next.run(request).await;
    }
    if path == "/api/auth/saml/begin" && method == Method::GET {
        return next.run(request).await;
    }
    if path == "/api/deception/aws-events" && method == Method::POST {
        return next.run(request).await;
    }
    if path == "/api/openapi.json" && method == Method::GET {
        if !weissman_core::tls_policy::is_production_environment() {
            return next.run(request).await;
        }
    }
    if (path == "/api/docs" || path == "/api/docs/") && method == Method::GET {
        if !weissman_core::tls_policy::is_production_environment() {
            return next.run(request).await;
        }
    }
    if path == "/api/auth/signup" && method == Method::POST {
        return next.run(request).await;
    }
    if path == "/api/auth/verify" && method == Method::GET {
        return next.run(request).await;
    }
    if path == "/api/v1/alerts/aws-canary" && method == Method::POST {
        return next.run(request).await;
    }
    if path == "/api/agents/enroll" && method == Method::POST {
        return next.run(request).await;
    }
    if path.starts_with("/api/") || path.starts_with("/ws/") {
        let extracted = extract_token_from_request(&request, path);
        if let Some((t, source)) = extracted {
            if let Some(mut ctx) = verify_token_for_request(&t, path, source) {
                if auth_jwt::is_user_access_context(&ctx) {
                    let Some(ref jti) = ctx.jti else {
                        tracing::debug!(
                            target: "auth_guard",
                            path = %path,
                            "Access token missing jti — re-login required"
                        );
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({
                                "detail": "Token missing jti; re-login required",
                                "ok": false,
                                "code": "token_missing_jti",
                            })),
                        )
                            .into_response();
                    };
                    match crate::auth_refresh::is_access_jti_revoked(state.auth_pool.as_ref(), jti)
                        .await
                    {
                        Ok(true) => {
                            tracing::debug!(
                                target: "auth_guard",
                                path = %path,
                                "Access token jti revoked"
                            );
                            return (
                                StatusCode::UNAUTHORIZED,
                                Json(json!({"detail": "Unauthorized", "ok": false})),
                            )
                                .into_response();
                        }
                        Ok(false) => {}
                        Err(e) => {
                            tracing::error!(
                                target: "auth_guard",
                                error = %e,
                                "revocation lookup failed"
                            );
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(json!({"detail": "Auth service unavailable", "ok": false})),
                            )
                                .into_response();
                        }
                    }
                    // Live RBAC revalidation: demoted/deactivated users lose privileges immediately.
                    ctx = match crate::auth_refresh::revalidate_auth_context(
                        state.auth_pool.as_ref(),
                        &ctx,
                    )
                    .await
                    {
                        Ok(Some(fresh)) => fresh,
                        Ok(None) => {
                            return (
                                StatusCode::UNAUTHORIZED,
                                Json(json!({
                                    "detail": "User inactive or removed",
                                    "ok": false,
                                    "code": "user_inactive",
                                })),
                            )
                                .into_response();
                        }
                        Err(e) => {
                            tracing::error!(
                                target: "auth_guard",
                                error = %e,
                                "RBAC revalidation failed"
                            );
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(json!({"detail": "Auth service unavailable", "ok": false})),
                            )
                                .into_response();
                        }
                    };
                }
                request.extensions_mut().insert(ctx);
                return next.run(request).await;
            }
            // Token was provided but validation failed
            tracing::debug!(
                target: "auth_guard",
                path = %path,
                method = %method,
                token_source = ?source,
                "JWT token validation failed for request"
            );
        } else {
            // No token found at all
            tracing::debug!(
                target: "auth_guard",
                path = %path,
                method = %method,
                "No auth token found in request (cookie or Authorization header; query only on SSE/agent WS)"
            );
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"detail": "Unauthorized", "ok": false})),
        )
            .into_response();
    }
    next.run(request).await
}

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    password: String,
    #[serde(default = "default_tenant_slug")]
    tenant_slug: String,
}

fn default_tenant_slug() -> String {
    "default".to_string()
}

async fn default_tenant_id(auth_pool: &PgPool) -> Option<i64> {
    sqlx::query_scalar::<_, i64>(
        "SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1",
    )
    .fetch_optional(auth_pool)
    .await
    .ok()
    .flatten()
}

/// Read PoE job from DB (RLS-scoped). Returns None if not found.
async fn poe_job_from_db(pool: &PgPool, tenant_id: i64, job_id: &str) -> Option<PoEJobState> {
    let mut tx = db::begin_tenant_tx(pool, tenant_id).await.ok()?;
    let row = sqlx::query(
        "SELECT job_id, status, run_id, message, error, COALESCE(findings_json,'[]') FROM poe_jobs WHERE job_id = $1",
    )
    .bind(job_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()??;
    let _ = tx.commit().await;
    let findings_json: String = row.try_get("findings_json").ok()?;
    let findings_count = serde_json::from_str::<Vec<Value>>(&findings_json)
        .map(|v| v.len())
        .unwrap_or(0);
    Some(PoEJobState {
        job_id: row.try_get("job_id").ok()?,
        status: row.try_get("status").ok()?,
        run_id: row.try_get("run_id").ok()?,
        findings_count: Some(findings_count),
        message: row.try_get("message").ok()?,
        error: row.try_get("error").ok()?,
    })
}

async fn poe_job_json_from_db(pool: &PgPool, tenant_id: i64, job_id: &str) -> Option<String> {
    poe_job_from_db(pool, tenant_id, job_id)
        .await
        .map(|s| serde_json::to_string(&s).unwrap_or_default())
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Redirect to the canonical, most up-to-date dashboard: Command Center (React) at /command-center/.
/// That is the only full UI (Globe, CyberRadar, CommandBar, System Core, Memory Lab, Zero-Day Radar, etc.).
async fn redirect_to_command_center() -> Redirect {
    Redirect::to("/command-center/")
}

/// Serves the React SPA index.html for any /command-center/* path so client-side routing works.
async fn command_center_spa_index(Extension(html): Extension<String>) -> Html<String> {
    Html(html)
}

/// Dashboard page at / : stats + findings table + clients table (default tenant, legacy HTML view).
async fn dashboard_page(State(state): State<Arc<AppState>>) -> Response {
    let (vulns, client_count, score, findings_rows, clients_rows) = match default_tenant_id(
        &state.auth_pool,
    )
    .await
    {
        Some(tid) => match db::begin_tenant_tx(&state.app_pool, tid).await {
            Ok(mut tx) => {
                let v: i64 =
                    sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM vulnerabilities")
                        .fetch_one(&mut *tx)
                        .await
                        .unwrap_or(0);
                let c: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM clients")
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap_or(0);
                let s: i64 = sqlx::query_scalar::<_, String>(
                    "SELECT summary FROM report_runs ORDER BY created_at DESC LIMIT 1",
                )
                .fetch_optional(&mut *tx)
                .await
                .ok()
                .flatten()
                .and_then(|x| serde_json::from_str::<Value>(&x).ok())
                .and_then(|j| {
                    j.get("by_severity").and_then(|b| b.as_object()).map(|by| {
                        (100i64
                            - by.get("critical").and_then(Value::as_i64).unwrap_or(0) * 25
                            - by.get("high").and_then(Value::as_i64).unwrap_or(0) * 15
                            - by.get("medium").and_then(Value::as_i64).unwrap_or(0) * 5)
                            .max(0)
                    })
                })
                .unwrap_or(0);
                let findings_data = sqlx::query(
                    "SELECT id, title, severity, source, client_id::text, discovered_at FROM vulnerabilities ORDER BY discovered_at DESC LIMIT 50",
                )
                .fetch_all(&mut *tx)
                .await
                .unwrap_or_default();
                let mut findings_rows = String::new();
                for r in &findings_data {
                    let id: i64 = r.try_get("id").unwrap_or(0);
                    let title: String = r.try_get("title").unwrap_or_else(|_| "—".to_string());
                    let severity: String =
                        r.try_get("severity").unwrap_or_else(|_| "—".to_string());
                    let source: String = r.try_get("source").unwrap_or_else(|_| "—".to_string());
                    let client_id: String =
                        r.try_get("client_id").unwrap_or_else(|_| "—".to_string());
                    let discovered: chrono::DateTime<Utc> =
                        r.try_get("discovered_at").unwrap_or_else(|_| Utc::now());
                    let discovered_il =
                        utc_str_to_israel(&discovered.format("%Y-%m-%d %H:%M:%S").to_string());
                    findings_rows.push_str(&format!(
                        "<tr><td>VLN-{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"time-cell\">{}</td></tr>",
                        id,
                        escape_html(&title),
                        escape_html(&severity),
                        escape_html(&source),
                        escape_html(&client_id),
                        escape_html(&discovered_il),
                    ));
                }
                if findings_rows.is_empty() {
                    findings_rows =
                        "<tr><td colspan=\"6\">No findings. Data is live from DB.</td></tr>"
                            .to_string();
                }
                let last_rows = sqlx::query("SELECT client_id, MAX(discovered_at) AS mx FROM vulnerabilities GROUP BY client_id")
                    .fetch_all(&mut *tx)
                    .await
                    .unwrap_or_default();
                let mut last_scan: HashMap<i64, String> = HashMap::new();
                for r in last_rows {
                    if let (Ok(cid), Ok(dt)) = (
                        r.try_get::<i64, _>("client_id"),
                        r.try_get::<chrono::DateTime<Utc>, _>("mx"),
                    ) {
                        last_scan.insert(cid, dt.format("%Y-%m-%d %H:%M:%S").to_string());
                    }
                }
                let clients = sqlx::query("SELECT id, name, domains FROM clients ORDER BY id")
                    .fetch_all(&mut *tx)
                    .await
                    .unwrap_or_default();
                let mut clients_rows = String::new();
                for r in clients {
                    let id: i64 = r.try_get("id").unwrap_or(0);
                    let name: String = r.try_get("name").unwrap_or_else(|_| "—".to_string());
                    let domains: String = r.try_get("domains").unwrap_or_else(|_| "[]".to_string());
                    let dom_short = if domains.len() > 60 {
                        format!("{}…", &domains[..57])
                    } else {
                        domains.clone()
                    };
                    let last_il = last_scan
                        .get(&id)
                        .map(|s| utc_str_to_israel(s))
                        .unwrap_or_else(|| "—".to_string());
                    clients_rows.push_str(&format!(
                        r#"<tr><td>{}</td><td>{}</td><td class="domains-cell">{}</td><td class="time-cell">{}</td><td class="actions-cell"><a href="/command-center/report/{}" class="btn-sm btn-view">View</a> <a href="/command-center/attack-surface-graph/{}" class="btn-sm btn-graph">Graph</a> <a href="/command-center/semantic-logic/{}" class="btn-sm btn-logic">Logic</a> <a href="/command-center/timing-profiler/{}" class="btn-sm btn-timing">Timing</a> <a href="/command-center/ai-arena/{}" class="btn-sm btn-arena">Arena</a> <a href="/command-center/cicd-matrix/{}" class="btn-sm btn-pipeline">Pipeline</a> <a href="/command-center/memory-lab/{}" class="btn-sm btn-memorylab">Memory Lab</a> <a href="/api/clients/{}/report/pdf" class="btn-sm btn-pdf" download>PDF</a> <a href="/api/clients/{}/export/csv" class="btn-sm btn-excel" download>Excel</a></td></tr>"#,
                        id,
                        escape_html(&name),
                        escape_html(&dom_short),
                        escape_html(&last_il),
                        id,
                        id,
                        id,
                        id,
                        id,
                        id,
                        id,
                        id,
                        id,
                    ));
                }
                if clients_rows.is_empty() {
                    clients_rows =
                        r#"<tr><td colspan="5">No clients yet. Add one below.</td></tr>"#
                            .to_string();
                }
                let _ = tx.commit().await;
                (v, c, s, findings_rows, clients_rows)
            }
            Err(_) => (
                0,
                0,
                0,
                "<tr><td colspan=\"6\">DB unavailable.</td></tr>".to_string(),
                r#"<tr><td colspan="5">DB unavailable.</td></tr>"#.to_string(),
            ),
        },
        None => (
            0,
            0,
            0,
            "<tr><td colspan=\"6\">No default tenant.</td></tr>".to_string(),
            r#"<tr><td colspan="5">No default tenant.</td></tr>"#.to_string(),
        ),
    };
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Weissman Dashboard</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: linear-gradient(135deg, #0a0e17 0%, #0f172a 50%, #0c1222 100%); color: #e2e8f0; margin: 0; min-height: 100vh; padding: 0; }}
    .layout {{ max-width: 1400px; margin: 0 auto; padding: 1.5rem 2rem 3rem; }}
    .topbar {{ display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; margin-bottom: 2rem; padding: 1rem 1.5rem; background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(12px); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 12px; }}
    .topbar h1 {{ margin: 0; font-size: 1.5rem; font-weight: 700; color: #38bdf8; letter-spacing: 0.02em; }}
    .topbar .tagline {{ color: #94a3b8; font-size: 0.85rem; margin-top: 0.2rem; }}
    a.btn {{ display: inline-block; background: linear-gradient(180deg, #0ea5e9, #0284c7); color: #fff; padding: 0.6rem 1.2rem; border-radius: 8px; text-decoration: none; font-weight: 600; margin-left: 0.5rem; border: 1px solid rgba(255,255,255,0.1); }}
    a.btn:hover {{ background: #0284c7; box-shadow: 0 0 12px rgba(56, 189, 248, 0.3); }}
    a.cmd {{ background: linear-gradient(180deg, #10b981, #059669); }}
    a.cmd:hover {{ background: #059669; box-shadow: 0 0 12px rgba(16, 185, 129, 0.3); }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .card {{ background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(8px); border: 1px solid rgba(51, 65, 85, 0.8); border-radius: 10px; padding: 1.25rem; }}
    .card .val {{ font-size: 1.75rem; font-weight: 700; color: #38bdf8; }}
    .card .label {{ font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
    .panel {{ background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(10px); border: 1px solid rgba(51, 65, 85, 0.8); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
    .panel h2 {{ color: #94a3b8; font-size: 0.95rem; font-weight: 600; margin: 0 0 1rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 0.65rem 0.85rem; text-align: left; border-bottom: 1px solid rgba(51, 65, 85, 0.6); }}
    th {{ background: rgba(15, 23, 42, 0.9); color: #38bdf8; font-weight: 600; font-size: 0.8rem; }}
    .domains-cell {{ max-width: 280px; word-break: break-all; font-size: 0.9rem; }}
    .actions-cell {{ white-space: nowrap; }}
    a.btn-sm {{ display: inline-block; padding: 0.35rem 0.65rem; border-radius: 6px; font-size: 0.8rem; font-weight: 600; text-decoration: none; margin-right: 0.35rem; }}
    a.btn-pdf {{ background: #dc2626; color: #fff; border: 1px solid rgba(255,255,255,0.2); }}
    a.btn-pdf:hover {{ background: #b91c1c; }}
    a.btn-excel {{ background: #16a34a; color: #fff; border: 1px solid rgba(255,255,255,0.2); }}
    a.btn-excel:hover {{ background: #15803d; }}
    a.btn-view {{ background: #0ea5e9; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; }}
    a.btn-view:hover {{ background: #0284c7; }}
    a.btn-graph {{ background: #6366f1; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; margin-left: 4px; }}
    a.btn-graph:hover {{ background: #4f46e5; }}
    a.btn-logic {{ background: #0d9488; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; margin-left: 4px; }}
    a.btn-logic:hover {{ background: #0f766e; }}
    a.btn-timing {{ background: #b45309; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; margin-left: 4px; }}
    a.btn-timing:hover {{ background: #d97706; }}
    a.btn-arena {{ background: #be185d; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; margin-left: 4px; }}
    a.btn-arena:hover {{ background: #9d174d; }}
    a.btn-pipeline {{ background: #0d9488; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; margin-left: 4px; }}
    a.btn-pipeline:hover {{ background: #0f766e; }}
    a.btn-memorylab {{ background: #7c3aed; color: #fff; border: 1px solid rgba(255,255,255,0.2); text-decoration: none; margin-left: 4px; }}
    a.btn-memorylab:hover {{ background: #6d28d9; }}
    .control-row {{ display: flex; align-items: center; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }}
    .control-row button {{ padding: 0.6rem 1.2rem; border-radius: 8px; font-weight: 600; cursor: pointer; border: none; font-size: 0.9rem; }}
    .control-row .btn-start {{ background: #10b981; color: #fff; }}
    .control-row .btn-stop {{ background: #dc2626; color: #fff; }}
    .control-row .status {{ padding: 0.4rem 0.8rem; border-radius: 6px; font-size: 0.85rem; font-weight: 500; }}
    .control-row .status.active {{ background: rgba(16, 185, 129, 0.2); color: #34d399; }}
    .control-row .status.inactive {{ background: rgba(100, 116, 139, 0.3); color: #94a3b8; }}
    .control-row .btn-runall {{ background: #7c3aed; color: #fff; }}
    .control-row .btn-runall:hover {{ background: #6d28d9; }}
    .control-desc {{ margin: 0; font-size: 0.8rem; color: #64748b; }}
    .time-cell {{ font-size: 0.85rem; color: #94a3b8; white-space: nowrap; }}
    .add-form {{ display: grid; grid-template-columns: 1fr 1fr auto; gap: 0.75rem; align-items: end; margin-top: 1rem; }}
    .add-form input {{ padding: 0.5rem 0.75rem; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0; font-size: 0.9rem; }}
    .add-form button {{ padding: 0.5rem 1rem; background: #0ea5e9; color: #fff; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; }}
  </style>
</head>
<body>
    <div class="layout">
    <header class="topbar">
      <div>
        <h1>WEISSMAN CYBERSECURITY</h1>
        <p class="tagline">Command Center — live data only (no dummy, no fake)</p>
      </div>
      <div>
        <a href="/" class="btn">Dashboard</a>
        <a href="/command-center/" class="btn cmd">Open War Room</a>
      </div>
    </header>
    <div style="background:#1e3a5f;color:#93c5fd;padding:10px 16px;margin:0 0 16px;border-radius:8px;text-align:center;">
      <strong>Legacy view.</strong> Full dashboard (Globe, Radar, Memory Lab, System Core, Zero-Day Radar): 
      <a href="/command-center/" style="color:#67e8f9;font-weight:bold;margin-left:6px;">→ Open Command Center</a>
    </div>
    <div class="cards">
      <div class="card"><span class="val">{vulns}</span><br/><span class="label">Vulnerabilities</span></div>
      <div class="card"><span class="val">{client_count}</span><br/><span class="label">Clients</span></div>
      <div class="card"><span class="val">{score}</span><br/><span class="label">Security Score</span></div>
    </div>
    <div class="panel">
      <h2>Global scan control</h2>
      <div class="control-row">
        <button type="button" class="btn-start" id="scanStart">Start continuous scan</button>
        <button type="button" class="btn-stop" id="scanStop">Stop scan</button>
        <button type="button" class="btn-runall" id="scanRunAll">Run full scan now (all clients, all 5 engines)</button>
        <span class="status inactive" id="scanStatus">—</span>
      </div>
      <p class="control-desc">Scans use client domains from the table below. No manual target needed. Engines: OSINT, ASM, Supply Chain, BOLA/IDOR, AI Fuzz.</p>
    </div>
    <div class="panel">
      <h2>Clients (live from DB)</h2>
      <table><thead><tr><th>ID</th><th>Name</th><th>Domains</th><th>Last scan (Israel)</th><th>Actions</th></tr></thead><tbody>{clients_rows}</tbody></table>
      <h2 style="margin-top: 1.5rem;">Add client</h2>
      <form class="add-form" id="addClientForm">
        <input type="text" name="name" placeholder="Company name" required />
        <input type="text" name="domains" placeholder='Domains JSON e.g. ["example.com"]' />
        <button type="submit">Add</button>
      </form>
    </div>
    <div class="panel">
      <h2>Recent findings (live from DB)</h2>
      <table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Source</th><th>Client</th><th>Discovered (Israel)</th></tr></thead><tbody>{findings_rows}</tbody></table>
    </div>
  </div>
  <script>
    (function() {{
      function setStatus(active) {{
        var el = document.getElementById('scanStatus');
        el.textContent = active ? 'Scanning active' : 'Stopped';
        el.className = 'status ' + (active ? 'active' : 'inactive');
      }}
      fetch('/api/scan/status').then(function(r) {{ return r.json(); }}).then(function(d) {{ setStatus(d.scanning_active); }}).catch(function() {{ setStatus(false); }});
      document.getElementById('scanStart').onclick = function() {{
        fetch('/api/scan/start', {{ method: 'POST' }}).then(function() {{ setStatus(true); }});
      }};
      document.getElementById('scanStop').onclick = function() {{
        fetch('/api/scan/stop', {{ method: 'POST' }}).then(function() {{ setStatus(false); }});
      }};
      document.getElementById('scanRunAll').onclick = function() {{
        var btn = this;
        btn.disabled = true;
        fetch('/api/scan/run-all', {{ method: 'POST' }}).then(function(r) {{ return r.json(); }}).then(function() {{ btn.disabled = false; setStatus(true); setTimeout(function() {{ location.reload(); }}, 3000); }}).catch(function() {{ btn.disabled = false; }});
      }};
      document.getElementById('addClientForm').onsubmit = function(e) {{
        e.preventDefault();
        var name = this.name.value.trim();
        var domains = this.domains.value.trim() || '[]';
        if (!name) return;
        fetch('/api/clients', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ name: name, domains: domains }})
        }}).then(function(r) {{ return r.json(); }}).then(function(d) {{ if (d.ok) location.reload(); }});
      }};
    }})();
  </script>
</body>
</html>"##,
        vulns = vulns,
        client_count = client_count,
        score = score,
        findings_rows = findings_rows,
        clients_rows = clients_rows,
    );
    Html(html).into_response()
}

/// Normalize internal telemetry JSON to Command Center `{ kind, payload, ts }` shape.
fn normalize_cc_event(raw: &str) -> Option<String> {
    let v: Value = serde_json::from_str(raw).ok()?;
    if v.get("kind").is_some() {
        return Some(raw.to_string());
    }
    let ts = chrono::Utc::now().timestamp_millis();
    if let Some(event) = v.get("event").and_then(Value::as_str) {
        let kind = match event {
            "finding_created" => {
                let sev = v
                    .get("severity")
                    .and_then(Value::as_str)
                    .unwrap_or("info")
                    .to_ascii_lowercase();
                if sev == "critical" || sev == "high" {
                    "critical_cve"
                } else {
                    "scan_pulse"
                }
            }
            "new_target" => "new_source_discovered",
            "progress" => "scan_pulse",
            "engine_error" | "error" => "emergency_alert",
            _ => "audit",
        };
        let payload = if event == "finding_created" {
            json!({
                "message": format!(
                    "Finding: {}",
                    v.get("title").and_then(Value::as_str).unwrap_or("—")
                ),
                "severity": v.get("severity").cloned().unwrap_or(json!("info")),
                "client_id": v.get("client_id").cloned().unwrap_or(Value::Null),
                "target": v.get("client_id").cloned().unwrap_or(Value::Null),
                "finding_id": v.get("finding_id").cloned().unwrap_or(Value::Null),
            })
        } else {
            v.clone()
        };
        return Some(json!({ "kind": kind, "payload": payload, "ts": ts }).to_string());
    }
    if v.get("message").is_some() || v.get("job_id").is_some() {
        let msg = v
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("job update");
        return Some(
            json!({
                "kind": "audit",
                "payload": {
                    "action": msg,
                    "message": msg,
                    "severity": v.get("status").and_then(Value::as_str).unwrap_or("info"),
                    "job_id": v.get("job_id").cloned().unwrap_or(Value::Null),
                },
                "ts": ts,
            })
            .to_string(),
        );
    }
    None
}

/// WebSocket: init handshake + live telemetry stream for Command Center.
async fn ws_command_center(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let pool = state.app_pool.clone();
    let telemetry = state.telemetry_broadcast_tx.clone();
    let tenant_id = auth.tenant_id;
    ws.on_upgrade(move |socket| async move {
        handle_ws_command_center(socket, pool, tenant_id, telemetry).await;
    })
}

async fn handle_ws_command_center(
    mut socket: WebSocket,
    pool: Arc<PgPool>,
    tenant_id: i64,
    telemetry: Arc<tokio::sync::broadcast::Sender<String>>,
) {
    let Ok(mut tx) = db::begin_tenant_tx(pool.as_ref(), tenant_id).await else {
        return;
    };
    let vuln_count: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM vulnerabilities")
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0);
    let client_count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM clients")
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);
    let score: i64 = sqlx::query_scalar::<_, String>(
        "SELECT summary FROM report_runs ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
    .and_then(|j| {
        j.get("by_severity").and_then(|b| b.as_object()).map(|by| {
            (100i64
                - by.get("critical").and_then(Value::as_i64).unwrap_or(0) * 25
                - by.get("high").and_then(Value::as_i64).unwrap_or(0) * 15
                - by.get("medium").and_then(Value::as_i64).unwrap_or(0) * 5)
                .max(0)
        })
    })
    .unwrap_or(0);
    let _ = tx.commit().await;
    let globe = json!({
        "scanPulses": [],
        "criticalVulns": [],
        "intelNodes": [{ "lat": 37.77, "lon": -122.42 }, { "lat": 52.52, "lon": 13.4 }],
    });
    let score_payload = json!({
        "security_score": score,
        "total_vulnerabilities": vuln_count,
        "assets_monitored": client_count,
    });
    let score_payload_ticker = score_payload.clone();
    let init = json!({ "type": "init", "globe": globe, "score": score_payload });
    if let Ok(s) = serde_json::to_string(&init) {
        let _ = socket.send(Message::Text(s)).await;
    }

    let mut rx = telemetry.subscribe();
    let mut ticker = tokio::time::interval(Duration::from_secs(15));

    loop {
        tokio::select! {
            inbound = socket.recv() => {
                match inbound {
                    None => break,
                    Some(Ok(Message::Text(text))) => {
                        if text.contains("\"type\":\"ping\"") || text.contains("\"ping\"") {
                            let _ = socket.send(Message::Text(json!({"type":"pong"}).to_string())).await;
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = socket.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Close(_))) => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
            telemetry_msg = rx.recv() => {
                if let Ok(raw) = telemetry_msg {
                    if let Some(normalized) = normalize_cc_event(&raw) {
                        if socket.send(Message::Text(normalized)).await.is_err() {
                            break;
                        }
                    }
                }
            }
            _ = ticker.tick() => {
                let Ok(mut tx) = db::begin_tenant_tx(pool.as_ref(), tenant_id).await else { continue; };
                let row = sqlx::query(
                    "SELECT id, title, severity, client_id::text AS client_id FROM vulnerabilities ORDER BY discovered_at DESC LIMIT 1",
                )
                .fetch_optional(&mut *tx)
                .await
                .ok()
                .flatten();
                let _ = tx.commit().await;
                if let Some(r) = row {
                    let title: String = r.try_get("title").unwrap_or_default();
                    let severity: String = r.try_get("severity").unwrap_or_else(|_| "info".into());
                    let client_id: String = r.try_get("client_id").unwrap_or_else(|_| "—".into());
                    let kind = if severity == "critical" || severity == "high" { "critical_cve" } else { "scan_pulse" };
                    let pulse = json!({
                        "type": "refresh",
                        "kind": kind,
                        "payload": {
                            "message": title,
                            "severity": severity,
                            "target": client_id,
                            "client_id": client_id,
                        },
                        "score": score_payload_ticker,
                    });
                    if let Ok(s) = serde_json::to_string(&pulse) {
                        let _ = socket.send(Message::Text(s)).await;
                    }
                }
            }
        }
    }
}

/// Ticker events for Command Center (live from DB — recent findings as events).
async fn api_command_center_ticker(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::OK, Json(json!({ "events": [] }))).into_response();
    };
    let rows = sqlx::query(
        "SELECT id, title, severity, source, client_id::text, discovered_at FROM vulnerabilities ORDER BY discovered_at DESC LIMIT 100",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let mut events = vec![];
    for r in rows {
        let discovered: chrono::DateTime<Utc> =
            r.try_get("discovered_at").unwrap_or_else(|_| Utc::now());
        let ds = discovered.format("%Y-%m-%d %H:%M:%S").to_string();
        let time = if ds.len() >= 19 {
            ds[11..19].to_string()
        } else {
            "00:00:00".to_string()
        };
        events.push(serde_json::json!({
            "id": format!("ev-{}", r.try_get::<i64, _>("id").unwrap_or(0)),
            "time": time,
            "target": r.try_get::<String, _>("client_id").unwrap_or_else(|_| "—".to_string()),
            "target_ip": "—",
            "agentId": "Discovery",
            "severity": r.try_get::<String, _>("severity").unwrap_or_else(|_| "info".to_string()),
            "message": r.try_get::<String, _>("title").unwrap_or_else(|_| "Finding".to_string()),
        }));
    }
    (StatusCode::OK, Json(json!({ "events": events }))).into_response()
}

#[derive(Deserialize)]
struct EnterpriseSettingsPatch {
    global_safe_mode: Option<bool>,
    alert_webhook_url: Option<String>,
}

#[derive(Deserialize)]
struct ClientBody {
    name: Option<String>,
    domains: Option<String>,
    tech_stack: Option<String>,
    ip_ranges: Option<String>,
    contact_email: Option<String>,
    #[serde(default)]
    auto_detect_tech_stack: Option<bool>,
    aws_cross_account_role_arn: Option<String>,
    aws_external_id: Option<String>,
    gcp_project_id: Option<String>,
    /// Engagement modules (baseline_asm, cloud_aws, endpoint_agent, …) stored in client_configs.
    engagement_modules: Option<Vec<String>>,
    /// Nested onboarding payload merged into client_configs.onboarding.
    onboarding: Option<Value>,
}

#[derive(Deserialize)]
struct ClientConfigBody {
    enabled_engines: Option<Vec<String>>,
    roe_mode: Option<String>,
    stealth_level: Option<u8>,
    auto_harvest: Option<bool>,
    /// When true, orchestrator runs passive Modbus/ENIP/S7 probes against domains + ip_ranges only.
    industrial_ot_enabled: Option<bool>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct TimingScanRunBody {
    target: Option<String>,
    client_id: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AiRedteamRunBody {
    target: Option<String>,
    client_id: Option<String>,
    ai_endpoint: Option<String>,
}

#[derive(Deserialize)]
struct PipelineScanRunBody {
    client_id: String,
    repo_url: String,
}

#[derive(Deserialize)]
struct PoEScanRunBody {
    client_id: String,
    target_url: String,
}

#[derive(Deserialize)]
struct LatencyProbeBody {
    url: String,
}

#[derive(Deserialize)]
struct DeepFuzzBody {
    target: Option<String>,
    #[serde(default)]
    client_id: Option<i64>,
    /// Optional paths from a prior ASM / General pass for semantic fuzz seeding.
    #[serde(default)]
    discovered_paths: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct GeneralMissionBody {
    domain: Option<String>,
    #[serde(default)]
    client_id: Option<i64>,
}

/// POST /api/council/debate — enqueues `council_debate` async job (Alpha → Beta → Gamma; optional OAST self-correction).
#[derive(Deserialize)]
struct CouncilDebateBody {
    /// Authorized target / mission brief for the council.
    target_brief: Option<String>,
    #[serde(default)]
    client_id: Option<i64>,
    /// Seed self-correction (e.g. prior listener miss) before the first round.
    #[serde(default)]
    failure_log: Option<String>,
    /// When true, re-run full council until `verify_oob_token_seen` succeeds or rounds exhausted.
    #[serde(default)]
    verify_oob: Option<bool>,
    /// Weissman Supreme Council: Proposer ∥ Critic, Sovereign General, optional phased CPU affinity + semantic memory.
    #[serde(default)]
    supreme: Option<bool>,
    /// Supreme Command Protocol: phased `process_mission` + signed `COUNCIL_DEBATE` audit rows.
    #[serde(default)]
    supreme_command_protocol: Option<bool>,
    #[serde(default)]
    max_council_rounds: Option<u32>,
    #[serde(default)]
    fallback_oast_token: Option<String>,
}

#[derive(Deserialize)]
struct PipelineStateQuery {
    run_id: i64,
    client_id: String,
}

/// Legacy shape for POST /api/system/configs: `[{ "key", "value" }]`. The handler also accepts `{ "configs": { ... } }`.
#[derive(Deserialize)]
#[allow(dead_code)]
struct SystemConfigBody {
    key: String,
    value: String,
}

#[derive(Deserialize)]
struct IdentityContextBody {
    role_name: String,
    #[serde(default)]
    privilege_order: i32,
    #[serde(default = "default_token_type")]
    token_type: String,
    token_value: String,
}

fn default_token_type() -> String {
    "bearer".to_string()
}

#[derive(Deserialize)]
struct PipelineStatePatchBody {
    run_id: Option<i64>,
    client_id: String,
    paused: Option<bool>,
    skip_to_stage: Option<i32>,
}

#[derive(Deserialize)]
struct RuntimeTraceBody {
    run_id: Option<i64>,
    finding_id: Option<String>,
    trace_id: Option<String>,
    source_file: Option<String>,
    line_number: Option<i32>,
    function_name: Option<String>,
    payload_hash: Option<String>,
    metadata: Option<Value>,
}

#[derive(Deserialize)]
struct AutoHealBody {
    finding_id: String,
    git_token: Option<String>,
    repo_slug: Option<String>,
    base_branch: Option<String>,
    docker_socket: Option<String>,
    image: Option<String>,
    container_port: Option<u16>,
    poc_exploit: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct DeceptionGenerateBody {
    types: Option<Vec<String>>,
    tech_hint: Option<String>,
    aws_access_key_id: Option<String>,
    aws_secret_access_key: Option<String>,
    aws_region: Option<String>,
    /// When true, mint a real deny-all IAM user + access key in the control-plane account (default chain).
    #[serde(default)]
    real_aws_canary: Option<bool>,
    /// When false, skip vLLM and use a template decoy (keys still real if `real_aws_canary`).
    #[serde(default)]
    use_llm_decoy: Option<bool>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SovereignPhantomBody {
    /// Target fingerprint / scan summary JSON for vLLM classification.
    fingerprint: serde_json::Value,
}

#[derive(Deserialize)]
struct DeceptionTriggeredBody {
    asset_id: Option<i64>,
    /// Accepted from deception webhooks for forward compatibility (not yet used server-side).
    #[allow(dead_code)]
    token_value: Option<String>,
    fingerprint: Option<String>,
    request_meta: Option<Value>,
}

#[derive(Deserialize, Serialize)]
struct DeceptionDeployCloudBody {
    asset_ids: Vec<i64>,
    s3_bucket: Option<String>,
    s3_object_key: Option<String>,
    s3_region: Option<String>,
    ssm_parameter_path: Option<String>,
}

const DEFAULT_CLIENT_CONFIGS_JSON: &str = r#"{"enabled_engines":["osint","asm","supply_chain","bola_idor","llm_path_fuzz","semantic_ai_fuzz","microsecond_timing","ai_adversarial_redteam","nexus_sovereign_swarm"],"roe_mode":"safe_proofs","stealth_level":50,"industrial_ot_enabled":false}"#;

// Handlers: see `handler_fragments.rs` (single wiring point for all `.inc` fragments).
include!("handler_fragments.rs");

pub fn new_app_state(
    app_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
) -> Arc<AppState> {
    // Optional read-only pool for /api/ask. Falls back to None if the env var
    // isn't set — endpoint will then return 503 with a clear "configure this" hint.
    let read_only_pool: Option<Arc<PgPool>> = match std::env::var("WEISSMAN_READ_ONLY_DATABASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        Some(url) => match sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_lazy(&url)
        {
            Ok(p) => Some(Arc::new(p)),
            Err(e) => {
                tracing::warn!(target: "nl_query", error = %e, "read-only pool init failed");
                None
            }
        },
        None => None,
    };
    let (timing_tx, _) = tokio::sync::broadcast::channel::<String>(256);
    let (redteam_tx, _) = tokio::sync::broadcast::channel::<String>(256);
    let (radar_tx, _) = tokio::sync::broadcast::channel::<String>(256);
    let (poe_updates_tx, poe_updates_rx) =
        flume::bounded::<(String, String)>(POE_UPDATES_CHANNEL_CAPACITY);
    let poe_job_registry: PoeJobRegistry = Arc::new(DashMap::new());
    let registry_clone = poe_job_registry.clone();
    tokio::spawn(async move {
        while let Ok((job_id, json)) = poe_updates_rx.recv_async().await {
            // Prune disconnected SSE subscribers as we forward. If no subscribers remain
            // for this job_id after pruning, drop the map entry too — otherwise the
            // DashMap accumulates one orphan key per scan forever (slow leak).
            let drop_key = {
                let Some(mut senders) = registry_clone.get_mut(&job_id) else {
                    continue;
                };
                senders.retain(|tx| match tx.try_send(json.clone()) {
                    Ok(()) => true,
                    Err(TrySendError::Disconnected(_)) => false,
                    Err(TrySendError::Full(_)) => true,
                });
                senders.is_empty()
            };
            if drop_key {
                registry_clone.remove(&job_id);
            }
        }
    });
    let (telemetry_tx, _) = tokio::sync::broadcast::channel::<String>(TELEMETRY_BROADCAST_CAPACITY);
    let telemetry_broadcast_tx = Arc::new(telemetry_tx);
    let edge_heartbeat_batcher =
        crate::edge_heartbeat_batch::spawn(app_pool.clone(), Some(telemetry_broadcast_tx.clone()));
    let (swarm_tx, _) = tokio::sync::broadcast::channel::<String>(512);
    let mpsc_cap = std::env::var("WEISSMAN_SOVEREIGN_MPSC_CAPACITY")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0);
    let (sovereign_swarm_tx, sovereign_swarm_rx) = match mpsc_cap {
        Some(cap) => {
            let (tx, rx) = tokio::sync::mpsc::channel(cap);
            (Some(Arc::new(tx)), std::sync::Mutex::new(Some(rx)))
        }
        None => (None, std::sync::Mutex::new(None)),
    };
    Arc::new(AppState {
        app_pool,
        intel_pool,
        auth_pool,
        read_only_pool,
        started_at: Instant::now(),
        timing_broadcast_tx: Arc::new(timing_tx),
        redteam_broadcast_tx: Arc::new(redteam_tx),
        radar_broadcast_tx: Arc::new(radar_tx),
        poe_job_registry,
        poe_job_updates_tx: poe_updates_tx,
        telemetry_broadcast_tx,
        swarm_broadcast_tx: Arc::new(swarm_tx),
        edge_heartbeat_batcher,
        sovereign_swarm_tx,
        sovereign_swarm_rx,
        endpoint_agents: crate::endpoint_agents::AgentRegistry::global(),
    })
}

pub fn spawn_http_background_tasks(state: &Arc<AppState>) {
    let app_pool = state.app_pool.clone();
    let intel_pool = state.intel_pool.clone();
    let auth_pool = state.auth_pool.clone();
    // Leader election: only ONE replica runs the singleton workers (scan cycles,
    // backups, cron, intel refresh). Holds a Postgres session advisory lock for its
    // lifetime; followers skip those loops so multi-replica deploys don't duplicate work.
    let is_leader = crate::leader_election::acquire_singleton_leadership_blocking();
    if is_leader {
        tracing::info!(target: "leader", "this replica holds singleton-worker leadership");
    } else {
        tracing::info!(target: "leader", "another replica is leader — skipping scan/backup/cron/intel loops");
    }
    crate::endpoint_agents::spawn_pending_task_pusher(
        app_pool.clone(),
        state.endpoint_agents.clone(),
    );
    if is_leader {
        crate::endpoint_agents::spawn_ueba_baseline_scheduler(
            app_pool.clone(),
            state.endpoint_agents.clone(),
        );
    }
    crate::agent_registry_sync::spawn_agent_registry_redis_sync(state.endpoint_agents.clone());
    // Cross-replica real-time: bridge the live telemetry broadcast over Redis pub/sub so
    // SSE/WS clients on every replica see events produced on any replica (no-op without REDIS_URL).
    crate::telemetry_bus::spawn_bridge("telemetry", (*state.telemetry_broadcast_tx).clone());
    crate::telemetry_bus::spawn_bridge("swarm", (*state.swarm_broadcast_tx).clone());
    crate::observability::register_llm_tenant_metering(app_pool.clone());
    crate::observability::spawn_pool_metrics_loop(
        app_pool.clone(),
        auth_pool.clone(),
        intel_pool.clone(),
    );
    if is_leader {
        crate::db_backup::spawn_database_backup_scheduler(auth_pool.clone(), app_pool.clone());
    }
    crate::server_db::init_db(std::path::Path::new("."));
    crate::orchestrator::spawn_orchestrator(
        app_pool.clone(),
        intel_pool.clone(),
        auth_pool.clone(),
        Some(state.telemetry_broadcast_tx.clone()),
    );
    // Enable orchestrator scanning by default (disable with WEISSMAN_SCANNING_ENABLED=0).
    // Leader-only: followers spawn the orchestrator but never run scan cycles.
    if is_leader
        && !matches!(
            std::env::var("WEISSMAN_SCANNING_ENABLED").as_deref(),
            Ok("0") | Ok("false") | Ok("no")
        )
    {
        crate::orchestrator::set_scanning_active(true);
        tracing::info!(target: "orchestrator", "Scanning enabled at boot (leader)");
    }
    let auth_pool_boot = auth_pool.clone();
    let app_pool_boot = app_pool.clone();
    tokio::spawn(async move {
        crate::auth_bootstrap::sync_admin_credentials(app_pool_boot.as_ref()).await;
        let _ = auth_pool_boot; // keep auth pool warm for future bootstrap hooks
    });
    // ── Singleton workers — leader replica only ────────────────────────────────
    if is_leader {
        tokio::spawn(crate::payload_sync_worker::run_worker_loop(
            app_pool.clone(),
            intel_pool.clone(),
            auth_pool.clone(),
        ));
        crate::redteam_background_worker::spawn_cron_worker(
            app_pool.clone(),
            auth_pool.clone(),
            state.telemetry_broadcast_tx.clone(),
        );
        crate::scan_schedule_worker::spawn_scan_schedule_worker(
            app_pool.clone(),
            auth_pool.clone(),
        );
        crate::alert_evaluator_worker::spawn_alert_evaluator_worker(
            app_pool.clone(),
            auth_pool.clone(),
        );
        crate::threat_intel_ingestor::spawn_ingest_worker(
            app_pool.clone(),
            intel_pool.clone(),
            auth_pool.clone(),
            state.telemetry_broadcast_tx.clone(),
        );
        crate::data_retention::spawn_data_retention_loop(app_pool.clone(), intel_pool.clone());
        crate::async_jobs::spawn_stale_lock_reclaim_loop(app_pool.clone());
        // Threat-intel mirrors (CISA KEV + FIRST EPSS). Both are best-effort, idempotent,
        // and gated by env vars so dev/offline runs can skip outbound HTTP.
        crate::intel_kev::bootstrap_kev_catalog(app_pool.clone());
        crate::intel_kev::spawn_kev_refresh_worker(app_pool.clone());
        crate::intel_epss::bootstrap_epss_backfill(app_pool.clone());
        crate::intel_epss::spawn_epss_backfill_worker(app_pool.clone());
        crate::intel_findings_backfill::bootstrap_findings_intel_backfill(app_pool.clone());
        // UEBA — purge old samples once an hour so the table stays bounded.
        crate::ueba_detector::spawn_retention_loop(app_pool.clone());
        crate::sovereign_self_scan::spawn_sovereign_self_scan_loop(
            app_pool.clone(),
            state.telemetry_broadcast_tx.clone(),
        );
        crate::predictive_analyzer::spawn_security_events_llm_loop(
            app_pool.clone(),
            state.telemetry_broadcast_tx.clone(),
        );
        crate::sovereign_c2::spawn_sovereign_stack(
            app_pool.clone(),
            state.telemetry_broadcast_tx.clone(),
            state.take_sovereign_swarm_rx(),
            state.sovereign_swarm_tx.clone(),
        );
    } // ── end singleton-leader workers ──────────────────────────────────────────
    if let Some(secs) = std::env::var("WEISSMAN_GENERAL_SELF_AUDIT_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        if secs > 0 && is_leader {
            if let Some(tid) = std::env::var("WEISSMAN_GENERAL_SELF_AUDIT_TENANT_ID")
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
            {
                let pool = app_pool.clone();
                tokio::spawn(async move {
                    let mut tick =
                        tokio::time::interval(std::time::Duration::from_secs(secs.max(600)));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        tick.tick().await;
                        let _ = crate::strategy_engine::run_self_defense_audit(
                            pool.as_ref(),
                            tid,
                            None,
                            "system_self_audit",
                            "127.0.0.1",
                        )
                        .await;
                    }
                });
            }
        }
    }
}

/// Builds the full Axum router (API, static Command Center, WebSockets).
///
/// CORS and global rate limiting are applied by the **`weissman-server`** binary only — this keeps
/// production policy in one place. Do not run a second HTTP entrypoint; use `weissman-server`.
pub async fn build_http_router(state: Arc<AppState>, static_dir: Option<PathBuf>) -> Router {
    crate::observability::init_prometheus_recorder();
    // Canonical dashboard = /command-center/ (React: Globe, Radar, Memory Lab, System Core, etc.).
    // When frontend/dist exists we redirect / and /dashboard there; /command-center is served by static_router (no duplicate route).
    let root_routes = if static_dir.is_some() {
        Router::new()
            .route("/", get(redirect_to_command_center))
            .route("/dashboard", get(redirect_to_command_center))
    } else if weissman_core::tls_policy::is_production_environment() {
        Router::new()
            .route("/", get(redirect_to_command_center))
            .route("/dashboard", get(redirect_to_command_center))
    } else {
        Router::new()
            .route("/", get(dashboard_page))
            .route("/dashboard", get(dashboard_page))
    };
    let api = root_routes
        .route("/ws/command-center", get(ws_command_center))
        .route("/api/dashboard/stats", get(api_dashboard_stats))
        .route("/api/dashboard/exec-kpis", get(api_dashboard_exec_kpis))
        .route("/api/findings", get(api_findings))
        .route("/api/findings/clusters", get(api_findings_clusters))
        .route("/api/findings/export/csv", get(api_findings_export_csv))
        .route("/api/export/findings", get(api_findings_export_csv))
        .route(
            "/api/findings/:id/status",
            patch(api_findings_update_status),
        )
        .route("/api/intel/status", get(api_intel_status))
        .route("/api/attack-coverage", get(api_attack_coverage))
        .route("/api/intel/suppressions", get(api_intel_suppressions))
        .route(
            "/api/intel/suppressions/:id",
            delete(api_intel_suppression_delete),
        )
        // Attack-path inference (BFS over risk_graph weighted by CVSS+EPSS+KEV).
        .route(
            "/api/attack-paths/:client_id",
            get(api_attack_paths_for_client),
        )
        // Unified threat analysis: attack-chain plan + multi-stage correlation over live findings.
        .route(
            "/api/threat-analysis/:client_id",
            get(api_threat_analysis_for_client),
        )
        .route(
            "/api/risk-graph/nodes/:node_id/flags",
            patch(api_risk_node_flags_patch),
        )
        // SOAR playbooks (DSL-driven automation; on-event dispatch + run history).
        .route(
            "/api/playbooks",
            get(api_playbooks_list).post(api_playbooks_create),
        )
        .route(
            "/api/playbooks/:id",
            patch(api_playbooks_update).delete(api_playbooks_delete),
        )
        .route("/api/playbooks/fire", post(api_playbooks_fire))
        .route("/api/playbooks/:id/runs", get(api_playbook_runs))
        // Financial blast-radius
        .route(
            "/api/financial-risk/:client_id",
            get(api_financial_risk_for_client),
        )
        .route(
            "/api/financial-risk/:client_id/apply-tags",
            post(api_apply_asset_tag_rules),
        )
        // Ask Weissman (NL → safe SQL)
        .route("/api/ask", post(api_ask))
        // UEBA + baseline/drift dashboard
        .route("/api/ueba/ingest", post(api_ueba_ingest))
        // NDR / ITDR live data ingest (feeds network beaconing/exfil + identity-threat detectors).
        .route("/api/ndr/flows", post(api_ndr_flows_ingest))
        .route("/api/itdr/auth-events", post(api_itdr_auth_ingest))
        .route("/api/ueba/anomalies", get(api_ueba_anomalies))
        .route("/api/baseline/summary", get(api_baseline_summary))
        .route("/api/baseline/drift", get(api_baseline_drift))
        .route("/api/baseline/anomalies", get(api_baseline_anomalies))
        .route("/api/config/public", get(api_config_public))
        .route("/api/engines/production", get(api_engines_production))
        .route("/api/engines/accounting", get(api_engines_accounting))
        .route("/api/engines/capabilities", get(api_engines_capabilities))
        .route("/api/engines/requirements", get(api_engines_requirements))
        .route("/api/onboarding/tenant-status", get(api_onboarding_tenant_status))
        .route(
            "/api/engines/nexus_sovereign_swarm/schema",
            get(api_nssi_config_schema),
        )
        .route("/api/engines/telemetry", get(api_engines_telemetry))
        .route("/api/openapi.json", get(api_openapi_spec))
        .route("/api/docs", get(crate::api_docs::api_docs_swagger))
        .route("/api/docs/", get(crate::api_docs::api_docs_swagger))
        .route("/api/auth/signup", post(crate::signup::api_signup))
        .route("/api/auth/verify", get(crate::signup::api_verify))
        .route("/api/reports", get(api_reports))
        .route("/api/command-center/scan", post(api_scan))
        .route(
            "/api/engines/top-tier/audit",
            get(api_engines_top_tier_audit),
        )
        .route(
            "/api/engines/top-tier/health-probe",
            post(api_top_tier_health_probe_start),
        )
        .route(
            "/api/engines/top-tier/:engine_id/history",
            get(api_top_tier_engine_history),
        )
        .route(
            "/api/engines/top-tier/:engine_id/export",
            get(api_top_tier_engine_export),
        )
        .route("/api/engines/history/:engine_id", get(api_engine_history))
        .route("/api/engines/export/:engine_id", get(api_engine_export))
        .route("/api/command-center/ticker", get(api_command_center_ticker))
        .route("/hooks/cicd/github", post(hook_cicd_github))
        .route("/hooks/cicd/gitlab", post(hook_cicd_gitlab))
        .route("/hooks/cicd/bitbucket", post(hook_cicd_bitbucket))
        .route("/hooks/cicd/scan", post(hook_cicd_generic))
        .route(
            "/api/metrics",
            get(crate::observability::api_prometheus_metrics_endpoint),
        )
        .route("/api/metrics/dashboard", get(api_metrics_dashboard))
        .route(
            "/api/rate-limits/status",
            get(crate::http::rate_limit_metrics::api_rate_limits_status),
        )
        .route(
            "/api/rate-limits/analytics",
            get(crate::http::rate_limit_metrics::api_rate_limits_analytics),
        )
        .route("/api/login", post(api_login))
        .route("/api/logout", post(api_logout))
        .route("/api/auth/refresh", post(api_auth_refresh))
        .route("/api/auth/mfa/verify", post(api_auth_mfa_verify))
        .route("/api/auth/mfa/setup", post(api_auth_mfa_setup))
        .route("/api/auth/mfa/enable", post(api_auth_mfa_enable))
        .route("/api/auth/mfa/disable", post(api_auth_mfa_disable))
        .route("/api/auth/mfa/status", get(api_auth_mfa_status))
        // Endpoint Agent
        .route(
            "/api/agents/enrollment-tokens",
            post(api_agents_create_token),
        )
        .route("/api/agents/enroll", post(api_agents_enroll))
        .route("/api/agents/status", get(api_agents_status))
        .route("/api/agents/dispatch", post(api_agents_dispatch_task))
        .route("/install/agent.sh", get(install_agent_sh))
        .route("/install/agent.ps1", get(install_agent_ps1))
        .route(
            "/install/binaries/:platform/weissman-agent",
            get(install_agent_binary),
        )
        .route(
            "/install/binaries/:platform/weissman-agent.sha256",
            get(install_agent_binary_sha256),
        )
        .route("/ws/agent", get(ws_agent))
        // Onboarding + billing (Paddle + self-serve register).
        .route("/api/onboarding/register", post(api_onboarding_register))
        .route("/api/onboarding/target", post(api_onboarding_target))
        .route(
            "/api/onboarding/launch-scan",
            post(api_onboarding_launch_scan),
        )
        .route("/api/billing/usage", get(api_billing_usage))
        .route(
            "/api/billing/checkout-session",
            post(api_billing_checkout_session),
        )
        .route("/api/billing/sync-paddle", post(api_billing_sync_paddle))
        .route("/api/webhooks/paddle", post(api_paddle_webhook))
        .route("/api/auth/oidc/begin", get(crate::oidc_auth::oidc_begin))
        .route(
            "/api/auth/oidc/callback",
            get(crate::oidc_auth::oidc_callback),
        )
        .route("/api/auth/saml/begin", get(crate::saml_auth::saml_begin))
        .route("/api/auth/saml/acs", post(crate::saml_auth::saml_acs))
        .route("/api/health", get(api_health))
        .route("/api/audit-logs", get(api_audit_logs))
        .route("/api/auth/me", get(api_auth_me))
        .route("/api/auth/sse-ticket", get(api_auth_sse_ticket))
        // ── Admin user management (CEO/Superadmin only) ───────────────────────
        .route(
            "/api/admin/users",
            get(crate::admin_users::api_admin_users_list)
                .post(crate::admin_users::api_admin_users_create),
        )
        .route(
            "/api/admin/users/:id",
            patch(crate::admin_users::api_admin_users_update),
        )
        .route(
            "/api/admin/users/:id/deactivate",
            post(crate::admin_users::api_admin_users_deactivate),
        )
        .route(
            "/api/enterprise/settings",
            get(api_enterprise_settings_get).patch(api_enterprise_settings_patch),
        )
        .route("/api/system/backup", post(api_system_backup))
        .route(
            "/api/clients",
            get(api_clients_list).post(api_clients_create),
        )
        .route(
            "/api/clients/:id",
            get(api_clients_get)
                .post(api_clients_update)
                .delete(api_clients_delete),
        )
        .route(
            "/api/clients/:id/scan/run-all",
            post(api_clients_scan_run_all),
        )
        .route(
            "/api/clients/:id/config",
            get(api_client_config_get).patch(api_client_config_patch),
        )
        .route("/api/clients/:id/readiness", get(api_clients_readiness))
        .route(
            "/api/clients/:id/engagements",
            get(api_client_engagements_list).post(api_client_engagements_create),
        )
        .route(
            "/api/engagements/:id",
            get(api_engagement_get).patch(api_engagement_patch),
        )
        .route(
            "/api/clients/:id/evidence",
            get(api_client_evidence_list).post(api_client_evidence_upload),
        )
        .route(
            "/api/clients/:id/discovery/saas-idp",
            get(api_client_saas_idp_discovery),
        )
        .route("/api/evidence/:id/download", get(api_evidence_download))
        .route("/api/evidence/:id", delete(api_evidence_delete))
        .route(
            "/api/roe/override-requests",
            get(api_roe_override_requests_list),
        )
        .route(
            "/api/roe/override-requests/:id/approve",
            post(api_roe_override_request_approve),
        )
        .route(
            "/api/roe/override-requests/:id/reject",
            post(api_roe_override_request_reject),
        )
        .route("/api/clients/:id/findings", get(api_client_findings_all))
        .route("/api/clients/:id/export/csv", get(api_client_export_csv))
        .route("/api/clients/:id/report/pdf", get(api_client_report_pdf))
        .route(
            "/api/clients/:id/report/crypto-proof",
            get(api_client_report_crypto_proof),
        )
        .route(
            "/api/clients/:id/attack-surface-graph",
            get(api_client_attack_surface_graph),
        )
        .route(
            "/api/clients/:id/semantic-state-machine",
            get(api_client_semantic_state_machine),
        )
        .route(
            "/api/clients/:id/semantic-logic/reasoning",
            get(api_client_semantic_reasoning),
        )
        .route("/api/verify-audit/:hash", get(api_verify_audit))
        .route("/api/scan/status", get(api_scan_status))
        .route("/api/scan/start", post(api_scan_start))
        .route("/api/scan/stop", post(api_scan_stop))
        .route("/api/scan/run-all", post(api_scan_run_all))
        .route("/api/scan/all-engines", post(api_scan_all_engines))
        .route("/api/discovery/domains", post(api_discovery_domains))
        .route(
            "/api/scan/discovered-domains",
            post(api_scan_discovered_domains),
        )
        .route(
            "/api/system/configs",
            get(api_system_configs_get).post(api_system_configs_post),
        )
        .route("/api/command-center/deep-fuzz", post(api_deep_fuzz))
        .route("/api/general/mission", post(api_general_mission))
        .route("/api/council/debate", post(api_council_debate))
        // ── Council HITL approval queue ───────────────────────────────────────
        .route("/api/council/hitl/propose", post(api_council_hitl_propose))
        .route("/api/council/hitl/queue", get(api_council_hitl_queue))
        .route(
            "/api/council/hitl/:id/approve",
            post(api_council_hitl_approve),
        )
        .route(
            "/api/council/hitl/:id/reject",
            post(api_council_hitl_reject),
        )
        // ── Structured OAST probe token registry ─────────────────────────────
        .route("/api/oast/probe", post(api_oast_probe_mint))
        .route("/api/oast/callbacks", get(api_oast_callbacks))
        .route("/api/oast/verify/:token", get(api_oast_probe_verify))
        // ── Template Engine (YAML) ──────────────────────────────────────────
        .route(
            "/api/template-engine/templates",
            get(api_template_engine_templates_list),
        )
        .route(
            "/api/template-engine/templates/:id",
            get(api_template_engine_template_get),
        )
        .route("/api/template-engine/run", post(api_template_engine_run))
        // ── AST smart fuzz preview (no traffic) ─────────────────────────────
        .route("/api/fuzz/ast-preview", post(api_fuzz_ast_preview))
        // ── Enterprise SSO management ─────────────────────────────────────────
        .route(
            "/api/sso/idps",
            get(crate::sso_management::api_sso_idps_list)
                .post(crate::sso_management::api_sso_idps_create),
        )
        .route(
            "/api/sso/idps/:id",
            get(crate::sso_management::api_sso_idp_get)
                .patch(crate::sso_management::api_sso_idp_patch)
                .delete(crate::sso_management::api_sso_idp_delete),
        )
        .route(
            "/api/sso/idps/:id/test",
            post(crate::sso_management::api_sso_idp_test),
        )
        .route(
            "/api/sso/idps/:id/toggle",
            post(crate::sso_management::api_sso_idp_toggle),
        )
        .route("/api/general/ascension", post(api_general_ascension))
        .route("/api/general/self-audit", post(api_general_self_audit))
        .route("/api/timing-scan/run", post(api_timing_scan_run))
        .route("/ws/timing", get(ws_timing))
        .route("/api/ai-redteam/run", post(api_ai_redteam_run))
        .route("/ws/ai-redteam", get(ws_ai_redteam))
        .route("/api/threat-intel/feed", get(api_threat_intel_feed))
        .route("/api/threat-intel/run", post(api_threat_intel_run))
        .route("/ws/threat-intel", get(ws_threat_intel))
        .route("/ws/swarm", get(ws_swarm))
        .route("/api/pipeline-scan/run", post(api_pipeline_scan_run))
        .route(
            "/api/clients/:id/cicd-findings",
            get(api_client_cicd_findings),
        )
        .route("/api/telemetry/stream", get(api_telemetry_stream))
        .route("/api/latency-probe", post(api_latency_probe))
        .route("/api/poe-scan/run", post(api_poe_scan_run))
        .route("/api/jobs", get(api_async_jobs_list))
        .route("/api/jobs/:job_id", get(api_async_job_status))
        .route("/api/poe-scan/status/:job_id", get(api_poe_scan_status))
        .route("/api/poe-scan/stream/:job_id", get(api_poe_scan_stream))
        .route(
            "/api/clients/:id/poe-findings",
            get(api_client_poe_findings),
        )
        .route(
            "/api/clients/:id/attack-chain",
            get(api_client_attack_chain),
        )
        .route("/api/identity/contexts", get(api_identity_contexts_alias))
        .route(
            "/api/clients/:id/identity-contexts",
            get(api_identity_contexts_list).post(api_identity_contexts_add),
        )
        .route(
            "/api/clients/:id/identity-contexts/:ctx_id",
            delete(api_identity_contexts_delete),
        )
        .route(
            "/api/clients/:id/privilege-escalation",
            get(api_privilege_escalation),
        )
        .route("/api/dag", get(api_dag_get))
        .route(
            "/api/pipeline/state",
            get(api_pipeline_state_get).patch(api_pipeline_state_patch),
        )
        .route("/api/risk/graph", get(api_risk_graph_alias))
        .route(
            "/api/clients/:id/risk-graph",
            get(api_risk_graph_get).post(api_risk_graph_build),
        )
        .route(
            "/api/clients/:id/risk-graph/export",
            get(api_risk_graph_export),
        )
        .route(
            "/api/clients/:id/runtime-traces",
            get(api_runtime_traces_list).post(api_runtime_traces_ingest),
        )
        .route("/api/clients/:id/auto-heal", post(api_auto_heal))
        .route(
            "/api/clients/:id/heal-requests",
            get(api_heal_requests_list),
        )
        .route("/api/clients/:id/deception", get(api_deception_list))
        .route(
            "/api/clients/:id/deception/generate",
            post(api_deception_generate),
        )
        .route(
            "/api/clients/:id/cloud-integration",
            patch(api_client_cloud_integration_patch),
        )
        .route(
            "/api/clients/:id/cloud-scan/run",
            post(api_client_cloud_scan_run),
        )
        .route("/api/compliance/posture", get(api_compliance_posture))
        // UI aliases: SystemConfiguration page + ComplianceFrameworks page expect these paths.
        .route(
            "/api/system/config",
            get(api_system_config_alias).put(api_system_config_put_alias),
        )
        .route(
            "/api/compliance/frameworks",
            get(api_compliance_frameworks_list),
        )
        .route(
            "/api/compliance/frameworks/:framework_id/controls",
            get(api_compliance_frameworks_controls),
        )
        .route(
            "/api/compliance/frameworks/:framework_id/report",
            get(api_compliance_frameworks_report),
        )
        .route("/api/search", get(api_global_search))
        .route(
            "/api/scans/schedules",
            get(api_scan_schedules_list).post(api_scan_schedules_create),
        )
        .route(
            "/api/scans/schedules/:id",
            put(api_scan_schedules_update)
                .patch(api_scan_schedules_patch)
                .delete(api_scan_schedules_delete),
        )
        .route("/api/scans/schedules/:id/run", post(api_scan_schedules_run))
        .route(
            "/api/alerts/rules",
            get(api_alert_rules_list).post(api_alert_rules_create),
        )
        .route(
            "/api/alerts/rules/:id",
            put(api_alert_rules_put)
                .patch(api_alert_rules_patch)
                .delete(api_alert_rules_delete),
        )
        .route("/api/alerts/rules/:id/test", post(api_alert_rules_test))
        .route(
            "/api/integrations",
            get(api_integrations_list).post(api_integrations_post),
        )
        .route("/api/integrations/:id/test", post(api_integrations_test))
        .route("/api/integrations/:id", delete(api_integrations_delete))
        .route("/api/ot-ics/devices", get(api_ot_ics_devices))
        .route("/api/mobile-security/apps", get(api_mobile_security_apps))
        .route("/api/soc/incidents", get(api_soc_incidents))
        .route(
            "/api/soc/incidents/:id/playbook-steps",
            patch(api_soc_incident_playbook_steps_patch),
        )
        .route("/api/soc/hunts", get(api_soc_hunts))
        .route("/api/soc/iocs", get(api_soc_iocs))
        .route("/api/soc/kill-chains", get(api_soc_kill_chains))
        .route("/api/soc/exploit-lab", get(api_soc_exploit_lab))
        .route("/api/soc/ai-patterns", get(api_soc_ai_patterns))
        .route(
            "/api/soc/social-engineering",
            get(api_soc_social_engineering),
        )
        .route(
            "/api/soc/social-engineering/campaigns",
            post(api_soc_social_engineering_campaigns_post),
        )
        .route("/api/soc/network-protocols", get(api_soc_network_protocols))
        .route("/api/reports/executive", get(api_reports_executive))
        .route(
            "/api/sovereign/phantom-trap",
            post(api_sovereign_phantom_trap),
        )
        .route("/api/deception/triggered", post(api_deception_triggered))
        .route("/api/deception/aws-events", post(api_deception_aws_events))
        .route("/api/v1/alerts/aws-canary", post(api_v1_alerts_aws_canary))
        .route(
            "/api/clients/:id/deception/deploy-cloud",
            post(api_deception_deploy_cloud),
        )
        .route("/api/heal-verify/:job_id/steps", get(api_heal_verify_steps))
        .route("/api/clients/:id/swarm/run", post(api_swarm_run))
        .route("/api/swarm/events", get(api_swarm_events))
        .route("/api/threat-ingest/run", post(api_threat_ingest_run))
        .route("/api/sbom/components", get(api_sbom_components_alias))
        .route("/api/sbom/export", get(api_sbom_export_alias))
        .route(
            "/api/clients/:id/sbom/components",
            get(api_client_sbom_list).post(api_client_sbom_post),
        )
        .route("/api/clients/:id/sbom/export", get(api_client_sbom_export))
        .route(
            "/api/containment/rules",
            get(api_containment_rules_alias).post(api_containment_rules_post_alias),
        )
        .route(
            "/api/containment/rules/:id",
            patch(api_containment_rules_patch_alias)
                .put(api_containment_rules_patch_alias)
                .delete(api_containment_rules_delete_alias),
        )
        .route(
            "/api/clients/:id/containment-rules",
            get(api_containment_rules_list).post(api_containment_rules_post),
        )
        .route(
            "/api/clients/:id/containment/execute",
            post(api_containment_execute),
        )
        .route("/api/clients/:id/llm-fuzz/run", post(api_llm_fuzz_run))
        .route("/api/clients/:id/llm-fuzz/events", get(api_llm_fuzz_events))
        .route(
            "/api/clients/:id/llm-fuzz/summary",
            get(api_llm_fuzz_summary),
        )
        .route(
            "/api/clients/:id/vulnerabilities/:vid/decrypt-poc",
            post(api_decrypt_sealed_poc),
        )
        .route("/api/payload-sync/status", get(api_payload_sync_status))
        .route("/api/payload-sync/payloads", get(api_payload_sync_payloads))
        .route("/api/payload-sync/run", post(api_payload_sync_run))
        .route("/api/edge-swarm/nodes", get(api_edge_swarm_nodes))
        .route("/api/edge-swarm/heartbeat", post(api_edge_swarm_heartbeat))
        .route("/api/edge-fuzz/manifest", get(api_edge_fuzz_manifest))
        .route("/api/crypto/capabilities", get(api_crypto_capabilities))
        .route("/api/crypto/pqc-selftest", get(api_crypto_pqc_selftest))
        .route(
            "/api/clients/:id/ot-ics/fingerprints",
            get(api_client_ot_ics_fingerprints),
        )
        .route(
            "/api/ceo/council/sessions/:job_id/stream",
            get(api_ceo_council_session_sse),
        )
        .route(
            "/api/ceo/strategy",
            get(api_ceo_strategy_get).patch(api_ceo_strategy_patch),
        )
        .route("/api/ceo/war-room/stream", get(api_ceo_war_room_sse))
        .route("/api/ceo/telemetry", get(api_ceo_telemetry_get))
        .route("/api/ceo/jobs/live", get(api_ceo_jobs_live_get))
        .route(
            "/api/ceo/global-safe-mode",
            patch(api_ceo_global_safe_patch),
        )
        .route(
            "/api/ceo/god-mode/snapshot",
            get(api_ceo_god_mode_snapshot_get),
        )
        .route(
            "/api/ceo/tenant/engines",
            get(api_ceo_tenant_engines_get)
                .put(api_ceo_tenant_engines_put)
                .patch(api_ceo_tenant_engines_put),
        )
        .route(
            "/api/ceo/god-mode/scan-interval",
            patch(api_ceo_god_mode_scan_interval_patch).post(api_ceo_god_mode_scan_interval_patch),
        )
        .route(
            "/api/ceo/hpc/policy",
            get(api_ceo_hpc_policy_get)
                .put(api_ceo_hpc_policy_put)
                .post(api_ceo_hpc_policy_put),
        )
        .route(
            "/api/ceo/vault/export/criticals",
            get(api_ceo_vault_export_criticals),
        )
        .route(
            "/api/ceo/vault/secrets",
            get(api_ceo_vault_secrets_alias).post(api_ceo_vault_secrets_post),
        )
        .route(
            "/api/ceo/vault/secrets/:id/access",
            post(api_ceo_vault_secrets_access),
        )
        .route(
            "/api/ceo/vault/secrets/:id/copy",
            post(api_ceo_vault_secrets_copy),
        )
        .route(
            "/api/ceo/vault/secrets/:id",
            put(api_ceo_vault_secrets_put).delete(api_ceo_vault_secrets_delete),
        )
        .route(
            "/api/ceo/vault",
            get(api_ceo_vault_list).post(api_ceo_vault_post),
        )
        .route("/api/ceo/vault/:id/match", post(api_ceo_vault_match))
        .route(
            "/api/ceo/genesis/vault/:id/match",
            post(api_ceo_vault_match),
        )
        .route("/api/ceo/vault/:id", get(api_ceo_vault_get))
        .route(
            "/api/ceo/sovereign/buffer",
            get(api_ceo_sovereign_buffer_get),
        )
        .route(
            "/api/ceo/sovereign/trigger",
            post(api_ceo_sovereign_trigger_post),
        )
        .route("/api/ceo/suspended-graphs", get(api_ceo_suspended_list))
        .route(
            "/api/ceo/suspended-graphs/:id/resume",
            post(api_ceo_suspended_resume),
        )
        .route("/api/ceo/suspended-graphs/:id", get(api_ceo_suspended_get))
        .layer(middleware::from_fn(
            crate::http::login_rate_limit_middleware,
        ))
        .layer(middleware::from_fn(
            crate::http::tenant_scan_limit::tenant_scan_rate_limit_middleware,
        ))
        .layer(middleware::from_fn(
            crate::http::ceo_rbac::ceo_rbac_middleware,
        ))
        .layer(middleware::from_fn(crate::rbac::mutation_rbac_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), auth_guard))
        .layer(middleware::from_fn(crate::http::api_rate_limit_middleware))
        .layer(middleware::from_fn(
            crate::observability::http_metrics_middleware,
        ))
        .layer(middleware::from_fn(
            crate::request_trace::trace_http_middleware,
        ))
        .with_state(state);
    // Frontend is built with base: '/command-center/' so assets at /command-center/assets/...
    let app = if let Some(dir) = static_dir {
        eprintln!("[Weissman] Command Center (React) enabled: {} → / and /dashboard redirect to /command-center/", dir.display());
        let index_path = dir.join("index.html");
        let index_html = tokio::fs::read_to_string(&index_path)
            .await
            .unwrap_or_else(|_| {
                eprintln!(
                    "[Weissman] Could not read {} for SPA fallback",
                    index_path.display()
                );
                String::from(
                    "<!DOCTYPE html><html><body>Command Center index not found.</body></html>",
                )
            });
        let spa_fallback = Router::new()
            .route("/", get(command_center_spa_index))
            .route("/*path", get(command_center_spa_index))
            .layer(Extension(index_html))
            .into_service();
        let serve_dir = ServeDir::new(dir)
            .fallback(spa_fallback)
            .map_response(|response| response.map(Body::new));
        let static_router = Router::new().nest_service("/command-center", serve_dir);
        api.merge(static_router)
    } else {
        eprintln!("[Weissman] Command Center not found (no frontend/dist). Using legacy dashboard at /. Set WEISSMAN_STATIC or run from project root with frontend/dist built.");
        api
    };
    app
}

pub async fn run_http_tcp_listener(app: Router, port: u16) {
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) if e.raw_os_error() == Some(98) => {
            eprintln!(
                "[Weissman] Port {} in use. Set PORT=8001 or stop the other process.",
                port
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[Weissman] FATAL: bind {}: {}", addr, e);
            std::process::exit(1);
        }
    };
    eprintln!(
        "[Weissman] Listening on http://0.0.0.0:{} (set PORT in .env to change; Nginx must proxy the same port)",
        port
    );
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        eprintln!("[Weissman] FATAL: server exited: {}", e);
        std::process::exit(1);
    }
    eprintln!("[Weissman] Graceful shutdown complete — in-flight requests drained.");
}

/// Resolves on SIGINT (Ctrl-C) or SIGTERM (container/systemd stop) so Axum drains
/// in-flight requests before the process exits — deploys/redeploys no longer cut
/// active scans, SSE streams, or agent dispatches mid-flight.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    eprintln!("[Weissman] Shutdown signal received — draining connections…");
}
