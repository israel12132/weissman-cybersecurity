//! Weissman OAST listener: records HTTP and DNS out-of-band interactions for fuzzing correlation.
//!
//! Env:
//! - `DATABASE_URL` — Postgres (same DB as app; table `oast_interaction_hits`).
//! - `WEISSMAN_OAST_DOMAIN` — preferred; e.g. `weissmancyber.com` (parse `{uuid}.weissmancyber.com`).
//! - `WEISSMAN_OAST_BASE_DOMAIN` — legacy alias for the same suffix.
//! - `OAST_HTTP_LISTEN` — default `0.0.0.0:9090`.
//! - `OAST_DNS_LISTEN` — default `0.0.0.0:5353` (set `OAST_DNS_ENABLE=0` to disable).
//! - `WEISSMAN_OAST_API_KEY` — optional Bearer for `/api/oast/*`.

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{error, info, warn};
use uuid::Uuid;

mod panic_shield;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    base_domain: String,
    api_key: Option<String>,
}

fn base_domain_from_env() -> String {
    env::var("WEISSMAN_OAST_DOMAIN")
        .or_else(|_| env::var("WEISSMAN_OAST_BASE_DOMAIN"))
        .unwrap_or_default()
        .trim()
        .trim_end_matches('.')
        .to_lowercase()
}

/// When unset, default to production suffix so a minimal deploy works (logged once).
fn base_domain_effective() -> String {
    let b = base_domain_from_env();
    if !b.is_empty() {
        return b;
    }
    let d = "weissmancyber.com".to_string();
    info!(
        target: "oast",
        "WEISSMAN_OAST_DOMAIN / WEISSMAN_OAST_BASE_DOMAIN unset; using default suffix {}",
        d
    );
    d
}

fn parse_interaction_token_label(label: &str) -> Option<Uuid> {
    let s = label.trim();
    if let Some(r) = s.strip_prefix("trap-") {
        if let Ok(u) = Uuid::parse_str(r) {
            return Some(u);
        }
    }
    if let Some(r) = s.strip_prefix("aws-mon-") {
        if let Ok(u) = Uuid::parse_str(r) {
            return Some(u);
        }
    }
    Uuid::parse_str(s).ok()
}

fn token_from_host(host: &str, suffix: &str) -> Option<Uuid> {
    let h = host.split(':').next()?.trim().to_lowercase();
    let s = suffix.trim_end_matches('.').to_lowercase();
    if s.is_empty() {
        return None;
    }
    if !h.ends_with(&s) || h.len() <= s.len() + 1 {
        return None;
    }
    let prefix = h.strip_suffix(&format!(".{s}"))?;
    let first = prefix.split('.').next()?;
    parse_interaction_token_label(first)
}

fn token_from_qname(qname: &str, suffix: &str) -> Option<Uuid> {
    let q = qname.trim_end_matches('.').to_lowercase();
    let s = suffix.trim_end_matches('.').to_lowercase();
    if s.is_empty() {
        return None;
    }
    if !q.ends_with(&s) || q.len() <= s.len() + 1 {
        return None;
    }
    let prefix = q.strip_suffix(&format!(".{s}"))?;
    let first = prefix.split('.').next()?;
    parse_interaction_token_label(first)
}

fn headers_to_json(headers: &HeaderMap) -> serde_json::Value {
    let mut m = HashMap::new();
    for (k, v) in headers.iter() {
        if let Ok(s) = v.to_str() {
            m.insert(k.as_str().to_string(), s.to_string());
        }
    }
    serde_json::to_value(m).unwrap_or(json!({}))
}

fn check_api_key(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let Some(ref expected) = state.api_key else {
        return Ok(());
    };
    let got = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = got.strip_prefix("Bearer ").unwrap_or("").trim();
    if token == expected {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn insert_hit(
    pool: &PgPool,
    token: Uuid,
    channel: &str,
    source_ip: Option<std::net::IpAddr>,
    http_method: Option<&str>,
    http_path: Option<&str>,
    host_header: Option<&str>,
    headers_json: serde_json::Value,
    dns_qname: Option<&str>,
    dns_qtype: Option<&str>,
    user_agent: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO oast_interaction_hits
           (interaction_token, channel, source_ip, http_method, http_path, host_header, headers_json, dns_qname, dns_qtype, user_agent)
           VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8, $9, $10)"#,
    )
    .bind(token)
    .bind(channel)
    .bind(source_ip.map(|ip| ip.to_string()))
    .bind(http_method)
    .bind(http_path)
    .bind(host_header)
    .bind(headers_json)
    .bind(dns_qname)
    .bind(dns_qtype)
    .bind(user_agent)
    .execute(pool)
    .await?;
    Ok(())
}

async fn http_catch_all(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let Some(token) = token_from_host(&host, &state.base_domain) else {
        return (StatusCode::NOT_FOUND, Body::from("not found")).into_response();
    };
    let path = uri.path().to_string();
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let hj = headers_to_json(&headers);
    if let Err(e) = insert_hit(
        &state.pool,
        token,
        "http",
        Some(addr.ip()),
        Some(method.as_str()),
        Some(&path),
        Some(&host),
        hj,
        None,
        None,
        ua.as_deref(),
    )
    .await
    {
        error!(target: "oast", "insert http hit: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Body::from("db error")).into_response();
    }
    let ip = addr.ip();
    let hcopy = host.clone();
    tokio::spawn(async move {
        panic_shield::maybe_react_to_trap_hit(Some(ip), &hcopy, None).await;
    });
    const GIF: &[u8] = &[
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff,
        0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x04, 0x01, 0x00, 0x3b,
    ];
    (
        StatusCode::OK,
        [("content-type", "image/gif")],
        Body::from(GIF),
    )
        .into_response()
}

async fn http_path_token(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token_str): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(token) = parse_interaction_token_label(token_str.trim()) else {
        return (StatusCode::BAD_REQUEST, "invalid token").into_response();
    };
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let path = uri.path().to_string();
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let hj = headers_to_json(&headers);
    let tok_s = token_str.clone();
    if let Err(e) = insert_hit(
        &state.pool,
        token,
        "http",
        Some(addr.ip()),
        Some(method.as_str()),
        Some(&path),
        Some(&host),
        hj,
        None,
        None,
        ua.as_deref(),
    )
    .await
    {
        error!(target: "oast", "insert path hit: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
    }
    let ip = addr.ip();
    let hcopy = host.clone();
    tokio::spawn(async move {
        panic_shield::maybe_react_to_trap_hit(Some(ip), &hcopy, Some(tok_s.as_str())).await;
    });
    (
        StatusCode::NO_CONTENT,
        axum::http::HeaderMap::new(),
        Body::empty(),
    )
        .into_response()
}

async fn api_status_plain(
    State(state): State<AppState>,
    Path(token_str): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(code) = check_api_key(&state, &headers) {
        return code.into_response();
    }
    let Some(token) = parse_interaction_token_label(token_str.trim()) else {
        return (StatusCode::BAD_REQUEST, "invalid token").into_response();
    };
    let row: (i64,) = match sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM oast_interaction_hits WHERE interaction_token = $1",
    )
    .bind(token)
    .fetch_one(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            error!(target: "oast", "count: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    };
    let body = if row.0 > 0 {
        env::var("WEISSMAN_OAST_HIT_SUBSTRING")
            .unwrap_or_else(|_| "oob_hit".to_string())
    } else {
        String::new()
    };
    (StatusCode::OK, [("content-type", "text/plain; charset=utf-8")], body).into_response()
}

async fn api_hits_json(
    State(state): State<AppState>,
    Path(token_str): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(code) = check_api_key(&state, &headers) {
        return (code, axum::Json(json!({"error":"unauthorized"}))).into_response();
    }
    let Some(token) = parse_interaction_token_label(token_str.trim()) else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error":"invalid_token"})),
        )
            .into_response();
    };
    let rows = match sqlx::query(
        r#"SELECT created_at, channel, source_ip::text, http_method, host_header, dns_qname, dns_qtype
           FROM oast_interaction_hits WHERE interaction_token = $1 ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(token)
    .fetch_all(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            error!(target: "oast", "list hits: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error":"db"})),
            )
                .into_response();
        }
    };
    let mut hits = Vec::new();
    for r in &rows {
        hits.push(json!({
            "at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok(),
            "channel": r.try_get::<String, _>("channel").ok(),
            "source_ip": r.try_get::<Option<String>, _>("source_ip").ok().flatten(),
            "http_method": r.try_get::<Option<String>, _>("http_method").ok().flatten(),
            "host_header": r.try_get::<Option<String>, _>("host_header").ok().flatten(),
            "dns_qname": r.try_get::<Option<String>, _>("dns_qname").ok().flatten(),
            "dns_qtype": r.try_get::<Option<String>, _>("dns_qtype").ok().flatten(),
        }));
    }
    let marker = env::var("WEISSMAN_OAST_HIT_SUBSTRING").unwrap_or_else(|_| "oob_hit".to_string());
    axum::Json(json!({
        "token": token_str,
        "hit_count": rows.len(),
        "oob_hit": !rows.is_empty(),
        "marker": marker,
        "hits": hits,
    }))
    .into_response()
}

fn parse_dns_qname(buf: &[u8]) -> Option<(String, u16)> {
    if buf.len() < 13 {
        return None;
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    if qd == 0 {
        return None;
    }
    let mut i = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *buf.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len > 253 || i + len >= buf.len() {
            return None;
        }
        i += 1;
        let label = std::str::from_utf8(&buf[i..i + len]).ok()?;
        labels.push(label.to_string());
        i += len;
    }
    if i + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
    Some((labels.join("."), qtype))
}

fn build_dns_response(query: &[u8], qend: usize) -> Option<Vec<u8>> {
    if query.len() < 12 || qend > query.len() {
        return None;
    }
    let mut out = Vec::with_capacity(12 + qend.saturating_sub(12));
    out.extend_from_slice(&query[0..2]);
    out.extend_from_slice(&[0x81, 0x80]);
    out.extend_from_slice(&query[4..6]);
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&query[12..qend]);
    Some(out)
}

fn dns_qend(query: &[u8]) -> Option<usize> {
    if query.len() < 13 {
        return None;
    }
    let mut i = 12usize;
    loop {
        let len = *query.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len > 253 || i + len >= query.len() {
            return None;
        }
        i += 1 + len;
    }
    if i + 4 > query.len() {
        return None;
    }
    Some(i + 4)
}

async fn dns_server_loop(socket: Arc<UdpSocket>, pool: PgPool, base_domain: String) {
    let mut buf = [0u8; 4096];
    loop {
        let Ok((n, src)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        if n < 12 {
            continue;
        }
        let Some(qend) = dns_qend(&buf[..n]) else {
            continue;
        };
        let Some((qname, qtype)) = parse_dns_qname(&buf[..n]) else {
            continue;
        };
        if let Some(token) = token_from_qname(&qname, &base_domain) {
            let qtype_s = format!("{}", qtype);
            if let Err(e) = insert_hit(
                &pool,
                token,
                "dns",
                Some(src.ip()),
                None,
                None,
                None,
                json!({}),
                Some(&qname),
                Some(&qtype_s),
                None,
            )
            .await
            {
                warn!(target: "oast", "dns insert: {}", e);
            } else {
                let qcopy = qname.clone();
                let ip = src.ip();
                tokio::spawn(async move {
                    panic_shield::maybe_react_to_trap_hit(Some(ip), &qcopy, None).await;
                });
            }
        }
        if let Some(resp) = build_dns_response(&buf[..n], qend) {
            let _ = socket.send_to(&resp, src).await;
        }
    }
}

async fn run() -> Result<(), String> {
    let database_url = env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL environment variable is required".to_string())?
        .trim()
        .to_string();
    if database_url.is_empty() {
        return Err("DATABASE_URL is empty".into());
    }
    let base = base_domain_effective();

    let pool = PgPoolOptions::new()
        .max_connections(32)
        .connect(&database_url)
        .await
        .map_err(|e| format!("postgres connect failed: {e}"))?;

    let api_key = env::var("WEISSMAN_OAST_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let state = AppState {
        pool: pool.clone(),
        base_domain: base.clone(),
        api_key,
    };

    let http_listen: SocketAddr = env::var("OAST_HTTP_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:9090".into())
        .parse()
        .map_err(|e| format!("OAST_HTTP_LISTEN: invalid socket address: {e}"))?;

    let app = Router::new()
        .route("/api/oast/status/:token", get(api_status_plain))
        .route("/api/oast/hits/:token", get(api_hits_json))
        .route("/i/:token", get(http_path_token).post(http_path_token))
        .fallback(http_catch_all)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(http_listen)
        .await
        .map_err(|e| format!("bind HTTP {http_listen}: {e}"))?;
    info!(target: "oast", %http_listen, domain = %base, "OAST HTTP listening");

    let dns_enable = !matches!(env::var("OAST_DNS_ENABLE").as_deref(), Ok("0") | Ok("false"));
    if dns_enable {
        let dns_listen = env::var("OAST_DNS_LISTEN").unwrap_or_else(|_| "0.0.0.0:5353".into());
        if let Ok(sock) = UdpSocket::bind(&dns_listen).await {
            info!(target: "oast", %dns_listen, "OAST DNS UDP listening");
            let s = Arc::new(sock);
            let p = pool.clone();
            let b = base.clone();
            tokio::spawn(dns_server_loop(s, p, b));
        } else {
            warn!(target: "oast", "OAST DNS bind failed for {}", dns_listen);
        }
    }

    let server = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>());
    server
        .await
        .map_err(|e| format!("HTTP server: {e}"))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,weissman_oast_server=info")),
        )
        .init();

    let _ = dotenvy::dotenv();

    if let Err(e) = run().await {
        error!(target: "oast", "{}", e);
        eprintln!("weissman-oast-server: {e}");
        std::process::exit(1);
    }
}
