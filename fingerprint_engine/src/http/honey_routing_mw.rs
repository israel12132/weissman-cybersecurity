//! Serve honeynet responses for decoy / lure paths intercepted in `auth_guard`.

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

use super::extract_client_ip;
use super::serve::AppState;
use crate::honey_deception_node;
use crate::honey_mimicry;
use crate::honey_routing::{
    classify, decoy_kind, extract_shell_command, is_decoy_path, DECOY_ADMIN, DECOY_FINGERPRINT,
    DECOY_SHELL,
};
use crate::tls_client_hello;
use std::time::Instant;

const MAX_BODY: usize = 65_536;

pub async fn serve_honey(state: Arc<AppState>, request: Request<Body>) -> Response {
    let started = Instant::now();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let headers = request.headers().clone();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();
    let (_parts, body) = request.into_parts();
    let bytes = to_bytes(body, MAX_BODY).await.unwrap_or_default();
    let body_str = String::from_utf8_lossy(&bytes).to_string();

    let ip = extract_client_ip(&headers, peer);
    let ua = header_str(&headers, header::USER_AGENT);
    let host = header_str(&headers, header::HOST);
    let mut header_map = serde_json::Map::new();
    for (k, v) in headers.iter() {
        let key = k.as_str().to_ascii_lowercase();
        if key == "authorization" || key == "cookie" {
            continue;
        }
        if let Ok(val) = v.to_str() {
            header_map.insert(key, json!(val.chars().take(256).collect::<String>()));
        }
    }

    let tls = tls_client_hello::from_request_headers(&headers, peer);

    let hit = crate::honey_routing::HoneyHit {
        method: method.as_str().to_string(),
        path: path.clone(),
        query,
        source_ip: ip,
        user_agent: ua,
        host: host.clone(),
        body: body_str.clone(),
        headers: Value::Object(header_map),
        tls: tls.to_json(),
    };
    let decision = classify(&hit, false);

    let app_pool = state.app_pool.clone();
    let auth_pool = state.auth_pool.clone();
    let telemetry = state.telemetry_broadcast_tx.clone();
    let hit_for_db = hit.clone();
    let decision_for_db = decision.clone();
    tokio::spawn(async move {
        let Ok((tenant_id, client_id)) = crate::honey_routing_store::resolve_scope(
            auth_pool.as_ref(),
            app_pool.as_ref(),
            &hit_for_db.host,
        )
        .await
        else {
            return;
        };
        match crate::honey_routing_store::ingest_hit(
            app_pool.as_ref(),
            tenant_id,
            client_id,
            &hit_for_db,
            &decision_for_db,
        )
        .await
        {
            Ok(ingested) => {
                if decoy_kind(&hit_for_db.path) == "browser_profile" {
                    if let Ok(profile) = serde_json::from_str::<Value>(&hit_for_db.body) {
                        let _ = crate::honey_routing_store::merge_browser_profile(
                            app_pool.as_ref(),
                            tenant_id,
                            ingested.session_id,
                            &profile,
                        )
                        .await;
                    }
                }
                crate::honey_routing_store::spawn_enrichment(
                    (*app_pool).clone(),
                    (*telemetry).clone(),
                    hit_for_db,
                    decision_for_db,
                    ingested,
                );
            }
            Err(e) => {
                tracing::debug!(target: "honey_routing", error = %e, "ingest failed");
            }
        }
    });

    honey_mimicry::finish_fabric_response(started, decoy_response(&method, &path, &body_str)).await
}

fn decoy_response(method: &axum::http::Method, path: &str, body: &str) -> Response {
    let p = crate::honey_routing::normalize_path(path);
    if p.starts_with(DECOY_FINGERPRINT) {
        return (StatusCode::NO_CONTENT, ()).into_response();
    }
    if p.starts_with(DECOY_SHELL) {
        if method == axum::http::Method::GET {
            return (StatusCode::OK, Json(honey_deception_node::shell_banner())).into_response();
        }
        let cmd = extract_shell_command(&crate::honey_routing::HoneyHit {
            method: method.to_string(),
            path: p.clone(),
            query: String::new(),
            source_ip: String::new(),
            user_agent: String::new(),
            host: String::new(),
            body: body.to_string(),
            headers: json!({}),
            tls: json!({}),
        })
        .unwrap_or_default();
        let cwd = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| v.get("cwd").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| "/home/ops-admin".into());
        return (
            StatusCode::OK,
            Json(honey_deception_node::shell_exec_json(&cmd, &cwd)),
        )
            .into_response();
    }
    if method == axum::http::Method::POST && (p.starts_with(DECOY_ADMIN) || is_decoy_path(&p)) {
        return (
            StatusCode::FORBIDDEN,
            Json(honey_deception_node::admin_login_error()),
        )
            .into_response();
    }
    // GET admin / lure paths: luxury HTML bait (same URL in the attacker browser).
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        honey_deception_node::admin_portal_html(),
    )
        .into_response()
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Used by unused-import keep-alive for Html in case of future SPA decoys.
#[allow(dead_code)]
fn _html_decoy() -> Html<String> {
    Html(honey_deception_node::admin_portal_html())
}
