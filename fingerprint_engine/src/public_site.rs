//! Public flagship-site APIs — no tenant session, no findings, no PII in GET bodies.
//!
//! `GET /api/public/platform-pulse` and `GET /api/public/engine-catalog` are derived from the
//! production engine registry (same source as Command Center). `POST /api/public/contact`
//! persists a sales lead; success requires a real insert.

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::engine_accounting;
use crate::http::client_ip::extract_client_ip;
use crate::http::AppState;

const MAX_NAME: usize = 120;
const MAX_EMAIL: usize = 254;
const MAX_COMPANY: usize = 160;
const MAX_MESSAGE: usize = 4000;
const MAX_SOURCE: usize = 64;

/// JSON for the marketing pulse. Deterministic engine counts; optional liveness from Postgres.
pub fn platform_pulse_json(postgres_ok: Option<bool>) -> Value {
    let accounting = engine_accounting::compute();
    let health = match postgres_ok {
        Some(true) | None => "operational",
        Some(false) => "degraded",
    };
    json!({
        "ok": true,
        "updated_at": Utc::now().to_rfc3339(),
        "health": health,
        "production_engines": accounting.total_ids,
        "distinct_canonical": accounting.distinct_canonical,
        "real_probes": accounting.remotely_detecting,
        "agent_required": accounting.agent_required,
        "alias_ids": accounting.alias_ids,
    })
}

/// Slim catalog: id, category, MITRE techniques, reality kind. No tenant fields, no findings.
pub fn engine_catalog_json() -> Value {
    let engines: Vec<Value> = crate::arsenal_catalog::catalog()
        .into_iter()
        .map(|c| {
            let mut row = json!({
                "id": c.id,
                "kind": c.kind,
                "category": c.category,
                "remote_detection": c.remote_detection,
                "mitre": c.techniques,
            });
            if let Some(canon) = c.canonical {
                row["canonical"] = json!(canon);
            }
            row
        })
        .collect();
    json!({
        "ok": true,
        "count": engines.len(),
        "engines": engines,
    })
}

fn json_leaks_tenant(v: &Value) -> bool {
    fn walk(v: &Value) -> bool {
        match v {
            Value::Object(map) => map.keys().any(|k| {
                let kl = k.to_ascii_lowercase();
                kl == "tenant_id"
                    || kl == "findings"
                    || kl == "email"
                    || kl.contains("password")
                    || walk(&map[k])
            }),
            Value::Array(items) => items.iter().any(walk),
            _ => false,
        }
    }
    walk(v)
}

pub async fn api_platform_pulse(State(state): State<Arc<AppState>>) -> Response {
    let postgres_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(state.app_pool.as_ref())
        .await
        .is_ok();
    let body = platform_pulse_json(Some(postgres_ok));
    (StatusCode::OK, Json(body)).into_response()
}

pub async fn api_engine_catalog() -> Response {
    (StatusCode::OK, Json(engine_catalog_json())).into_response()
}

#[derive(Debug, Deserialize)]
pub struct ContactRequest {
    pub name: String,
    pub email: String,
    #[serde(default)]
    pub company: String,
    pub message: String,
    #[serde(default)]
    pub source: String,
}

fn trim_field<'a>(raw: &'a str, max: usize) -> Result<&'a str, &'static str> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("required");
    }
    if s.len() > max {
        return Err("too_long");
    }
    Ok(s)
}

fn validate_email(raw: &str) -> Result<String, &'static str> {
    let e = raw.trim().to_lowercase();
    if e.len() < 5 || e.len() > MAX_EMAIL || !e.contains('@') || e.contains(' ') {
        return Err("invalid_email");
    }
    let (local, domain) = e.split_once('@').ok_or("invalid_email")?;
    if local.is_empty() || !domain.contains('.') {
        return Err("invalid_email");
    }
    Ok(e)
}

pub async fn api_public_contact(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ContactRequest>,
) -> Response {
    let name = match trim_field(&body.name, MAX_NAME) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "code": "invalid_name", "detail": "Name is required." })),
            )
                .into_response();
        }
    };
    let email = match validate_email(&body.email) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "ok": false, "code": "invalid_email", "detail": "A valid work email is required." }),
                ),
            )
                .into_response();
        }
    };
    let message = match trim_field(&body.message, MAX_MESSAGE) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "ok": false, "code": "invalid_message", "detail": "A short message is required." }),
                ),
            )
                .into_response();
        }
    };
    let company = body.company.trim();
    if company.len() > MAX_COMPANY {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "code": "invalid_company", "detail": "Company is too long." })),
        )
            .into_response();
    }
    let source = body.source.trim();
    if source.len() > MAX_SOURCE {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "code": "invalid_source" })),
        )
            .into_response();
    }
    let ip = extract_client_ip(&headers, addr);

    match insert_contact_lead(
        state.app_pool.as_ref(),
        name,
        &email,
        if company.is_empty() { None } else { Some(company) },
        message,
        if source.is_empty() { None } else { Some(source) },
        &ip,
    )
    .await
    {
        Ok(()) => {
            notify_sales(name, &email, company, message);
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "ok": true,
                    "detail": "Thanks — we received your request and will reply from sales."
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!(target: "public_contact", error = %e, "contact lead insert failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "ok": false,
                    "code": "contact_unavailable",
                    "detail": "Could not store the request. Email sales@weissman.io or try again."
                })),
            )
                .into_response()
        }
    }
}

async fn insert_contact_lead(
    pool: &PgPool,
    name: &str,
    email: &str,
    company: Option<&str>,
    message: &str,
    source: Option<&str>,
    client_ip: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO public_contact_leads (name, email, company, message, source, client_ip)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(name)
    .bind(email)
    .bind(company)
    .bind(message)
    .bind(source)
    .bind(client_ip)
    .execute(pool)
    .await?;
    Ok(())
}

fn notify_sales(name: &str, email: &str, company: &str, message: &str) {
    let to = std::env::var("WEISSMAN_SALES_EMAIL").unwrap_or_else(|_| "sales@weissman.io".into());
    let body = format!(
        "New Weissman demo request\n\nName: {name}\nEmail: {email}\nCompany: {company}\n\n{message}\n"
    );
    tokio::spawn(async move {
        if let Err(e) =
            crate::signup::send_signup_email(&to, "Weissman — new demo request", &body).await
        {
            tracing::debug!(target: "public_contact", error = %e, "sales email not sent");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pulse_has_live_engine_counts_and_no_tenant_leak() {
        let v = platform_pulse_json(Some(true));
        assert_eq!(v["ok"], true);
        assert_eq!(v["health"], "operational");
        assert!(v["production_engines"].as_u64().unwrap() >= 1);
        assert!(v["real_probes"].as_u64().is_some());
        assert!(!json_leaks_tenant(&v));
        let s = v.to_string();
        assert!(!s.contains("tenant_id"));
        assert!(!s.contains("findings"));
    }

    #[test]
    fn pulse_degraded_when_postgres_down() {
        let v = platform_pulse_json(Some(false));
        assert_eq!(v["health"], "degraded");
        assert!(v["production_engines"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn catalog_matches_production_ids_without_secrets() {
        let v = engine_catalog_json();
        let n = v["count"].as_u64().unwrap() as usize;
        let engines = v["engines"].as_array().unwrap();
        assert_eq!(n, engines.len());
        assert_eq!(n, weissman_core::models::engine::production_engine_ids().len());
        let osint = engines.iter().find(|e| e["id"] == "osint").expect("osint");
        assert!(osint["category"].as_str().unwrap().len() > 1);
        assert!(osint["mitre"].is_array());
        assert!(!json_leaks_tenant(&v));
        let s = v.to_string();
        assert!(!s.contains("tenant_id"));
        assert!(!s.contains("password"));
    }

    #[test]
    fn email_validation_rejects_garbage() {
        assert!(validate_email("not-an-email").is_err());
        assert!(validate_email("a@b").is_err());
        assert!(validate_email("ok@weissman.io").is_ok());
    }
}
