//! Public demo / contact intake for the marketing site.
//!
//! `POST /api/public/demo-request`
//!
//! Success requires SMTP to be configured (`WEISSMAN_SMTP_ENABLED` plus host/from).
//! If mail cannot be sent, the handler returns **503** — the website must not claim
//! the request was delivered.

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;

use crate::http::client_ip::extract_client_ip;

const MAX_NAME: usize = 120;
const MAX_EMAIL: usize = 254;
const MAX_COMPANY: usize = 160;
const MAX_ROLE: usize = 120;
const MAX_MESSAGE: usize = 4000;
const MIN_MESSAGE: usize = 10;

#[derive(Debug, Deserialize)]
pub struct DemoRequest {
    pub name: String,
    pub email: String,
    pub company: String,
    #[serde(default)]
    pub role: String,
    pub message: String,
}

fn smtp_ready() -> bool {
    matches!(
        std::env::var("WEISSMAN_SMTP_ENABLED").as_deref(),
        Ok("true") | Ok("1") | Ok("yes")
    ) && std::env::var("WEISSMAN_SMTP_HOST").is_ok()
        && std::env::var("WEISSMAN_SMTP_FROM").is_ok()
}

fn validate_email(email: &str) -> Result<String, String> {
    let e = email.trim().to_lowercase();
    if e.len() < 5 || e.len() > MAX_EMAIL {
        return Err("invalid email".into());
    }
    if e.chars().any(char::is_whitespace) || e.matches('@').count() != 1 {
        return Err("invalid email".into());
    }
    let (local, domain) = e.split_once('@').ok_or("invalid email")?;
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err("invalid email".into());
    }
    Ok(e)
}

fn clip(s: &str, max: usize) -> String {
    s.trim().chars().take(max).collect()
}

/// Public: `POST /api/public/demo-request`.
pub async fn api_demo_request(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<DemoRequest>,
) -> Response {
    let ip = extract_client_ip(&headers, addr);
    let name = clip(&body.name, MAX_NAME);
    let company = clip(&body.company, MAX_COMPANY);
    let role = clip(&body.role, MAX_ROLE);
    let message = clip(&body.message, MAX_MESSAGE);
    let email = match validate_email(&body.email) {
        Ok(e) => e,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "detail": msg })),
            )
                .into_response();
        }
    };
    if name.len() < 2 || company.len() < 2 || message.len() < MIN_MESSAGE {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "detail": "name, organisation, and a short message are required"
            })),
        )
            .into_response();
    }

    if !smtp_ready() {
        tracing::info!(
            target: "demo_request",
            client_ip = %ip,
            "demo request rejected — SMTP not configured"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "code": "smtp_unconfigured",
                "detail": "This deployment is not configured to accept demo requests over email. Contact sales@weissman.io."
            })),
        )
            .into_response();
    }

    let subject = format!("Weissman demo request — {company}");
    let text = format!(
        "Name: {name}\nEmail: {email}\nCompany: {company}\nRole: {role}\nIP: {ip}\n\n{message}\n"
    );
    match send_sales_email(&subject, &text).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "detail": "Request received. We will reply from sales@weissman.io."
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(target: "demo_request", error = %e, "demo email failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "ok": false,
                    "code": "smtp_failed",
                    "detail": "The request could not be emailed from this deployment. Contact sales@weissman.io."
                })),
            )
                .into_response()
        }
    }
}

async fn send_sales_email(subject: &str, body: &str) -> Result<(), String> {
    let host = std::env::var("WEISSMAN_SMTP_HOST").map_err(|_| "WEISSMAN_SMTP_HOST")?;
    let port: u16 = std::env::var("WEISSMAN_SMTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(587);
    let user = std::env::var("WEISSMAN_SMTP_USER").unwrap_or_default();
    let pass = std::env::var("WEISSMAN_SMTP_PASSWORD").unwrap_or_default();
    let from = std::env::var("WEISSMAN_SMTP_FROM").map_err(|_| "WEISSMAN_SMTP_FROM")?;
    let to = std::env::var("WEISSMAN_SALES_EMAIL").unwrap_or_else(|_| "sales@weissman.io".into());
    let subject = subject.to_string();
    let body = body.to_string();

    tokio::task::spawn_blocking(move || -> Result<(), String> {
        use lettre::message::{header::ContentType, Mailbox, Message};
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{SmtpTransport, Transport};
        let from_m: Mailbox = from
            .parse()
            .map_err(|e: lettre::address::AddressError| e.to_string())?;
        let to_m: Mailbox = to
            .parse()
            .map_err(|e: lettre::address::AddressError| e.to_string())?;
        let email = Message::builder()
            .from(from_m)
            .to(to_m)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)
            .map_err(|e| e.to_string())?;
        let mut builder = SmtpTransport::starttls_relay(&host)
            .map_err(|e| e.to_string())?
            .port(port)
            .timeout(Some(Duration::from_secs(15)));
        if !user.is_empty() {
            builder = builder.credentials(Credentials::new(user, pass));
        }
        builder.build().send(&email).map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
    .map_err(|e| format!("join: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_email_ok() {
        assert_eq!(validate_email("  A@B.co ").unwrap(), "a@b.co");
    }

    #[test]
    fn validate_email_rejects() {
        assert!(validate_email("nope").is_err());
        assert!(validate_email("a@@b.com").is_err());
    }

    #[test]
    fn clip_trims_and_caps() {
        assert_eq!(clip("  hi  ", 8), "hi");
        assert_eq!(clip(&"x".repeat(20), 5).len(), 5);
    }
}
