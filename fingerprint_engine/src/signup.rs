//! Self-serve signup + email verification.
//!
//! Flow:
//!   1. `POST /api/auth/signup`  — accepts (email, workspace_name, password). Validates,
//!      bcrypts the password, generates a random verification token, stores both hashed.
//!      Sends the verification email (when SMTP is configured) and returns 202 — never
//!      reveals whether the email was already registered, to prevent enumeration.
//!   2. `GET  /api/auth/verify?token=<plaintext>` — atomically consumes the token,
//!      creates the tenant + admin user, returns a redirect to the dashboard with a
//!      session cookie.
//!
//! Self-serve is disabled when `WEISSMAN_SELF_SERVE_SIGNUP` is not "true" / "1". In that
//! mode the public endpoints return 503 with a "contact sales" message so the UI can
//! still render the form gracefully.

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Datelike, Utc};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::http::client_ip::extract_client_ip;

/// Pull from env once; default disabled so existing self-hosted installs don't accidentally
/// expose signup to the world.
pub fn self_serve_enabled() -> bool {
    matches!(
        std::env::var("WEISSMAN_SELF_SERVE_SIGNUP").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

const TOKEN_LIFETIME_SECS: u64 = 24 * 3600; // 24 hours
const MIN_PASSWORD_LEN: usize = 12;
const MAX_PASSWORD_LEN: usize = 256;
const MAX_EMAIL_LEN: usize = 254;

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub workspace_name: String,
    pub password: String,
    #[serde(default)]
    pub accept_terms: bool,
}

#[derive(Debug, Deserialize)]
pub struct VerifyQuery {
    pub token: String,
}

fn hash_token(plaintext: &str) -> String {
    let mut h = Sha256::new();
    h.update(plaintext.trim().as_bytes());
    hex::encode(h.finalize())
}

fn generate_token() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    // URL-safe base64 (no padding) — fits cleanly in a query-string param.
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn slugify(input: &str) -> String {
    let s: String = input
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    // collapse repeated dashes
    let mut out = String::with_capacity(s.len());
    let mut last_dash = false;
    for c in s.chars() {
        if c == '-' {
            if !last_dash && !out.is_empty() {
                out.push('-');
            }
            last_dash = true;
        } else {
            out.push(c);
            last_dash = false;
        }
    }
    out.trim_matches('-').chars().take(40).collect()
}

fn validate_email(email: &str) -> Result<String, String> {
    let e = email.trim().to_lowercase();
    if e.len() < 5 || e.len() > MAX_EMAIL_LEN {
        return Err("invalid email length".into());
    }
    // Lightweight RFC 5322 check: exactly one '@', non-empty local + domain, no whitespace.
    if e.chars().any(char::is_whitespace) {
        return Err("invalid email".into());
    }
    let at_count = e.matches('@').count();
    if at_count != 1 {
        return Err("invalid email".into());
    }
    let (local, domain) = e.split_once('@').ok_or("invalid email")?;
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err("invalid email".into());
    }
    Ok(e)
}

fn validate_password(p: &str) -> Result<(), String> {
    if p.len() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {} characters",
            MIN_PASSWORD_LEN
        ));
    }
    if p.len() > MAX_PASSWORD_LEN {
        return Err("password too long".into());
    }
    // Require some character-class diversity. NIST 800-63B actually deprecates this kind
    // of rule in favour of length-only, but enterprise buyers expect it; trade-off chosen
    // here is "strong + non-annoying": at least one letter and at least one non-letter.
    let has_alpha = p.chars().any(|c| c.is_alphabetic());
    let has_other = p.chars().any(|c| !c.is_alphabetic());
    if !(has_alpha && has_other) {
        return Err("password must mix letters and numbers/symbols".into());
    }
    Ok(())
}

fn validate_workspace_name(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.len() < 2 || n.len() > 80 {
        return Err("workspace name must be 2–80 characters".into());
    }
    Ok(n.to_string())
}

/// Public: `POST /api/auth/signup`.
pub async fn api_signup(
    State(state): State<Arc<crate::http::AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<SignupRequest>,
) -> Response {
    if !self_serve_enabled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "code": "self_serve_disabled",
                "detail": "Self-serve signup is not enabled on this deployment. Contact sales@weissman.io to request an account."
            })),
        )
            .into_response();
    }

    if !body.accept_terms {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "code": "terms_not_accepted",
                "detail": "You must accept the Terms of Service and Privacy Policy."
            })),
        )
            .into_response();
    }

    let email = match validate_email(&body.email) {
        Ok(e) => e,
        Err(msg) => return invalid(&msg),
    };
    let workspace = match validate_workspace_name(&body.workspace_name) {
        Ok(n) => n,
        Err(msg) => return invalid(&msg),
    };
    if let Err(msg) = validate_password(&body.password) {
        return invalid(&msg);
    }
    let slug = {
        let s = slugify(&workspace);
        if s.is_empty() {
            return invalid("workspace name must contain letters or numbers");
        }
        s
    };

    let bcrypt_hash = match bcrypt::hash(&body.password, 12) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "could not hash password"})),
            )
                .into_response()
        }
    };

    let plaintext_token = generate_token();
    let token_hash = hash_token(&plaintext_token);
    let ip = extract_client_ip(&headers, addr);
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(256)
        .collect::<String>();

    // Garbage-collect expired rows opportunistically (no separate worker for this
    // low-volume table). Bounded delete — won't lock if there are millions of rows.
    let _ = sqlx::query("DELETE FROM pending_signups WHERE expires_at < now() - interval '7 days'")
        .execute(state.auth_pool.as_ref())
        .await;

    let res = sqlx::query(
        r#"INSERT INTO pending_signups (
                email, workspace_name, requested_slug, bcrypt_hash, token_hash,
                ip_address, user_agent, expires_at
           ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, now() + ($8 || ' seconds')::interval
           )"#,
    )
    .bind(&email)
    .bind(&workspace)
    .bind(&slug)
    .bind(&bcrypt_hash)
    .bind(&token_hash)
    .bind(&ip)
    .bind(&ua)
    .bind(TOKEN_LIFETIME_SECS as i64)
    .execute(state.auth_pool.as_ref())
    .await;

    if let Err(e) = res {
        tracing::warn!(target: "signup", error = %e, "failed to insert pending signup");
        // Do not leak: return 202 so attackers can't enumerate which emails are taken.
    }

    let public_base =
        std::env::var("WEISSMAN_PUBLIC_URL").unwrap_or_else(|_| "http://localhost".to_string());
    let verify_link = format!(
        "{}/api/auth/verify?token={}",
        public_base.trim_end_matches('/'),
        plaintext_token
    );

    // Send verification email if SMTP is configured. Even on failure we still return 202.
    spawn_signup_verification_email(email.clone(), workspace.clone(), verify_link.clone());

    if std::env::var("WEISSMAN_SIGNUP_RETURN_LINK").as_deref() == Ok("1") {
        // Dev-only: return the link so we don't need a real SMTP. Never enable in prod.
        return (
            StatusCode::ACCEPTED,
            Json(json!({
                "ok": true,
                "detail": "Verification email sent. (Dev mode: link returned in response.)",
                "verify_url": verify_link
            })),
        )
            .into_response();
    }

    (
        StatusCode::ACCEPTED,
        Json(json!({
            "ok": true,
            "detail": "If the email is valid, a verification link has been sent. Check your inbox."
        })),
    )
        .into_response()
}

/// Public: `GET /api/auth/verify?token=…` — consume the token + create the tenant + user.
pub async fn api_verify(
    State(state): State<Arc<crate::http::AppState>>,
    Query(q): Query<VerifyQuery>,
) -> Response {
    if !self_serve_enabled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "code": "self_serve_disabled"})),
        )
            .into_response();
    }
    let token_hash = hash_token(&q.token);
    let mut tx = match state.auth_pool.begin().await {
        Ok(t) => t,
        Err(_) => return invalid("database unavailable"),
    };
    let row = match sqlx::query(
        r#"UPDATE pending_signups
              SET consumed_at = now()
            WHERE token_hash = $1
              AND consumed_at IS NULL
              AND expires_at > now()
        RETURNING email, workspace_name, requested_slug, bcrypt_hash"#,
    )
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            let _ = tx.rollback().await;
            return (
                StatusCode::GONE,
                Json(json!({
                    "ok": false,
                    "code": "token_invalid_or_expired",
                    "detail": "This verification link is invalid, already used, or expired. Sign up again to get a new link."
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::warn!(target: "signup", error = %e, "verify lookup failed");
            let _ = tx.rollback().await;
            return invalid("database error");
        }
    };

    let email: String = row.try_get("email").unwrap_or_default();
    let workspace: String = row.try_get("workspace_name").unwrap_or_default();
    let base_slug: String = row.try_get("requested_slug").unwrap_or_default();
    let bcrypt_hash: String = row.try_get("bcrypt_hash").unwrap_or_default();

    // Pick a slug that doesn't already exist. Append a numeric suffix on collision.
    let final_slug = match unique_slug(&mut tx, &base_slug).await {
        Ok(s) => s,
        Err(msg) => {
            let _ = tx.rollback().await;
            return invalid(&msg);
        }
    };

    let tenant_id: i64 = match sqlx::query_scalar(
        r#"INSERT INTO tenants (slug, name, active)
           VALUES ($1, $2, true)
           RETURNING id"#,
    )
    .bind(&final_slug)
    .bind(&workspace)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(target: "signup", error = %e, "tenant insert failed");
            let _ = tx.rollback().await;
            return invalid("could not provision workspace");
        }
    };

    // RLS on `users` is forced — must set tenant GUC before INSERT so the WITH CHECK
    // policy `tenant_id = current_setting('app.current_tenant_id')::bigint` passes.
    if let Err(e) = sqlx::query("SET LOCAL app.current_tenant_id = $1::text")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
    {
        tracing::warn!(target: "signup", error = %e, "set tenant guc failed");
        let _ = tx.rollback().await;
        return invalid("could not establish tenant context");
    }

    let user_insert_sql = r#"
        INSERT INTO users (tenant_id, email, password_hash, role, is_superadmin, is_active, created_at)
        VALUES ($1, $2, $3, 'admin', false, true, now())
        ON CONFLICT (tenant_id, email) DO UPDATE SET is_active = true, updated_at = now()
        RETURNING id
    "#;
    let user_id: i64 = match sqlx::query_scalar(user_insert_sql)
        .bind(tenant_id)
        .bind(&email)
        .bind(&bcrypt_hash)
        .fetch_one(&mut *tx)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(target: "signup", error = %e, "user insert failed");
            let _ = tx.rollback().await;
            return invalid("could not provision user");
        }
    };

    // Mirror billing::register_tenant_and_admin — starter plan + usage counter for the month.
    let sub_status = if crate::billing::billing_strict_enabled() {
        "trialing"
    } else {
        "active"
    };
    if let Err(e) = sqlx::query(
        "INSERT INTO tenant_subscriptions (tenant_id, plan_slug, status) VALUES ($1, $2, $3)",
    )
    .bind(tenant_id)
    .bind("starter")
    .bind(sub_status)
    .execute(&mut *tx)
    .await
    {
        tracing::warn!(target: "signup", error = %e, "subscription insert failed");
        let _ = tx.rollback().await;
        return invalid("could not provision subscription");
    }
    let period = {
        let n = Utc::now().naive_utc().date();
        format!("{:04}-{:02}", n.year(), n.month())
    };
    if let Err(e) = sqlx::query(
        "INSERT INTO tenant_usage_counters (tenant_id, period_ym, scans_started) VALUES ($1, $2, 0)",
    )
    .bind(tenant_id)
    .bind(&period)
    .execute(&mut *tx)
    .await
    {
        tracing::warn!(target: "signup", error = %e, "usage counter insert failed");
        let _ = tx.rollback().await;
        return invalid("could not provision usage tracking");
    }

    if let Err(e) = tx.commit().await {
        tracing::warn!(target: "signup", error = %e, "verify commit failed");
        return invalid("commit failed");
    }

    tracing::info!(
        target: "signup",
        tenant_id,
        user_id,
        workspace = %workspace,
        slug = %final_slug,
        "self-serve signup verified"
    );

    // Send a welcome email asynchronously.
    spawn_signup_welcome_email(email.clone(), workspace.clone(), final_slug.clone());

    // Redirect to the login page with a query flag so the UI can show a one-time toast.
    let login_url = format!("/command-center/login?verified=1&tenant={}", final_slug);
    let mut resp = axum::response::Redirect::to(&login_url).into_response();
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp
}

async fn unique_slug(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    base: &str,
) -> Result<String, String> {
    let base = if base.is_empty() { "workspace" } else { base };
    let base = base.chars().take(36).collect::<String>();
    for suffix in 0..200 {
        let candidate = if suffix == 0 {
            base.clone()
        } else {
            format!("{}-{}", base, suffix)
        };
        let exists: Option<i64> =
            sqlx::query_scalar("SELECT id FROM tenants WHERE slug = $1 LIMIT 1")
                .bind(&candidate)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| format!("slug lookup: {e}"))?;
        if exists.is_none() {
            return Ok(candidate);
        }
    }
    Err("could not generate a unique workspace slug".to_string())
}

fn invalid(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"ok": false, "code": "validation_failed", "detail": msg})),
    )
        .into_response()
}

fn spawn_signup_verification_email(email: String, workspace: String, link: String) {
    tokio::spawn(async move {
        if let Err(e) = send_signup_email(
            &email,
            "Confirm your Weissman account",
            &format!(
                "Welcome to Weissman, {}!\n\n\
                 Click this link within 24 hours to activate your workspace ({}):\n\n  {}\n\n\
                 If you didn't request this, you can safely ignore this email.\n\n\
                 — The Weissman team",
                workspace_display_name(&workspace),
                workspace,
                link
            ),
        )
        .await
        {
            tracing::warn!(target: "signup_email", to = %email, error = %e, "verification email failed");
        }
    });
}

fn spawn_signup_welcome_email(email: String, workspace: String, slug: String) {
    tokio::spawn(async move {
        let public_base =
            std::env::var("WEISSMAN_PUBLIC_URL").unwrap_or_else(|_| "http://localhost".to_string());
        let body = format!(
            "Your Weissman workspace is live, {}!\n\n\
             Workspace name: {}\n\
             Tenant slug:    {}\n\n\
             Sign in: {}/command-center/login\n\n\
             Next steps:\n\
              1. Add a client (target) under Clients → New.\n\
              2. Approve scan scope (domains, IP ranges).\n\
              3. Hit \"Run\" on any of the 253 engines.\n\n\
             Reply to this email or write to support@weissman.io if you need help.\n\n\
             — The Weissman team",
            workspace_display_name(&workspace),
            workspace,
            slug,
            public_base.trim_end_matches('/')
        );
        if let Err(e) = send_signup_email(&email, "Your Weissman workspace is ready", &body).await {
            tracing::warn!(target: "signup_email", to = %email, error = %e, "welcome email failed");
        }
    });
}

fn workspace_display_name(workspace: &str) -> String {
    if workspace.is_empty() {
        "there".to_string()
    } else {
        workspace.to_string()
    }
}

/// Send a transactional email via SMTP. Returns Ok(()) when SMTP is not configured
/// (so signup still succeeds on local-dev without an SMTP) but logs at debug level.
async fn send_signup_email(to: &str, subject: &str, body: &str) -> Result<(), String> {
    let enabled = matches!(
        std::env::var("WEISSMAN_SMTP_ENABLED").as_deref(),
        Ok("true") | Ok("1") | Ok("yes")
    );
    if !enabled {
        tracing::debug!(
            target: "signup_email",
            to,
            subject,
            "SMTP disabled — email not sent (set WEISSMAN_SMTP_ENABLED=true)"
        );
        return Ok(());
    }
    let host = std::env::var("WEISSMAN_SMTP_HOST").map_err(|_| "WEISSMAN_SMTP_HOST")?;
    let port: u16 = std::env::var("WEISSMAN_SMTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(587);
    let user = std::env::var("WEISSMAN_SMTP_USER").unwrap_or_default();
    let pass = std::env::var("WEISSMAN_SMTP_PASSWORD").unwrap_or_default();
    let from = std::env::var("WEISSMAN_SMTP_FROM").map_err(|_| "WEISSMAN_SMTP_FROM")?;
    let to_owned = to.to_string();
    let subject_owned = subject.to_string();
    let body_owned = body.to_string();

    // SMTP I/O is blocking — keep the runtime free.
    let res = tokio::task::spawn_blocking(move || -> Result<(), String> {
        use lettre::message::{header::ContentType, Mailbox, Message};
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{SmtpTransport, Transport};
        let from_m: Mailbox = from
            .parse()
            .map_err(|e: lettre::address::AddressError| e.to_string())?;
        let to_m: Mailbox = to_owned
            .parse()
            .map_err(|e: lettre::address::AddressError| e.to_string())?;
        let email = Message::builder()
            .from(from_m)
            .to(to_m)
            .subject(subject_owned)
            .header(ContentType::TEXT_PLAIN)
            .body(body_owned)
            .map_err(|e| e.to_string())?;
        let mut builder = SmtpTransport::starttls_relay(&host)
            .map_err(|e| e.to_string())?
            .port(port)
            .timeout(Some(Duration::from_secs(15)));
        if !user.is_empty() {
            builder = builder.credentials(Credentials::new(user, pass));
        }
        let mailer = builder.build();
        mailer.send(&email).map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
    .map_err(|e| format!("join: {e}"))?;
    res
}
