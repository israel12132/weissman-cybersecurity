//! Enterprise SSO management: CRUD for `tenant_idps`, Test-Connection verification.
//!
//! These endpoints are operator-facing (require JWT auth). They allow administrators to
//! configure IdP connections (Okta, Azure AD, Google Workspace, Ping Identity, custom SAML/OIDC)
//! without touching the database directly.
//!
//! Routes (registered in `serve.rs`):
//!   GET    /api/sso/idps            — list all IdPs for the tenant
//!   POST   /api/sso/idps            — create a new IdP config
//!   GET    /api/sso/idps/:id        — get one IdP config
//!   PATCH  /api/sso/idps/:id        — update IdP config
//!   DELETE /api/sso/idps/:id        — remove an IdP config
//!   POST   /api/sso/idps/:id/test   — Test Connection (OIDC discovery or SAML metadata fetch)
//!   POST   /api/sso/idps/:id/toggle — toggle active/inactive

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::sync::Arc;

use crate::db;
use crate::http::AppState;
use crate::auth_jwt::AuthContext;

// ─── Request / response shapes ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateIdpBody {
    /// Human-readable label for this IdP (e.g. "Okta Production").
    pub name: String,
    /// Protocol: "oidc" or "saml".
    pub provider: String,
    /// UI vendor hint: okta | azure_ad | google | ping | saml_custom | oidc_custom
    #[serde(default = "default_vendor_hint")]
    pub vendor_hint: String,

    // ── OIDC fields ───────────────────────────────────────────────────────────
    #[serde(default)]
    pub issuer_url: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_path: Option<String>,
    #[serde(default)]
    pub email_claim: Option<String>,
    #[serde(default)]
    pub jwks_uri_override: Option<String>,

    // ── Azure AD ──────────────────────────────────────────────────────────────
    #[serde(default)]
    pub azure_tenant_id: Option<String>,

    // ── Okta ──────────────────────────────────────────────────────────────────
    #[serde(default)]
    pub okta_domain: Option<String>,

    // ── SAML fields ───────────────────────────────────────────────────────────
    #[serde(default)]
    pub saml_idp_sso_url: Option<String>,
    #[serde(default)]
    pub saml_idp_cert_pem: Option<String>,
    #[serde(default)]
    pub sp_entity_id: Option<String>,

    #[serde(default = "default_active")]
    pub active: bool,
}

#[derive(Debug, Deserialize)]
pub struct PatchIdpBody {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub vendor_hint: Option<String>,
    #[serde(default)]
    pub issuer_url: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_path: Option<String>,
    #[serde(default)]
    pub email_claim: Option<String>,
    #[serde(default)]
    pub jwks_uri_override: Option<String>,
    #[serde(default)]
    pub azure_tenant_id: Option<String>,
    #[serde(default)]
    pub okta_domain: Option<String>,
    #[serde(default)]
    pub saml_idp_sso_url: Option<String>,
    #[serde(default)]
    pub saml_idp_cert_pem: Option<String>,
    #[serde(default)]
    pub sp_entity_id: Option<String>,
    #[serde(default)]
    pub active: Option<bool>,
}

fn default_vendor_hint() -> String {
    "oidc_custom".to_string()
}
fn default_active() -> bool {
    true
}

fn norm_vendor_hint(h: &str) -> &str {
    match h {
        "okta" | "azure_ad" | "google" | "ping" | "saml_custom" | "oidc_custom" => h,
        _ => "oidc_custom",
    }
}

fn norm_provider(p: &str) -> Option<&str> {
    match p {
        "oidc" | "saml" => Some(p),
        _ => None,
    }
}

/// Build a JSON row from a sqlx `Row` fetched from `tenant_idps`.
fn row_to_json(r: &sqlx::postgres::PgRow) -> Value {
    json!({
        "id":               r.try_get::<i64,_>("id").ok(),
        "name":             r.try_get::<String,_>("name").ok(),
        "provider":         r.try_get::<String,_>("provider").ok(),
        "vendor_hint":      r.try_get::<String,_>("vendor_hint").ok(),
        "issuer_url":       r.try_get::<String,_>("issuer_url").ok(),
        "client_id":        r.try_get::<String,_>("client_id").ok(),
        // client_secret intentionally omitted from responses (write-only)
        "redirect_path":    r.try_get::<String,_>("redirect_path").ok(),
        "email_claim":      r.try_get::<String,_>("email_claim").ok(),
        "jwks_uri_override":r.try_get::<Option<String>,_>("jwks_uri_override").ok().flatten(),
        "azure_tenant_id":  r.try_get::<Option<String>,_>("azure_tenant_id").ok().flatten(),
        "okta_domain":      r.try_get::<Option<String>,_>("okta_domain").ok().flatten(),
        "saml_idp_sso_url": r.try_get::<Option<String>,_>("saml_idp_sso_url").ok().flatten(),
        // saml_idp_cert_pem returned (public key material, not secret)
        "saml_idp_cert_pem":r.try_get::<Option<String>,_>("saml_idp_cert_pem").ok().flatten(),
        "sp_entity_id":     r.try_get::<Option<String>,_>("sp_entity_id").ok().flatten(),
        "active":           r.try_get::<bool,_>("active").ok(),
        "last_test_at":     r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("last_test_at").ok().flatten(),
        "last_test_ok":     r.try_get::<Option<bool>,_>("last_test_ok").ok().flatten(),
        "last_test_error":  r.try_get::<Option<String>,_>("last_test_error").ok().flatten(),
        "created_at":       r.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at").ok(),
    })
}

// ─── GET /api/sso/idps ────────────────────────────────────────────────────────

pub async fn api_sso_idps_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": e.to_string()}))).into_response(),
    };
    let rows = sqlx::query(
        r#"SELECT id, name, provider, vendor_hint, issuer_url, client_id,
                  redirect_path, email_claim, jwks_uri_override,
                  azure_tenant_id, okta_domain,
                  saml_idp_sso_url, saml_idp_cert_pem, sp_entity_id,
                  active, last_test_at, last_test_ok, last_test_error, created_at
           FROM tenant_idps
           WHERE tenant_id = $1
           ORDER BY created_at DESC"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&mut *tx)
    .await;
    let _ = tx.commit().await;

    match rows {
        Ok(rows) => {
            let items: Vec<Value> = rows.iter().map(row_to_json).collect();
            Json(json!({"idps": items, "count": items.len()})).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

// ─── POST /api/sso/idps ───────────────────────────────────────────────────────

pub async fn api_sso_idps_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<CreateIdpBody>,
) -> Response {
    let name = body.name.trim().to_string();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "name required"}))).into_response();
    }
    let Some(provider) = norm_provider(body.provider.trim()) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "provider must be 'oidc' or 'saml'"}))).into_response();
    };
    let vendor_hint = norm_vendor_hint(body.vendor_hint.trim()).to_string();
    let issuer_url = body.issuer_url.as_deref().unwrap_or("").trim().to_string();
    let client_id = body.client_id.as_deref().unwrap_or("").trim().to_string();
    let redirect_path = body.redirect_path.as_deref().unwrap_or("/api/auth/oidc/callback").trim().to_string();
    let email_claim = body.email_claim.as_deref().unwrap_or("email").trim().to_string();

    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": e.to_string()}))).into_response(),
    };

    let row = sqlx::query(
        r#"INSERT INTO tenant_idps
               (tenant_id, provider, vendor_hint, name, issuer_url, client_id,
                client_secret, redirect_path, email_claim, jwks_uri_override,
                azure_tenant_id, okta_domain,
                saml_idp_sso_url, saml_idp_cert_pem, sp_entity_id, active)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
           RETURNING id, name, provider, vendor_hint, issuer_url, client_id,
                     redirect_path, email_claim, jwks_uri_override,
                     azure_tenant_id, okta_domain,
                     saml_idp_sso_url, saml_idp_cert_pem, sp_entity_id,
                     active, last_test_at, last_test_ok, last_test_error, created_at"#,
    )
    .bind(auth.tenant_id)
    .bind(provider)
    .bind(&vendor_hint)
    .bind(&name)
    .bind(&issuer_url)
    .bind(&client_id)
    .bind(body.client_secret.as_deref())
    .bind(&redirect_path)
    .bind(&email_claim)
    .bind(body.jwks_uri_override.as_deref())
    .bind(body.azure_tenant_id.as_deref())
    .bind(body.okta_domain.as_deref())
    .bind(body.saml_idp_sso_url.as_deref())
    .bind(body.saml_idp_cert_pem.as_deref())
    .bind(body.sp_entity_id.as_deref())
    .bind(body.active)
    .fetch_one(&mut *tx)
    .await;

    let _ = tx.commit().await;

    match row {
        Ok(r) => (StatusCode::CREATED, Json(row_to_json(&r))).into_response(),
        Err(e) if e.to_string().contains("unique") || e.to_string().contains("duplicate") => {
            (StatusCode::CONFLICT, Json(json!({"error": "name already exists for this tenant"}))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

// ─── GET /api/sso/idps/:id ────────────────────────────────────────────────────

pub async fn api_sso_idp_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(idp_id): Path<i64>,
) -> Response {
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": e.to_string()}))).into_response(),
    };
    let row = sqlx::query(
        r#"SELECT id, name, provider, vendor_hint, issuer_url, client_id,
                  redirect_path, email_claim, jwks_uri_override,
                  azure_tenant_id, okta_domain,
                  saml_idp_sso_url, saml_idp_cert_pem, sp_entity_id,
                  active, last_test_at, last_test_ok, last_test_error, created_at
           FROM tenant_idps
           WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(idp_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await;
    let _ = tx.commit().await;

    match row {
        Ok(Some(r)) => Json(row_to_json(&r)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

// ─── PATCH /api/sso/idps/:id ──────────────────────────────────────────────────

pub async fn api_sso_idp_patch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(idp_id): Path<i64>,
    Json(body): Json<PatchIdpBody>,
) -> Response {
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": e.to_string()}))).into_response(),
    };

    // Build dynamic SET clause only for provided fields
    let mut sets: Vec<String> = Vec::new();
    let mut idx: i32 = 3; // $1 = id, $2 = tenant_id

    macro_rules! push_field {
        ($opt:expr, $col:literal) => {
            if $opt.is_some() {
                sets.push(format!("{} = ${}", $col, idx));
                idx += 1;
            }
        };
    }
    push_field!(body.name, "name");
    push_field!(body.vendor_hint, "vendor_hint");
    push_field!(body.issuer_url, "issuer_url");
    push_field!(body.client_id, "client_id");
    push_field!(body.client_secret, "client_secret");
    push_field!(body.redirect_path, "redirect_path");
    push_field!(body.email_claim, "email_claim");
    push_field!(body.jwks_uri_override, "jwks_uri_override");
    push_field!(body.azure_tenant_id, "azure_tenant_id");
    push_field!(body.okta_domain, "okta_domain");
    push_field!(body.saml_idp_sso_url, "saml_idp_sso_url");
    push_field!(body.saml_idp_cert_pem, "saml_idp_cert_pem");
    push_field!(body.sp_entity_id, "sp_entity_id");
    push_field!(body.active, "active");

    if sets.is_empty() {
        let _ = tx.rollback().await;
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "no fields to update"}))).into_response();
    }

    let sql = format!(
        r#"UPDATE tenant_idps SET {}
           WHERE id = $1 AND tenant_id = $2
           RETURNING id, name, provider, vendor_hint, issuer_url, client_id,
                     redirect_path, email_claim, jwks_uri_override,
                     azure_tenant_id, okta_domain,
                     saml_idp_sso_url, saml_idp_cert_pem, sp_entity_id,
                     active, last_test_at, last_test_ok, last_test_error, created_at"#,
        sets.join(", ")
    );

    let mut q = sqlx::query(&sql).bind(idp_id).bind(auth.tenant_id);

    if let Some(v) = body.name.as_deref() { q = q.bind(v.trim()); }
    if let Some(v) = body.vendor_hint.as_deref() { q = q.bind(norm_vendor_hint(v.trim())); }
    if let Some(v) = body.issuer_url.as_deref() { q = q.bind(v.trim()); }
    if let Some(v) = body.client_id.as_deref() { q = q.bind(v.trim()); }
    if let Some(v) = body.client_secret.as_deref() { q = q.bind(v); }
    if let Some(v) = body.redirect_path.as_deref() { q = q.bind(v.trim()); }
    if let Some(v) = body.email_claim.as_deref() { q = q.bind(v.trim()); }
    if let Some(v) = body.jwks_uri_override.as_deref() { q = q.bind(v.trim()); }
    if let Some(v) = body.azure_tenant_id.as_deref() { q = q.bind(v.trim()); }
    if let Some(v) = body.okta_domain.as_deref() { q = q.bind(v.trim()); }
    if let Some(v) = body.saml_idp_sso_url.as_deref() { q = q.bind(v.trim()); }
    if let Some(v) = body.saml_idp_cert_pem.as_deref() { q = q.bind(v); }
    if let Some(v) = body.sp_entity_id.as_deref() { q = q.bind(v.trim()); }
    if let Some(v) = body.active { q = q.bind(v); }

    let row = q.fetch_optional(&mut *tx).await;
    let _ = tx.commit().await;

    match row {
        Ok(Some(r)) => Json(row_to_json(&r)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

// ─── DELETE /api/sso/idps/:id ─────────────────────────────────────────────────

pub async fn api_sso_idp_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(idp_id): Path<i64>,
) -> Response {
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": e.to_string()}))).into_response(),
    };
    let deleted: Option<i64> = sqlx::query_scalar(
        "DELETE FROM tenant_idps WHERE id = $1 AND tenant_id = $2 RETURNING id",
    )
    .bind(idp_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;

    if deleted.is_some() {
        Json(json!({"ok": true, "deleted_id": idp_id})).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response()
    }
}

// ─── POST /api/sso/idps/:id/toggle ───────────────────────────────────────────

pub async fn api_sso_idp_toggle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(idp_id): Path<i64>,
) -> Response {
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": e.to_string()}))).into_response(),
    };
    let new_active: Option<bool> = sqlx::query_scalar(
        "UPDATE tenant_idps SET active = NOT active WHERE id = $1 AND tenant_id = $2 RETURNING active",
    )
    .bind(idp_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;

    match new_active {
        Some(a) => Json(json!({"ok": true, "id": idp_id, "active": a})).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
    }
}

// ─── POST /api/sso/idps/:id/test — Test Connection ───────────────────────────
//
// For OIDC: performs OpenID Connect discovery (GET {issuer_url}/.well-known/openid-configuration)
// and validates the response shape.
// For SAML: fetches the metadata URL (saml_idp_sso_url) and checks for XML.
// Records the result in last_test_at / last_test_ok / last_test_error.

pub async fn api_sso_idp_test(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(idp_id): Path<i64>,
) -> Response {
    // Fetch IdP config
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": e.to_string()}))).into_response(),
    };
    let row = sqlx::query(
        "SELECT provider, issuer_url, saml_idp_sso_url FROM tenant_idps WHERE id = $1 AND tenant_id = $2",
    )
    .bind(idp_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await;
    let _ = tx.commit().await;

    let Ok(Some(row)) = row else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response();
    };
    let provider: String = row.try_get("provider").unwrap_or_default();
    let issuer_url: String = row.try_get("issuer_url").unwrap_or_default();
    let saml_url: Option<String> = row.try_get("saml_idp_sso_url").ok().flatten();

    // Perform the connectivity test
    let (ok, error_msg, detail) = perform_test_connection(&provider, &issuer_url, saml_url.as_deref()).await;

    // Persist the result
    let mut tx2 = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => {
            // Return the test result even if we can't persist
            return Json(json!({"ok": ok, "error": error_msg, "detail": detail})).into_response();
        }
    };
    let _ = sqlx::query(
        r#"UPDATE tenant_idps
           SET last_test_at = now(), last_test_ok = $1, last_test_error = $2
           WHERE id = $3 AND tenant_id = $4"#,
    )
    .bind(ok)
    .bind(error_msg.as_deref())
    .bind(idp_id)
    .bind(auth.tenant_id)
    .execute(&mut *tx2)
    .await;
    let _ = tx2.commit().await;

    let status = if ok { StatusCode::OK } else { StatusCode::BAD_GATEWAY };
    (status, Json(json!({"ok": ok, "error": error_msg, "detail": detail}))).into_response()
}

/// Performs the actual test without auth context — safe for the Rust async runtime.
async fn perform_test_connection(
    provider: &str,
    issuer_url: &str,
    saml_url: Option<&str>,
) -> (bool, Option<String>, Value) {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("Weissman-SSO-Test/1.0")
        .build()
    {
        Ok(c) => c,
        Err(e) => return (false, Some(e.to_string()), json!({})),
    };

    if provider == "oidc" {
        // OIDC discovery
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        match client.get(&discovery_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<Value>().await {
                    Ok(doc) => {
                        let has_issuer = doc.get("issuer").is_some();
                        let has_jwks = doc.get("jwks_uri").is_some();
                        if has_issuer && has_jwks {
                            (true, None, json!({
                                "discovery_url": discovery_url,
                                "issuer": doc.get("issuer"),
                                "authorization_endpoint": doc.get("authorization_endpoint"),
                                "token_endpoint": doc.get("token_endpoint"),
                                "userinfo_endpoint": doc.get("userinfo_endpoint"),
                                "jwks_uri": doc.get("jwks_uri"),
                            }))
                        } else {
                            (false, Some("discovery document missing issuer or jwks_uri".to_string()), doc)
                        }
                    }
                    Err(e) => (false, Some(format!("invalid JSON: {e}")), json!({})),
                }
            }
            Ok(resp) => (
                false,
                Some(format!("HTTP {}", resp.status())),
                json!({"discovery_url": discovery_url}),
            ),
            Err(e) => (false, Some(e.to_string()), json!({"discovery_url": discovery_url})),
        }
    } else {
        // SAML: attempt to fetch metadata / SSO URL
        let url = saml_url.unwrap_or(issuer_url);
        if url.is_empty() {
            return (false, Some("saml_idp_sso_url not configured".to_string()), json!({}));
        }
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let body = resp.text().await.unwrap_or_default();
                let is_xml = body.trim_start().starts_with('<');
                if is_xml {
                    (true, None, json!({"url": url, "content_type": content_type, "byte_length": body.len()}))
                } else {
                    (false, Some("response does not look like SAML XML/metadata".to_string()), json!({"url": url}))
                }
            }
            Ok(resp) => (
                false,
                Some(format!("HTTP {}", resp.status())),
                json!({"url": url}),
            ),
            Err(e) => (false, Some(e.to_string()), json!({"url": url})),
        }
    }
}
