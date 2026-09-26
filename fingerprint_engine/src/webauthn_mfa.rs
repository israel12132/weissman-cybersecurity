//! WebAuthn / FIDO2 passkeys — phishing-resistant MFA factor (server-side ceremony).
//!
//! This is an ADDITIONAL second factor alongside TOTP ([`crate::auth_mfa`]). A passkey
//! is bound to this relying party's origin, so a phished credential cannot be replayed
//! against `WEISSMAN_PUBLIC_BASE_URL` — the defining property TOTP lacks.
//!
//! Ceremony state (the `PasskeyRegistration` / `PasskeyAuthentication` produced by
//! `start_*` and consumed by `finish_*`) must survive between the two stateless HTTP
//! calls, so it is persisted server-side, keyed by user, with a short TTL:
//!   - `webauthn_reg_state`  — pending registration state (authed enrolment).
//!   - `webauthn_auth_state` — pending authentication state (login second factor).
//! Enrolled credentials live in `webauthn_credentials` (one row per passkey).
//!
//! All three tables are FORCE-RLS tenant-scoped, so every access runs inside a
//! `db::begin_tenant_tx`. Unlike service-account API keys, there is no pre-session
//! lookup here: registration runs under a live `AuthContext`, and authentication runs
//! under the `mfa_pending` token minted by `/api/login`, which carries the tenant — so
//! no `SECURITY DEFINER` shim is needed.
//!
//! webauthn-rs 0.5.x API (exact): `WebauthnBuilder::new(rp_id, &rp_origin)?.build()?`,
//! `start_passkey_registration(uuid, name, display, exclude)`,
//! `finish_passkey_registration(&reg, &state)`, `start_passkey_authentication(&passkeys)`,
//! `finish_passkey_authentication(&auth, &state)`. `Passkey` serialises via serde; the
//! two `*State` types serialise only with the `danger-allow-state-serialisation` feature.

use axum::{
    extract::{Extension, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::sync::Arc;

use webauthn_rs::prelude::{
    CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Uuid, Webauthn, WebauthnBuilder,
};

use crate::auth_jwt::{self, AuthContext};
use crate::db;
use crate::http::AppState;

const RP_NAME: &str = "Weissman-Cybersecurity";

// ── Small response helpers (mirror crate::api_keys) ────────────────────────────
fn bad_request(detail: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "detail": detail })),
    )
        .into_response()
}

fn unauthorized(detail: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "ok": false, "detail": detail })),
    )
        .into_response()
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "ok": false,
            "detail": "Authentication service temporarily unavailable",
            "code": "auth_degraded"
        })),
    )
        .into_response()
}

/// Append a `Set-Cookie` line (self-contained: the private `append_set_cookie` in
/// `server_handlers_auth.inc` is not reachable from a normal module).
fn append_set_cookie(headers: &mut HeaderMap, line: &str) {
    if let Ok(v) = HeaderValue::from_str(line) {
        headers.append(SET_COOKIE, v);
    }
}

/// Public origin used to derive the relying-party id + origin, exactly as OIDC/SAML do.
fn public_base_url() -> String {
    std::env::var("WEISSMAN_PUBLIC_BASE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8000".to_string())
}

/// Build a `Webauthn` from `WEISSMAN_PUBLIC_BASE_URL` (rp_id = host, rp_origin = full URL).
///
/// `WebauthnBuilder::new` borrows both `rp_id: &'a str` and `rp_origin: &'a Url`, so the
/// parsed URL and the host string are held in locals that outlive the builder; `.build()`
/// consumes the builder and returns an owned, lifetime-free `Webauthn`.
fn build_webauthn() -> Result<Webauthn, String> {
    let base = public_base_url();
    let rp_origin =
        Url::parse(&base).map_err(|e| format!("invalid WEISSMAN_PUBLIC_BASE_URL: {e}"))?;
    let rp_id = rp_origin
        .host_str()
        .ok_or_else(|| "WEISSMAN_PUBLIC_BASE_URL has no host component".to_string())?
        .to_string();
    WebauthnBuilder::new(&rp_id, &rp_origin)
        .map_err(|e| e.to_string())?
        .rp_name(RP_NAME)
        .build()
        .map_err(|e| e.to_string())
}

/// Deterministic per-user WebAuthn user handle. Stable across enrolments (so
/// `excludeCredentials` and the authenticator's stored handle stay consistent) and
/// derived without a schema column via SHA-256 → 16 bytes → UUID. `Uuid::from_bytes`
/// needs no extra `uuid` crate feature.
fn user_handle(tenant_id: i64, user_id: i64) -> Uuid {
    let mut h = Sha256::new();
    h.update(format!("weissman-webauthn:{tenant_id}:{user_id}").as_bytes());
    let digest = h.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

/// Load all enrolled passkeys for a user inside an existing tenant tx.
/// JSONB is read via `passkey::text` (the crate does not enable the sqlx `json`
/// feature) and deserialised with serde_json.
async fn load_passkeys(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    user_id: i64,
) -> Result<Vec<Passkey>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT passkey::text AS passkey FROM webauthn_credentials \
         WHERE tenant_id = $1 AND user_id = $2 ORDER BY id",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let s: String = r.try_get("passkey").unwrap_or_default();
        if let Ok(pk) = serde_json::from_str::<Passkey>(&s) {
            out.push(pk);
        }
    }
    Ok(out)
}

// ── Registration (authed: enrol a passkey for the current session user) ─────────

/// POST /api/auth/webauthn/register/start — begin passkey enrolment.
/// Returns a `CreationChallengeResponse` (browser `navigator.credentials.create`).
pub async fn api_webauthn_register_start(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let webauthn = match build_webauthn() {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(target: "webauthn", error = %e, "webauthn build failed");
            return unavailable();
        }
    };
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => return unavailable(),
    };
    // Username / display name for the authenticator UI.
    let email = match sqlx::query(
        "SELECT COALESCE(NULLIF(trim(email), ''), '') AS email \
         FROM users WHERE id = $1 AND tenant_id = $2 AND is_active = true",
    )
    .bind(auth.user_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(r)) => r.try_get::<String, _>("email").unwrap_or_default(),
        Ok(None) => {
            let _ = tx.rollback().await;
            return unauthorized("User not found");
        }
        Err(_) => {
            let _ = tx.rollback().await;
            return unavailable();
        }
    };
    let display = if email.is_empty() {
        format!("user-{}", auth.user_id)
    } else {
        email.clone()
    };
    // Exclude already-enrolled credentials so the authenticator refuses a duplicate.
    let existing = match load_passkeys(&mut tx, auth.tenant_id, auth.user_id).await {
        Ok(v) => v,
        Err(_) => {
            let _ = tx.rollback().await;
            return unavailable();
        }
    };
    let exclude: Vec<CredentialID> = existing.iter().map(|pk| pk.cred_id().clone()).collect();
    let exclude = if exclude.is_empty() {
        None
    } else {
        Some(exclude)
    };

    let (ccr, reg_state) = match webauthn.start_passkey_registration(
        user_handle(auth.tenant_id, auth.user_id),
        &display,
        &display,
        exclude,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = tx.rollback().await;
            tracing::error!(target: "webauthn", error = %e, "start_passkey_registration failed");
            return bad_request("could not start passkey registration");
        }
    };
    let state_json = match serde_json::to_string(&reg_state) {
        Ok(s) => s,
        Err(_) => {
            let _ = tx.rollback().await;
            return unavailable();
        }
    };
    // One pending registration per user; TTL 5 minutes.
    if sqlx::query(
        "INSERT INTO webauthn_reg_state (user_id, tenant_id, state, expires_at) \
         VALUES ($1, $2, $3::jsonb, now() + interval '5 minutes') \
         ON CONFLICT (user_id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id, \
             state = EXCLUDED.state, created_at = now(), expires_at = EXCLUDED.expires_at",
    )
    .bind(auth.user_id)
    .bind(auth.tenant_id)
    .bind(&state_json)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        return unavailable();
    }
    if tx.commit().await.is_err() {
        return unavailable();
    }
    let options = match serde_json::to_value(&ccr) {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "options": options })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct RegisterFinishBody {
    /// The `PublicKeyCredential` produced by `navigator.credentials.create`.
    pub credential: Value,
    /// Optional friendly label for the passkey.
    #[serde(default)]
    pub name: Option<String>,
}

/// POST /api/auth/webauthn/register/finish — persist the new passkey.
pub async fn api_webauthn_register_finish(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<RegisterFinishBody>,
) -> Response {
    let reg: RegisterPublicKeyCredential = match serde_json::from_value(body.credential) {
        Ok(c) => c,
        Err(_) => return bad_request("malformed credential"),
    };
    let name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 200)
        .map(str::to_string);
    let webauthn = match build_webauthn() {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(target: "webauthn", error = %e, "webauthn build failed");
            return unavailable();
        }
    };
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => return unavailable(),
    };
    // Consume the pending state (single-use, unexpired).
    let state_json: String = match sqlx::query(
        "DELETE FROM webauthn_reg_state \
         WHERE user_id = $1 AND tenant_id = $2 AND expires_at > now() \
         RETURNING state::text AS state",
    )
    .bind(auth.user_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(r)) => r.try_get::<String, _>("state").unwrap_or_default(),
        Ok(None) => {
            let _ = tx.rollback().await;
            return bad_request("no pending registration (start one and finish within 5 minutes)");
        }
        Err(_) => {
            let _ = tx.rollback().await;
            return unavailable();
        }
    };
    let reg_state: PasskeyRegistration = match serde_json::from_str(&state_json) {
        Ok(s) => s,
        Err(_) => {
            let _ = tx.rollback().await;
            return unavailable();
        }
    };
    let passkey = match webauthn.finish_passkey_registration(&reg, &reg_state) {
        Ok(pk) => pk,
        Err(e) => {
            let _ = tx.rollback().await;
            tracing::warn!(target: "webauthn", error = %e, "finish_passkey_registration failed");
            return bad_request("passkey registration verification failed");
        }
    };
    let cred_id_bytes: Vec<u8> = passkey.cred_id().as_ref().to_vec();
    let passkey_json = match serde_json::to_string(&passkey) {
        Ok(s) => s,
        Err(_) => {
            let _ = tx.rollback().await;
            return unavailable();
        }
    };
    let inserted = match sqlx::query(
        "INSERT INTO webauthn_credentials (user_id, tenant_id, cred_id, passkey, name) \
         VALUES ($1, $2, $3, $4::jsonb, $5) \
         ON CONFLICT (cred_id) DO NOTHING",
    )
    .bind(auth.user_id)
    .bind(auth.tenant_id)
    .bind(&cred_id_bytes)
    .bind(&passkey_json)
    .bind(name.as_deref())
    .execute(&mut *tx)
    .await
    {
        Ok(r) => r.rows_affected(),
        Err(_) => {
            let _ = tx.rollback().await;
            return unavailable();
        }
    };
    // MINOR-2 fix: ON CONFLICT (cred_id) DO NOTHING stores nothing on a duplicate — do NOT
    // report success or write a "registered" audit row for a credential that wasn't stored.
    if inserted != 1 {
        let _ = tx.rollback().await;
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "code": "duplicate_credential",
                "detail": "this passkey is already registered"
            })),
        )
            .into_response();
    }
    if crate::audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &auth.role,
        "webauthn_registered",
        &format!(
            "cred_id_len={} name={}",
            cred_id_bytes.len(),
            name.as_deref().unwrap_or("-")
        ),
        "-",
    )
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        return unavailable();
    }
    if tx.commit().await.is_err() {
        return unavailable();
    }
    (StatusCode::CREATED, Json(json!({ "ok": true }))).into_response()
}

// ── Authentication (login second factor: consumes the mfa_pending token) ────────

#[derive(Deserialize)]
pub struct AuthStartBody {
    /// The `mfa_token` returned by `/api/login` (a signed `mfa_pending` JWT).
    pub mfa_token: String,
}

/// POST /api/auth/webauthn/authenticate/start — begin the login passkey ceremony.
/// Returns a `RequestChallengeResponse` (browser `navigator.credentials.get`).
pub async fn api_webauthn_authenticate_start(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthStartBody>,
) -> Response {
    let Some(ctx) = auth_jwt::verify_mfa_pending_token(body.mfa_token.trim()) else {
        return unauthorized("Invalid or expired MFA session");
    };
    let webauthn = match build_webauthn() {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(target: "webauthn", error = %e, "webauthn build failed");
            return unavailable();
        }
    };
    let mut tx = match db::begin_tenant_tx(&state.app_pool, ctx.tenant_id).await {
        Ok(t) => t,
        Err(_) => return unavailable(),
    };
    let passkeys = match load_passkeys(&mut tx, ctx.tenant_id, ctx.user_id).await {
        Ok(v) => v,
        Err(_) => {
            let _ = tx.rollback().await;
            return unavailable();
        }
    };
    if passkeys.is_empty() {
        let _ = tx.rollback().await;
        return bad_request("no passkey enrolled for this account");
    }
    let (rcr, auth_state) = match webauthn.start_passkey_authentication(&passkeys) {
        Ok(v) => v,
        Err(e) => {
            let _ = tx.rollback().await;
            tracing::error!(target: "webauthn", error = %e, "start_passkey_authentication failed");
            return bad_request("could not start passkey authentication");
        }
    };
    let state_json = match serde_json::to_string(&auth_state) {
        Ok(s) => s,
        Err(_) => {
            let _ = tx.rollback().await;
            return unavailable();
        }
    };
    if sqlx::query(
        "INSERT INTO webauthn_auth_state (user_id, tenant_id, state, expires_at) \
         VALUES ($1, $2, $3::jsonb, now() + interval '5 minutes') \
         ON CONFLICT (user_id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id, \
             state = EXCLUDED.state, created_at = now(), expires_at = EXCLUDED.expires_at",
    )
    .bind(ctx.user_id)
    .bind(ctx.tenant_id)
    .bind(&state_json)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        return unavailable();
    }
    if tx.commit().await.is_err() {
        return unavailable();
    }
    let options = match serde_json::to_value(&rcr) {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "options": options })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct AuthFinishBody {
    /// The `mfa_token` returned by `/api/login` (same token used at start).
    pub mfa_token: String,
    /// The `PublicKeyCredential` produced by `navigator.credentials.get`.
    pub credential: Value,
}

/// POST /api/auth/webauthn/authenticate/finish — verify the assertion, roll the
/// signature counter forward, mark MFA satisfied, and mint the real session.
pub async fn api_webauthn_authenticate_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<AuthFinishBody>,
) -> Response {
    let Some(ctx) = auth_jwt::verify_mfa_pending_token(body.mfa_token.trim()) else {
        return unauthorized("Invalid or expired MFA session");
    };
    let pkc: PublicKeyCredential = match serde_json::from_value(body.credential) {
        Ok(c) => c,
        Err(_) => return bad_request("malformed credential"),
    };
    let webauthn = match build_webauthn() {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(target: "webauthn", error = %e, "webauthn build failed");
            return unavailable();
        }
    };
    let mut tx = match db::begin_tenant_tx(&state.app_pool, ctx.tenant_id).await {
        Ok(t) => t,
        Err(_) => return unavailable(),
    };
    // Consume the pending auth state (single-use, unexpired).
    let state_json: String = match sqlx::query(
        "DELETE FROM webauthn_auth_state \
         WHERE user_id = $1 AND tenant_id = $2 AND expires_at > now() \
         RETURNING state::text AS state",
    )
    .bind(ctx.user_id)
    .bind(ctx.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(r)) => r.try_get::<String, _>("state").unwrap_or_default(),
        Ok(None) => {
            let _ = tx.rollback().await;
            return bad_request(
                "no pending authentication (start one and finish within 5 minutes)",
            );
        }
        Err(_) => {
            let _ = tx.rollback().await;
            return unavailable();
        }
    };
    let auth_state: PasskeyAuthentication = match serde_json::from_str(&state_json) {
        Ok(s) => s,
        Err(_) => {
            let _ = tx.rollback().await;
            return unavailable();
        }
    };
    let result = match webauthn.finish_passkey_authentication(&pkc, &auth_state) {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.rollback().await;
            tracing::warn!(target: "webauthn", error = %e, "finish_passkey_authentication failed");
            return unauthorized("passkey verification failed");
        }
    };
    // MINOR-1 fix: re-check the user is still active before minting (mirrors mfa/verify). The
    // mfa_pending token proves the password step, but a user deactivated within the token's
    // <=5-min TTL must not obtain a session via a passkey. (auth_guard would reject on the next
    // request, but do not mint the session in the first place.)
    match sqlx::query("SELECT 1 FROM users WHERE id = $1 AND tenant_id = $2 AND is_active = true")
        .bind(ctx.user_id)
        .bind(ctx.tenant_id)
        .fetch_optional(&mut *tx)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            let _ = tx.rollback().await;
            return unauthorized("account is not active");
        }
        Err(_) => {
            let _ = tx.rollback().await;
            return unavailable();
        }
    }
    // Roll the signature counter forward for the credential that just authenticated.
    // `AuthenticationResult::cred_id()` is the credential id (HumanBinaryData → &[u8]).
    let used_cred_id: Vec<u8> = result.cred_id().as_ref().to_vec();
    if result.needs_update() {
        let row = sqlx::query(
            "SELECT passkey::text AS passkey FROM webauthn_credentials \
             WHERE tenant_id = $1 AND user_id = $2 AND cred_id = $3",
        )
        .bind(ctx.tenant_id)
        .bind(ctx.user_id)
        .bind(&used_cred_id)
        .fetch_optional(&mut *tx)
        .await;
        if let Ok(Some(r)) = row {
            let s: String = r.try_get("passkey").unwrap_or_default();
            if let Ok(mut pk) = serde_json::from_str::<Passkey>(&s) {
                let _ = pk.update_credential(&result);
                if let Ok(updated) = serde_json::to_string(&pk) {
                    let _ = sqlx::query(
                        "UPDATE webauthn_credentials SET passkey = $1::jsonb, last_used_at = now() \
                         WHERE tenant_id = $2 AND user_id = $3 AND cred_id = $4",
                    )
                    .bind(&updated)
                    .bind(ctx.tenant_id)
                    .bind(ctx.user_id)
                    .bind(&used_cred_id)
                    .execute(&mut *tx)
                    .await;
                }
            }
        }
    } else {
        let _ = sqlx::query(
            "UPDATE webauthn_credentials SET last_used_at = now() \
             WHERE tenant_id = $1 AND user_id = $2 AND cred_id = $3",
        )
        .bind(ctx.tenant_id)
        .bind(ctx.user_id)
        .bind(&used_cred_id)
        .execute(&mut *tx)
        .await;
    }
    let ip = crate::http::client_ip::extract_client_ip(&headers, addr);
    if crate::audit_log::insert_audit(
        &mut tx,
        ctx.tenant_id,
        Some(ctx.user_id),
        &ctx.role,
        "webauthn_verify",
        "passkey assertion verified",
        &ip,
    )
    .await
    .is_err()
    {
        let _ = tx.rollback().await;
        return unavailable();
    }
    if tx.commit().await.is_err() {
        return unavailable();
    }
    // MFA satisfied → mint the real session, exactly as /api/auth/mfa/verify does.
    let binding = auth_jwt::StreamBinding::from_http(&headers, addr);
    let (access_jwt, access_cookie, refresh_cookie) =
        match crate::auth_refresh::build_session_cookie_headers(
            state.auth_pool.as_ref(),
            ctx.user_id,
            ctx.tenant_id,
            &binding,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(target: "webauthn", error = %e, "session cookie build failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "ok": false, "detail": "session issuance failed" })),
                )
                    .into_response();
            }
        };
    let mut response = (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "user_id": ctx.user_id,
            "tenant_id": ctx.tenant_id,
            "role": ctx.role,
            "is_superadmin": ctx.is_superadmin,
            "access_token": access_jwt,
        })),
    )
        .into_response();
    append_set_cookie(response.headers_mut(), &access_cookie);
    append_set_cookie(response.headers_mut(), &refresh_cookie);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_handle_is_deterministic_and_tenant_scoped() {
        assert_eq!(user_handle(3, 7), user_handle(3, 7));
        assert_ne!(user_handle(3, 7), user_handle(4, 7));
        assert_ne!(user_handle(3, 7), user_handle(3, 8));
    }

    #[test]
    fn migration_copies_are_byte_identical_and_force_rls() {
        let fe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("migrations/20260926100000_webauthn_passkeys.sql");
        let db = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/weissman-db/migrations/20260926100000_webauthn_passkeys.sql");
        let a = std::fs::read_to_string(&fe).unwrap();
        let b = std::fs::read_to_string(&db).unwrap();
        assert_eq!(a, b);
        assert!(a.contains("FORCE ROW LEVEL SECURITY"));
        assert!(a.contains("app_current_tenant_id()"));
        assert!(a.contains("webauthn_credentials"));
        assert!(a.contains("webauthn_reg_state"));
        assert!(a.contains("webauthn_auth_state"));
    }
}
