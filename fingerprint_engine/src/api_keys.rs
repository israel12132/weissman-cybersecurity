//! Service-account API keys — non-interactive, scoped machine credentials.
//!
//! A key is presented as `Authorization: Bearer wsk_<prefix>_<secret>`. Only
//! `sha256(secret)` (BYTEA) and the public `key_prefix` are stored; the secret is
//! shown ONCE at creation. Authentication happens in [`crate::http`]'s `auth_guard`
//! (JWT first, then this API-key path) and yields a synthetic [`AuthContext`] plus an
//! [`ApiKeyIdentity`]. Authorization is a FAIL-CLOSED per-route scope gate
//! ([`enforce_api_key_scope`]): a key can only reach the explicitly allow-listed
//! read routes, and only with the matching scope.
//!
//! Design mirrors the SCIM bearer-token path ([`crate::scim`]) and its
//! `public.lookup_scim_token` SECURITY DEFINER lookup.

use axum::{
    extract::{Extension, Path, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::auth_jwt::AuthContext;
use crate::db;
use crate::http::AppState;

/// Token namespace prefix. A `HeaderOrCookie` bearer starting with this is an API key.
pub const KEY_TOKEN_PREFIX: &str = "wsk_";

pub const SCOPE_AUDIT_READ: &str = "audit:read";
pub const SCOPE_FINDINGS_READ: &str = "findings:read";

/// Scopes a caller may request at creation time.
const VALID_SCOPES: &[&str] = &[SCOPE_AUDIT_READ, SCOPE_FINDINGS_READ];

/// `(method, exact path, required scope)` that an API-key principal may reach.
///
/// FAIL-CLOSED: any `(method, path)` not listed here is rejected for API keys, so a
/// machine credential can never reach a human or mutation route even though the
/// synthetic principal carries an admin-equivalent role (needed only to satisfy the
/// audit route's own `require_admin` gate). This table is the real least-privilege
/// boundary: only add read (GET) routes here, and only ones whose handlers do not
/// call `revalidate_auth_context` (which would fail for the synthetic user_id 0).
static API_KEY_ROUTES: &[(Method, &str, &str)] = &[
    (Method::GET, "/api/audit-logs", SCOPE_AUDIT_READ),
    (Method::GET, "/api/audit/export", SCOPE_AUDIT_READ),
    (Method::GET, "/api/findings", SCOPE_FINDINGS_READ),
    (Method::GET, "/api/findings/clusters", SCOPE_FINDINGS_READ),
    (Method::GET, "/api/findings/export/csv", SCOPE_FINDINGS_READ),
    (Method::GET, "/api/export/findings", SCOPE_FINDINGS_READ),
];

/// Request-scoped marker that the caller authenticated with an API key (inserted as
/// an axum extension alongside the synthetic [`AuthContext`]).
#[derive(Clone, Debug)]
pub struct ApiKeyIdentity {
    pub key_id: i64,
    pub tenant_id: i64,
    pub scopes: Vec<String>,
}

fn sha256_bytes(s: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().to_vec()
}

fn forbidden(detail: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "ok": false, "detail": detail })),
    )
        .into_response()
}

fn bad_request(detail: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "detail": detail })),
    )
        .into_response()
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "ok": false, "detail": "api key store unavailable" })),
    )
        .into_response()
}

/// Split `wsk_<prefix>_<secret>` into `(prefix, secret)`. Both segments are hex and
/// contain no `_`, so a single split after the namespace prefix is unambiguous.
fn parse_api_key(token: &str) -> Option<(String, String)> {
    let rest = token.trim().strip_prefix(KEY_TOKEN_PREFIX)?;
    let mut parts = rest.splitn(2, '_');
    let prefix = parts.next()?.trim();
    let secret = parts.next()?.trim();
    if prefix.is_empty() || secret.is_empty() {
        return None;
    }
    Some((prefix.to_string(), secret.to_string()))
}

/// Resolve a `wsk_...` bearer to a synthetic `AuthContext` + `ApiKeyIdentity`.
///
/// - `Ok(Some(..))` — valid, live key.
/// - `Ok(None)` — present but invalid (bad format, unknown prefix, revoked, expired,
///   or secret mismatch) → the caller returns 401.
/// - `Err(())` — datastore unavailable → the caller returns 503 (fail-closed).
pub async fn authenticate_api_key(
    state: &AppState,
    token: &str,
) -> Result<Option<(AuthContext, ApiKeyIdentity)>, ()> {
    let Some((prefix, secret)) = parse_api_key(token) else {
        return Ok(None);
    };
    // SECURITY DEFINER lookup: prefix is globally unique, so this resolves the row
    // before any tenant GUC is set (the machine caller has no session).
    let row = sqlx::query(
        "SELECT id, tenant_id, key_hash, scopes, expires_at, revoked_at FROM public.lookup_api_key($1)",
    )
    .bind(&prefix)
    .fetch_optional(state.app_pool.as_ref())
    .await
    .map_err(|_| ())?;
    let Some(row) = row else {
        return Ok(None);
    };

    let revoked_at = row
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("revoked_at")
        .ok()
        .flatten();
    if revoked_at.is_some() {
        return Ok(None);
    }
    let expires_at = row
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("expires_at")
        .ok()
        .flatten();
    if let Some(exp) = expires_at {
        if exp <= chrono::Utc::now() {
            return Ok(None);
        }
    }
    let stored_hash: Vec<u8> = match row.try_get("key_hash") {
        Ok(h) => h,
        Err(_) => return Ok(None),
    };
    // Constant-time compare (subtle). Both are SHA-256 (32 bytes); a mismatched length
    // yields Choice(0) rather than a panic.
    let presented = sha256_bytes(&secret);
    if !bool::from(presented.as_slice().ct_eq(stored_hash.as_slice())) {
        return Ok(None);
    }

    let key_id: i64 = row.try_get("id").unwrap_or(0);
    let tenant_id: i64 = row.try_get("tenant_id").unwrap_or(0);
    if key_id <= 0 || tenant_id <= 0 {
        return Ok(None);
    }
    let scopes: Vec<String> = row.try_get::<Vec<String>, _>("scopes").unwrap_or_default();

    // Best-effort last_used_at touch in its own tenant tx; never fails the request.
    if let Ok(mut tx) = db::begin_tenant_tx(state.app_pool.as_ref(), tenant_id).await {
        let _ = sqlx::query(
            "UPDATE api_keys SET last_used_at = now() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(key_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
    }

    // Synthetic principal: admin-equivalent role so the audit route's own require_admin
    // gate passes, but reachability is bounded to API_KEY_ROUTES by enforce_api_key_scope.
    let ctx = AuthContext {
        user_id: 0,
        tenant_id,
        role: crate::rbac::roles::ADMIN.to_string(),
        is_superadmin: false,
        agent_id: None,
        jti: None,
        bind_ip: None,
        bind_tls_fp: None,
        assigned_client_id: None,
    };
    let ident = ApiKeyIdentity {
        key_id,
        tenant_id,
        scopes,
    };
    Ok(Some((ctx, ident)))
}

/// Fail-closed scope gate for an API-key request. Returns `Ok(())` only when the
/// exact `(method, path)` is allow-listed AND the key carries the required scope.
pub fn enforce_api_key_scope(
    method: &Method,
    path: &str,
    scopes: &[String],
) -> Result<(), Response> {
    let Some(entry) = API_KEY_ROUTES
        .iter()
        .find(|(m, p, _)| m == method && *p == path)
    else {
        return Err(forbidden(
            "this endpoint is not available to service-account API keys",
        ));
    };
    let required = entry.2;
    if scopes.iter().any(|s| s.as_str() == required) {
        Ok(())
    } else {
        Err(forbidden(&format!(
            "api key is missing the required scope '{}'",
            required
        )))
    }
}

#[derive(Deserialize)]
pub struct CreateApiKeyBody {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Optional lifetime in days; when set the key expires that many days from now.
    #[serde(default)]
    pub expires_in_days: Option<i64>,
}

/// POST /api/admin/api-keys — mint a key; returns the raw secret ONCE. Admin only.
pub async fn api_admin_api_keys_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<CreateApiKeyBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let name = body.name.trim().to_string();
    if name.is_empty() || name.len() > 200 {
        return bad_request("name is required (1-200 chars)");
    }
    let mut scopes: Vec<String> = body
        .scopes
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    scopes.sort();
    scopes.dedup();
    if scopes.is_empty() {
        return bad_request("at least one scope is required");
    }
    if let Some(bad) = scopes.iter().find(|s| !VALID_SCOPES.contains(&s.as_str())) {
        return bad_request(&format!(
            "unknown scope '{}' (valid: {})",
            bad,
            VALID_SCOPES.join(", ")
        ));
    }
    let expires_at: Option<chrono::DateTime<chrono::Utc>> = match body.expires_in_days {
        Some(d) if d > 0 => Some(chrono::Utc::now() + chrono::Duration::days(d.min(3650))),
        Some(_) => return bad_request("expires_in_days must be positive"),
        None => None,
    };

    // wsk_<prefix>_<secret>: 6-byte public prefix (lookup) + 32-byte secret (hashed).
    let mut prefix_bytes = [0u8; 6];
    let mut secret_bytes = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut prefix_bytes);
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut secret_bytes);
    let prefix = hex::encode(prefix_bytes);
    let secret = hex::encode(secret_bytes);
    let token = format!("{}{}_{}", KEY_TOKEN_PREFIX, prefix, secret);
    let key_hash = sha256_bytes(&secret);

    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => return unavailable(),
    };
    let inserted = sqlx::query(
        r#"INSERT INTO api_keys (tenant_id, name, key_prefix, key_hash, scopes, created_by, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, created_at"#,
    )
    .bind(auth.tenant_id)
    .bind(&name)
    .bind(&prefix)
    .bind(&key_hash)
    .bind(&scopes)
    .bind(auth.user_id)
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await;
    let (id, created_at) = match inserted {
        Ok(row) => (
            row.try_get::<i64, _>("id").unwrap_or(0),
            row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                .ok(),
        ),
        Err(_) => {
            let _ = tx.rollback().await;
            return unavailable();
        }
    };
    // Tamper-evident audit in the same tx: no key without an audit row.
    let details = format!(
        "name={} prefix={} scopes={}",
        name,
        prefix,
        scopes.join(",")
    );
    if crate::audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &auth.role,
        "api_key_created",
        &details,
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
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "id": id,
            "name": name,
            "key_prefix": prefix,
            "scopes": scopes,
            "expires_at": expires_at,
            "created_at": created_at,
            "api_key": token,
            "warning": "Copy this key now — Weissman stores only its SHA-256 hash and cannot show it again.",
        })),
    )
        .into_response()
}

/// GET /api/admin/api-keys — list keys (prefix, scopes, usage; never the secret). Admin only.
pub async fn api_admin_api_keys_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => return unavailable(),
    };
    let rows = sqlx::query(
        r#"SELECT id, name, key_prefix, scopes, created_at, expires_at, last_used_at, revoked_at
           FROM api_keys WHERE tenant_id = $1
           ORDER BY created_at DESC"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match rows {
        Ok(rows) => {
            let items: Vec<Value> = rows
                .iter()
                .map(|r| {
                    let revoked_at = r
                        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("revoked_at")
                        .ok()
                        .flatten();
                    json!({
                        "id": r.try_get::<i64, _>("id").unwrap_or(0),
                        "name": r.try_get::<String, _>("name").unwrap_or_default(),
                        "key_prefix": r.try_get::<String, _>("key_prefix").unwrap_or_default(),
                        "scopes": r.try_get::<Vec<String>, _>("scopes").unwrap_or_default(),
                        "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok(),
                        "expires_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("expires_at").ok().flatten(),
                        "last_used_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_used_at").ok().flatten(),
                        "revoked_at": revoked_at,
                        "active": revoked_at.is_none(),
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "api_keys": items })),
            )
                .into_response()
        }
        Err(_) => unavailable(),
    }
}

/// DELETE /api/admin/api-keys/:id — revoke a key (soft, sets revoked_at). Admin only.
pub async fn api_admin_api_keys_revoke(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => return unavailable(),
    };
    let res = sqlx::query(
        "UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&mut *tx)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            let _ = crate::audit_log::insert_audit(
                &mut tx,
                auth.tenant_id,
                Some(auth.user_id),
                &auth.role,
                "api_key_revoked",
                &format!("id={}", id),
                "-",
            )
            .await;
            if tx.commit().await.is_err() {
                return unavailable();
            }
            (StatusCode::OK, Json(json!({ "ok": true, "id": id }))).into_response()
        }
        Ok(_) => {
            let _ = tx.rollback().await;
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "ok": false, "detail": "api key not found or already revoked" })),
            )
                .into_response()
        }
        Err(_) => {
            let _ = tx.rollback().await;
            unavailable()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_api_key_splits_prefix_and_secret() {
        let (p, s) = parse_api_key("wsk_deadbeef_0123abcd").expect("parse");
        assert_eq!(p, "deadbeef");
        assert_eq!(s, "0123abcd");
        assert!(parse_api_key("nope_x_y").is_none());
        assert!(parse_api_key("wsk_only").is_none());
        assert!(parse_api_key("wsk__missingprefix").is_none());
    }

    #[test]
    fn scope_gate_is_fail_closed_and_scope_checked() {
        let g = Method::GET;
        // Unlisted method on a listed path → denied.
        assert!(enforce_api_key_scope(
            &Method::POST,
            "/api/findings",
            &["findings:read".to_string()]
        )
        .is_err());
        // Admin-management path is never reachable by a key.
        assert!(
            enforce_api_key_scope(&g, "/api/admin/api-keys", &["findings:read".to_string()])
                .is_err()
        );
        // Listed route, wrong scope → denied.
        assert!(
            enforce_api_key_scope(&g, "/api/audit-logs", &["findings:read".to_string()]).is_err()
        );
        // Listed route, right scope → allowed.
        assert!(enforce_api_key_scope(&g, "/api/audit-logs", &["audit:read".to_string()]).is_ok());
        assert!(enforce_api_key_scope(&g, "/api/findings", &["findings:read".to_string()]).is_ok());
    }

    #[test]
    fn sha256_constant_time_compare() {
        let a = sha256_bytes("secret");
        let b = sha256_bytes("secret");
        assert!(bool::from(a.as_slice().ct_eq(b.as_slice())));
        let c = sha256_bytes("other");
        assert!(!bool::from(a.as_slice().ct_eq(c.as_slice())));
    }

    #[test]
    fn migration_copies_are_byte_identical_and_force_rls() {
        let fe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("migrations/20260923101000_service_account_api_keys.sql");
        let db = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/weissman-db/migrations/20260923101000_service_account_api_keys.sql");
        let a = std::fs::read_to_string(&fe).unwrap();
        let b = std::fs::read_to_string(&db).unwrap();
        assert_eq!(a, b);
        assert!(a.contains("FORCE ROW LEVEL SECURITY"));
        assert!(a.contains("public.lookup_api_key"));
        assert!(a.contains("SET search_path = public, pg_temp"));
        assert!(a.contains("app_current_tenant_id()"));
    }
}
