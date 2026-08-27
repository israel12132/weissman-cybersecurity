//! Impersonation / scope-switch: new JWT whose `cid` is the requested client.
//!
//! Never a client-side picker that keeps the old token and sends another
//! `client_id`. Authenticates against [`user_client_scope_grants`]. Portal
//! users with a bound customer cannot switch (403).

use axum::{
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::{PgPool, Row};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::auth_jwt::{AuthContext, StreamBinding};
use crate::client_isolation;
use crate::http::{extract_client_ip, AppState};

#[derive(Debug, Deserialize)]
pub struct ScopeSwitchBody {
    /// Destination customer. `null` / omitted = exit impersonation (staff unscoped).
    #[serde(default)]
    pub client_id: Option<i64>,
}

/// Policy: a portal identity cannot leave its provisioned customer.
#[must_use]
pub fn portal_may_not_switch(auth: &AuthContext) -> bool {
    client_isolation::is_portal_identity(auth)
}

/// True when `to_cid` is allowed by the grant table (wildcard or explicit).
pub async fn grant_allows(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    to_cid: Option<i64>,
) -> Result<bool, sqlx::Error> {
    match to_cid {
        None => {
            // Exit impersonation: any staff/owner row (wildcard or specific) may return home.
            let n: i64 = sqlx::query_scalar(
                r#"SELECT COUNT(*)::bigint FROM user_client_scope_grants
                   WHERE tenant_id = $1 AND user_id = $2"#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .fetch_one(pool)
            .await?;
            Ok(n > 0)
        }
        Some(cid) if cid > 0 => {
            let n: i64 = sqlx::query_scalar(
                r#"SELECT COUNT(*)::bigint FROM user_client_scope_grants
                   WHERE tenant_id = $1 AND user_id = $2
                     AND (client_id IS NULL OR client_id = $3)"#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .bind(cid)
            .fetch_one(pool)
            .await?;
            Ok(n > 0)
        }
        Some(_) => Ok(false),
    }
}

/// Insert a wildcard grant for a staff/owner user (idempotent).
pub async fn ensure_wildcard_grant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    user_id: i64,
    granted_by: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO user_client_scope_grants (tenant_id, user_id, client_id, granted_by)
           SELECT $1, $2, NULL, $3
           WHERE NOT EXISTS (
               SELECT 1 FROM user_client_scope_grants
               WHERE user_id = $2 AND client_id IS NULL
           )"#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(granted_by)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Drop all grants (portal conversion) or replace with wildcard (staff conversion).
pub async fn sync_grants_for_role(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    user_id: i64,
    is_portal: bool,
    granted_by: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM user_client_scope_grants WHERE tenant_id = $1 AND user_id = $2")
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    if !is_portal {
        ensure_wildcard_grant(tx, tenant_id, user_id, granted_by).await?;
    }
    Ok(())
}

async fn client_exists_in_tenant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    cid: i64,
) -> Result<bool, sqlx::Error> {
    let id: Option<i64> =
        sqlx::query_scalar("SELECT id FROM clients WHERE id = $1 AND tenant_id = $2 LIMIT 1")
            .bind(cid)
            .bind(tenant_id)
            .fetch_optional(&mut **tx)
            .await?;
    Ok(id.is_some())
}

fn append_set_cookie(headers: &mut axum::http::HeaderMap, line: &str) {
    if let Ok(v) = axum::http::HeaderValue::from_str(line) {
        headers.append(axum::http::header::SET_COOKIE, v);
    }
}

fn extract_refresh_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_h = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    let prefix = format!("{}=", crate::auth_refresh::REFRESH_COOKIE_NAME);
    for part in cookie_h.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&prefix) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// POST /api/auth/scope-switch — mint a **new** JWT whose `cid` is `client_id`.
pub async fn api_scope_switch(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ScopeSwitchBody>,
) -> Response {
    if auth.agent_id.is_some() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "detail": "Agent sessions cannot scope-switch",
                "error_code": "portal_forbidden",
            })),
        )
            .into_response();
    }
    if portal_may_not_switch(&auth) {
        tracing::warn!(
            target: "scope_switch",
            user_id = auth.user_id,
            tenant_id = auth.tenant_id,
            to_cid = ?body.client_id,
            "portal user blocked from scope-switch"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "detail": "Customer-portal accounts cannot switch to another tenant",
                "error_code": "portal_scope_locked",
            })),
        )
            .into_response();
    }

    let to_cid = body.client_id.filter(|id| *id > 0);
    if to_cid == auth.assigned_client_id {
        return (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "assigned_client_id": auth.assigned_client_id,
                "unchanged": true,
            })),
        )
            .into_response();
    }

    // Management plane: unscoped client GUC so grants/audit are visible, tenant still set.
    let Ok(mut tx) =
        weissman_db::begin_tenant_tx_scoped(state.app_pool.as_ref(), auth.tenant_id, None).await
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable"})),
        )
            .into_response();
    };

    if let Some(cid) = to_cid {
        match client_exists_in_tenant(&mut tx, auth.tenant_id, cid).await {
            Ok(true) => {}
            Ok(false) => {
                let _ = tx.rollback().await;
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "ok": false,
                        "detail": "Not found",
                        "error_code": "not_found",
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!(target: "scope_switch", error = %e, "client lookup failed");
                let _ = tx.rollback().await;
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"ok": false, "detail": "Database unavailable"})),
                )
                    .into_response();
            }
        }
    }

    let allowed = match grant_allows_tx(&mut tx, auth.tenant_id, auth.user_id, to_cid).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(target: "scope_switch", error = %e, "grant lookup failed");
            let _ = tx.rollback().await;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": "Database unavailable"})),
            )
                .into_response();
        }
    };
    if !allowed {
        let _ = tx.rollback().await;
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "detail": "Not permitted to switch to that customer",
                "error_code": "scope_switch_denied",
            })),
        )
            .into_response();
    }

    let binding = StreamBinding::from_http(&headers, addr);
    let minted = match crate::auth_jwt::create_access_token(
        auth.user_id,
        auth.tenant_id,
        auth.role.as_str(),
        auth.is_superadmin,
        &binding,
        to_cid,
    ) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(target: "scope_switch", error = %e, "JWT mint failed");
            let _ = tx.rollback().await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "session issuance failed"})),
            )
                .into_response();
        }
    };

    let from_jti = auth.jti.clone();
    if let Err(e) = sqlx::query(
        r#"INSERT INTO user_scope_switch_audit
           (tenant_id, actor_user_id, from_cid, to_cid, from_jti, to_jti)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(auth.tenant_id)
    .bind(auth.user_id)
    .bind(auth.assigned_client_id)
    .bind(to_cid)
    .bind(&from_jti)
    .bind(&minted.jti)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(target: "scope_switch", error = %e, "audit insert failed");
        let _ = tx.rollback().await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": "audit failed"})),
        )
            .into_response();
    }

    let ip = extract_client_ip(&headers, addr);
    let details = format!(
        "scope_switch from_cid={} to_cid={}",
        auth.assigned_client_id
            .map(|n| n.to_string())
            .unwrap_or_else(|| "null".into()),
        to_cid
            .map(|n| n.to_string())
            .unwrap_or_else(|| "null".into())
    );
    let _ = crate::audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        &format!("user:{}", auth.user_id),
        "scope_switch",
        &details,
        &ip,
    )
    .await;

    if let Err(e) = tx.commit().await {
        tracing::error!(target: "scope_switch", error = %e, "commit failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": "commit failed"})),
        )
            .into_response();
    }

    if let Some(old_jti) = from_jti.as_deref() {
        let expiry = chrono::Utc::now() + chrono::Duration::hours(6);
        let _ =
            crate::auth_refresh::revoke_access_jti(state.auth_pool.as_ref(), old_jti, expiry).await;
    }
    if let Some(raw) = extract_refresh_cookie(&headers) {
        let _ = crate::auth_refresh::update_refresh_scope(
            state.auth_pool.as_ref(),
            &raw,
            to_cid,
            &minted.jti,
        )
        .await;
    }

    tracing::info!(
        target: "scope_switch",
        user_id = auth.user_id,
        tenant_id = auth.tenant_id,
        from_cid = ?auth.assigned_client_id,
        to_cid = ?to_cid,
        "issued new JWT for scope-switch"
    );

    let mut res = (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "user_id": auth.user_id,
            "tenant_id": auth.tenant_id,
            "role": auth.role,
            "is_superadmin": auth.is_superadmin,
            "assigned_client_id": to_cid,
            "access_token": minted.token,
            "impersonating": to_cid.is_some(),
        })),
    )
        .into_response();
    append_set_cookie(
        res.headers_mut(),
        &crate::auth_jwt::session_cookie_value(&minted.token),
    );
    res
}

async fn grant_allows_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    user_id: i64,
    to_cid: Option<i64>,
) -> Result<bool, sqlx::Error> {
    match to_cid {
        None => {
            let n: i64 = sqlx::query_scalar(
                r#"SELECT COUNT(*)::bigint FROM user_client_scope_grants
                   WHERE tenant_id = $1 AND user_id = $2"#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .fetch_one(&mut **tx)
            .await?;
            Ok(n > 0)
        }
        Some(cid) => {
            let n: i64 = sqlx::query_scalar(
                r#"SELECT COUNT(*)::bigint FROM user_client_scope_grants
                   WHERE tenant_id = $1 AND user_id = $2
                     AND (client_id IS NULL OR client_id = $3)"#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .bind(cid)
            .fetch_one(&mut **tx)
            .await?;
            Ok(n > 0)
        }
    }
}

/// GET /api/auth/scope-targets — customers this session may switch to.
pub async fn api_scope_targets(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if portal_may_not_switch(&auth) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "detail": "Customer-portal accounts cannot switch to another tenant",
                "error_code": "portal_scope_locked",
                "clients": [],
            })),
        )
            .into_response();
    }
    let Ok(mut tx) =
        weissman_db::begin_tenant_tx_scoped(state.app_pool.as_ref(), auth.tenant_id, None).await
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable", "clients": []})),
        )
            .into_response();
    };
    let wildcard: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1 FROM user_client_scope_grants
               WHERE tenant_id = $1 AND user_id = $2 AND client_id IS NULL
           )"#,
    )
    .bind(auth.tenant_id)
    .bind(auth.user_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(false);

    let rows = if wildcard {
        sqlx::query(r#"SELECT id, name FROM clients WHERE tenant_id = $1 ORDER BY name, id"#)
            .bind(auth.tenant_id)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    } else {
        sqlx::query(
            r#"SELECT c.id, c.name
               FROM clients c
               JOIN user_client_scope_grants g
                 ON g.client_id = c.id AND g.tenant_id = c.tenant_id
               WHERE g.tenant_id = $1 AND g.user_id = $2
               ORDER BY c.name, c.id"#,
        )
        .bind(auth.tenant_id)
        .bind(auth.user_id)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default()
    };
    let _ = tx.commit().await;
    let clients: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64, _>("id").unwrap_or(0),
                "name": r.try_get::<String, _>("name").unwrap_or_default(),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "can_exit_scope": true,
            "current_client_id": auth.assigned_client_id,
            "clients": clients,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(role: &str, cid: Option<i64>) -> AuthContext {
        AuthContext {
            user_id: 1,
            tenant_id: 1,
            role: role.to_string(),
            is_superadmin: false,
            agent_id: None,
            jti: Some("j".into()),
            bind_ip: None,
            bind_tls_fp: None,
            assigned_client_id: cid,
        }
    }

    #[test]
    fn portal_cannot_switch() {
        assert!(portal_may_not_switch(&ctx("client", Some(3))));
        assert!(!portal_may_not_switch(&ctx("operator", None)));
        assert!(!portal_may_not_switch(&ctx("operator", Some(3))));
        assert!(!portal_may_not_switch(&ctx("ceo", None)));
    }

    #[test]
    fn scope_switch_body_deserializes_null_and_id() {
        let a: ScopeSwitchBody = serde_json::from_str(r#"{"client_id": 9}"#).unwrap();
        assert_eq!(a.client_id, Some(9));
        let b: ScopeSwitchBody = serde_json::from_str(r#"{"client_id": null}"#).unwrap();
        assert_eq!(b.client_id, None);
        let c: ScopeSwitchBody = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(c.client_id, None);
    }
}
