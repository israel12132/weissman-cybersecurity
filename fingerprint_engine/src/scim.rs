//! SCIM 2.0 (RFC 7643/7644) directory sync with an identity kill-switch.
//!
//! Entra / Okta push Users + Groups here. Deprovision (`active=false` or DELETE)
//! sets `users.is_active=false` and immediately revokes refresh tokens + access
//! JTIs so a leaver cannot keep a Command Center session. Group → role maps are
//! applied on membership change and at SSO login. CEO / superadmin are never
//! assignable from SCIM.

use axum::{
    extract::{Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth_jwt::AuthContext;
use crate::auth_refresh;
use crate::db;
use crate::http::AppState;
use crate::rbac::{self, roles};

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

const ALLOWED_ROLES: &[&str] = &[roles::VIEWER, roles::ANALYST, roles::OPERATOR, roles::ADMIN];

#[derive(Clone, Copy)]
struct ScimPrincipal {
    tenant_id: i64,
}

#[derive(Debug, Deserialize)]
pub struct ScimListQuery {
    pub filter: Option<String>,
    #[serde(rename = "startIndex")]
    pub start_index: Option<i64>,
    pub count: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimFilter {
    pub attr: String,
    pub value: String,
}

fn sha256_token(raw: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(raw.trim().as_bytes());
    h.finalize().to_vec()
}

fn scim_error(status: StatusCode, detail: &str) -> Response {
    (
        status,
        Json(json!({
            "schemas": [ERROR_SCHEMA],
            "status": status.as_u16().to_string(),
            "detail": detail,
        })),
    )
        .into_response()
}

fn scim_json(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

/// Restrict IdP-driven roles. Never ceo/client/agent/superadmin.
pub fn sanitize_role(role: &str) -> Option<&'static str> {
    let n = role.trim().to_ascii_lowercase();
    ALLOWED_ROLES
        .iter()
        .copied()
        .find(|r| r.eq_ignore_ascii_case(&n))
}

pub fn highest_mapped_role<'a>(
    roles_in: impl IntoIterator<Item = &'a str>,
) -> Option<&'static str> {
    let mut best: Option<&'static str> = None;
    let mut best_rank = 0u8;
    for r in roles_in {
        if let Some(s) = sanitize_role(r) {
            let rank = rbac::role_rank(s);
            if rank > best_rank {
                best_rank = rank;
                best = Some(s);
            }
        }
    }
    best
}

pub fn parse_scim_eq_filter(filter: &str) -> Option<ScimFilter> {
    let f = filter.trim();
    if f.is_empty() {
        return None;
    }
    let re = regex::Regex::new(r#"(?i)^\s*([A-Za-z.]+)\s+eq\s+"([^"]*)"\s*$"#).ok()?;
    let cap = re.captures(f)?;
    Some(ScimFilter {
        attr: cap.get(1)?.as_str().to_ascii_lowercase(),
        value: cap.get(2)?.as_str().to_string(),
    })
}

/// Groups from a **verified** compact JWT payload (signature already checked).
pub fn groups_from_verified_jwt(compact: &str) -> Vec<String> {
    let Some(payload) = compact.split('.').nth(1) else {
        return Vec::new();
    };
    let Ok(bytes) =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
    else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
        return Vec::new();
    };
    groups_from_claim_value(&v)
}

fn groups_from_claim_value(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["groups", "wids", "roles"] {
        match v.get(key) {
            Some(Value::Array(items)) => {
                for item in items {
                    if let Some(s) = item.as_str() {
                        let t = s.trim();
                        if !t.is_empty() {
                            out.push(t.to_string());
                        }
                    }
                }
            }
            Some(Value::String(s)) => {
                for part in s.split([',', ';']) {
                    let t = part.trim();
                    if !t.is_empty() {
                        out.push(t.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Group / memberOf AttributeValues from a verified SAML assertion.
pub fn groups_from_saml_xml(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(re_attr) = regex::Regex::new(
        r#"(?is)Name\s*=\s*"[^"]*(?:groups?|memberOf|Group)[^"]*"[^>]*>(.*?)</[^>]*Attribute>"#,
    ) else {
        return out;
    };
    let Ok(re_val) = regex::Regex::new(r"(?is)<[^>]*AttributeValue[^>]*>([^<]+)</") else {
        return out;
    };
    for cap in re_attr.captures_iter(xml) {
        if let Some(body) = cap.get(1) {
            for v in re_val.captures_iter(body.as_str()) {
                if let Some(m) = v.get(1) {
                    let t = html_unescape(m.as_str().trim());
                    if !t.is_empty() {
                        out.push(t);
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
}

/// SSO login: refuse deactivated (SCIM kill-switch) users; JIT otherwise.
pub async fn resolve_sso_user(
    auth: &PgPool,
    app: &PgPool,
    tenant_id: i64,
    email: &str,
    claim_groups: &[String],
) -> Result<i64, (StatusCode, Json<Value>)> {
    let email = email.trim();
    let row = sqlx::query(
        r#"SELECT id, COALESCE(is_active, false) AS is_active
           FROM auth.v_user_lookup
           WHERE tenant_id = $1 AND lower(trim(email)) = lower(trim($2))"#,
    )
    .bind(tenant_id)
    .bind(email)
    .fetch_optional(auth)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": format!("{e}")})),
        )
    })?;

    if let Some(r) = row {
        let uid: i64 = r.try_get("id").unwrap_or(0);
        let active: bool = r.try_get("is_active").unwrap_or(false);
        if !active {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "ok": false,
                    "detail": "Account deactivated by identity provider (SCIM kill-switch)",
                    "code": "scim_deprovisioned",
                })),
            ));
        }
        let _ = apply_groups_to_user(app, tenant_id, uid, claim_groups).await;
        return Ok(uid);
    }

    let mapped = role_from_claim_groups(app, tenant_id, claim_groups)
        .await
        .unwrap_or(None);
    let role = mapped.unwrap_or(roles::VIEWER);
    let uid = weissman_db::auth_access::insert_user_auth(auth, tenant_id, email, None, role)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": format!("provision: {e}")})),
            )
        })?;
    let _ = apply_groups_to_user(app, tenant_id, uid, claim_groups).await;
    Ok(uid)
}

async fn role_from_claim_groups(
    pool: &PgPool,
    tenant_id: i64,
    groups: &[String],
) -> Result<Option<&'static str>, sqlx::Error> {
    if groups.is_empty() {
        return Ok(None);
    }
    let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await else {
        return Ok(None);
    };
    let mapped = mapped_roles_for_groups(&mut tx, tenant_id, groups).await?;
    let _ = tx.commit().await;
    Ok(highest_mapped_role(mapped.iter().map(String::as_str)))
}

async fn mapped_roles_for_groups(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    groups: &[String],
) -> Result<Vec<String>, sqlx::Error> {
    if groups.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        r#"SELECT weissman_role FROM weissman_scim_group_role_maps
           WHERE tenant_id = $1
             AND (group_external_id = ANY($2) OR group_display_name = ANY($2))"#,
    )
    .bind(tenant_id)
    .bind(groups)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .iter()
        .filter_map(|r| r.try_get::<String, _>("weissman_role").ok())
        .collect())
}

async fn apply_groups_to_user(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    claim_groups: &[String],
) -> Result<(), sqlx::Error> {
    let mut tx = db::begin_tenant_tx(pool, tenant_id).await?;
    let mut roles_found = mapped_roles_for_groups(&mut tx, tenant_id, claim_groups).await?;
    let member_roles: Vec<String> = sqlx::query_scalar(
        r#"SELECT m.weissman_role
           FROM weissman_scim_group_role_maps m
           JOIN weissman_scim_groups g
             ON g.tenant_id = m.tenant_id
            AND (g.external_id = m.group_external_id OR g.display_name = m.group_display_name)
           JOIN weissman_scim_group_members gm
             ON gm.group_id = g.id AND gm.tenant_id = m.tenant_id
           WHERE m.tenant_id = $1 AND gm.user_id = $2"#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    roles_found.extend(member_roles);
    if let Some(role) = highest_mapped_role(roles_found.iter().map(String::as_str)) {
        sqlx::query(
            r#"UPDATE users SET role = $3, updated_at = now()
               WHERE id = $1 AND tenant_id = $2
                 AND lower(role) <> 'ceo'"#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(role)
        .execute(&mut *tx)
        .await?;
    }
    let _ = tx.commit().await;
    Ok(())
}

fn bearer_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
    let rest = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    let t = rest.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

async fn authenticate_scim(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<ScimPrincipal, Response> {
    let Some(raw) = bearer_from_headers(headers) else {
        return Err(scim_error(
            StatusCode::UNAUTHORIZED,
            "Authorization Bearer token required",
        ));
    };
    let hash = sha256_token(&raw);
    let row = sqlx::query(r#"SELECT token_id, tenant_id FROM public.lookup_scim_token($1)"#)
        .bind(&hash)
        .fetch_optional(state.app_pool.as_ref())
        .await
        .map_err(|_| scim_error(StatusCode::SERVICE_UNAVAILABLE, "token lookup failed"))?;
    let Some(row) = row else {
        return Err(scim_error(
            StatusCode::UNAUTHORIZED,
            "invalid or revoked token",
        ));
    };
    let tenant_id: i64 = row.try_get("tenant_id").unwrap_or(0);
    let token_id: i64 = row.try_get("token_id").unwrap_or(0);
    if tenant_id <= 0 || token_id <= 0 {
        return Err(scim_error(
            StatusCode::UNAUTHORIZED,
            "invalid or revoked token",
        ));
    }
    if let Ok(mut tx) = db::begin_tenant_tx(state.app_pool.as_ref(), tenant_id).await {
        let _ = sqlx::query(
            "UPDATE weissman_scim_tokens SET last_used_at = now() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(token_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
    }
    Ok(ScimPrincipal { tenant_id })
}

fn user_resource(
    scim_id: Uuid,
    email: &str,
    external_id: Option<&str>,
    active: bool,
    role: &str,
) -> Value {
    json!({
        "schemas": [USER_SCHEMA],
        "id": scim_id.to_string(),
        "externalId": external_id.unwrap_or(""),
        "userName": email,
        "active": active,
        "displayName": email,
        "emails": [{"value": email, "primary": true, "type": "work"}],
        "meta": {"resourceType": "User"},
        "roles": [{"value": role, "primary": true}],
    })
}

fn group_resource(id: Uuid, display: &str, external_id: Option<&str>, members: &[Value]) -> Value {
    json!({
        "schemas": [GROUP_SCHEMA],
        "id": id.to_string(),
        "externalId": external_id.unwrap_or(""),
        "displayName": display,
        "members": members,
        "meta": {"resourceType": "Group"},
    })
}

fn list_response(resources: Vec<Value>, start: i64, total: i64) -> Value {
    json!({
        "schemas": [LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

fn page_bounds(q: &ScimListQuery) -> (i64, i64) {
    let start = q.start_index.unwrap_or(1).max(1);
    let count = q.count.unwrap_or(100).clamp(1, 200);
    (start, count)
}

async fn ensure_scim_id(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    user_id: i64,
) -> Result<Uuid, sqlx::Error> {
    if let Some(id) = sqlx::query_scalar::<_, Uuid>(
        "SELECT scim_id FROM users WHERE id = $1 AND tenant_id = $2 AND scim_id IS NOT NULL",
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await?
    {
        return Ok(id);
    }
    let id = Uuid::new_v4();
    sqlx::query(
        "UPDATE users SET scim_id = $3 WHERE id = $1 AND tenant_id = $2 AND scim_id IS NULL",
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(id)
}

async fn record_event(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    action: &str,
    email: &str,
    user_id: Option<i64>,
    role: Option<&str>,
    sessions_revoked: i32,
    details: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO weissman_scim_events
           (tenant_id, action, user_email, user_id, role, sessions_revoked, details)
           VALUES ($1,$2,$3,$4,$5,$6,$7)"#,
    )
    .bind(tenant_id)
    .bind(action)
    .bind(email)
    .bind(user_id)
    .bind(role)
    .bind(sessions_revoked)
    .bind(details)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Deactivate + revoke sessions. Does not physically delete the user (audit trail).
/// Refresh + JTI writes go to `auth_pool` (`weissman_auth` BYPASSRLS). `weissman_app`
/// has no GRANT on `user_refresh_tokens` / `weissman_revoked_tokens`, and the latter
/// is FORCE RLS with no policy.
async fn kill_switch_user(
    tx: &mut Transaction<'_, Postgres>,
    auth_pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    email: &str,
) -> Result<i32, sqlx::Error> {
    sqlx::query(
        "UPDATE users SET is_active = false, updated_at = now() WHERE id = $1 AND tenant_id = $2",
    )
    .bind(user_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await?;
    let jtis: Vec<Option<String>> = sqlx::query_scalar(
        r#"UPDATE user_refresh_tokens SET revoked_at = now()
           WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
           RETURNING access_jti"#,
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_all(auth_pool)
    .await?;
    let mut n = 0i32;
    let exp = chrono::Utc::now() + chrono::Duration::hours(48);
    for jti in jtis.into_iter().flatten() {
        if jti.is_empty() {
            continue;
        }
        let _ = auth_refresh::revoke_access_jti(auth_pool, &jti, exp).await;
        n += 1;
    }
    record_event(
        tx,
        tenant_id,
        "kill_switch",
        email,
        Some(user_id),
        None,
        n,
        json!({"reason": "scim_deprovision"}),
    )
    .await?;
    Ok(n)
}

async fn reactivate_user(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    user_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users SET is_active = true, updated_at = now() WHERE id = $1 AND tenant_id = $2",
    )
    .bind(user_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn email_from_user_body(body: &Value) -> Option<String> {
    if let Some(u) = body.get("userName").and_then(Value::as_str) {
        let t = u.trim();
        if t.contains('@') {
            return Some(t.to_string());
        }
    }
    if let Some(arr) = body.get("emails").and_then(Value::as_array) {
        for e in arr {
            if let Some(v) = e.get("value").and_then(Value::as_str) {
                let t = v.trim();
                if t.contains('@') {
                    return Some(t.to_string());
                }
            }
        }
    }
    None
}

// ── Public SCIM protocol ────────────────────────────────────────────────────

pub async fn scim_service_provider_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = authenticate_scim(&state, &headers).await {
        return r;
    }
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": true},
            "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": true, "maxResults": 200},
            "changePassword": {"supported": false},
            "sort": {"supported": false},
            "etag": {"supported": false},
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Tenant SCIM token minted in Command Center SSO"
            }]
        }),
    )
}

pub async fn scim_resource_types(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = authenticate_scim(&state, &headers).await {
        return r;
    }
    scim_json(
        StatusCode::OK,
        json!([
            {"schemas":["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],"id":"User","name":"User","endpoint":"/Users","schema":USER_SCHEMA},
            {"schemas":["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],"id":"Group","name":"Group","endpoint":"/Groups","schema":GROUP_SCHEMA}
        ]),
    )
}

pub async fn scim_users_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ScimListQuery>,
) -> Response {
    let p = match authenticate_scim(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let (start, count) = page_bounds(&q);
    let mut tx = match db::begin_tenant_tx(state.app_pool.as_ref(), p.tenant_id).await {
        Ok(t) => t,
        Err(_) => return scim_error(StatusCode::SERVICE_UNAVAILABLE, "database"),
    };
    let parsed = q.filter.as_deref().and_then(parse_scim_eq_filter);
    let mut sql = String::from(
        r#"SELECT id, email, role, COALESCE(is_active,true) AS is_active,
                  scim_id, scim_external_id
           FROM users WHERE tenant_id = $1"#,
    );
    if let Some(f) = &parsed {
        match f.attr.as_str() {
            "username" | "emails.value" => {
                sql.push_str(" AND lower(trim(email)) = lower(trim($2))")
            }
            "externalid" => sql.push_str(" AND scim_external_id = $2"),
            "id" => sql.push_str(" AND scim_id::text = $2"),
            _ => {}
        }
    }
    sql.push_str(" ORDER BY id LIMIT 200");
    let mut query = sqlx::query(&sql).bind(p.tenant_id);
    if let Some(f) = &parsed {
        if matches!(
            f.attr.as_str(),
            "username" | "emails.value" | "externalid" | "id"
        ) {
            query = query.bind(&f.value);
        }
    }
    let rows = match query.fetch_all(&mut *tx).await {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.rollback().await;
            return scim_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
    };
    let total = rows.len() as i64;
    let mut resources = Vec::new();
    let skip = (start - 1) as usize;
    for r in rows.into_iter().skip(skip).take(count as usize) {
        let uid: i64 = r.try_get("id").unwrap_or(0);
        let email: String = r.try_get("email").unwrap_or_default();
        let role: String = r.try_get("role").unwrap_or_else(|_| roles::VIEWER.into());
        let active: bool = r.try_get("is_active").unwrap_or(true);
        let ext: Option<String> = r.try_get("scim_external_id").ok().flatten();
        let scim_id = match ensure_scim_id(&mut tx, p.tenant_id, uid).await {
            Ok(id) => id,
            Err(_) => continue,
        };
        resources.push(user_resource(
            scim_id,
            &email,
            ext.as_deref(),
            active,
            &role,
        ));
    }
    let _ = tx.commit().await;
    scim_json(StatusCode::OK, list_response(resources, start, total))
}

pub async fn scim_users_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let p = match authenticate_scim(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let mut tx = match db::begin_tenant_tx(state.app_pool.as_ref(), p.tenant_id).await {
        Ok(t) => t,
        Err(_) => return scim_error(StatusCode::SERVICE_UNAVAILABLE, "database"),
    };
    match load_user_by_scim(&mut tx, p.tenant_id, id).await {
        Ok(Some(v)) => {
            let _ = tx.commit().await;
            scim_json(StatusCode::OK, v)
        }
        Ok(None) => {
            let _ = tx.rollback().await;
            scim_error(StatusCode::NOT_FOUND, "User not found")
        }
        Err(e) => {
            let _ = tx.rollback().await;
            scim_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
        }
    }
}

async fn load_user_by_scim(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    scim_id: Uuid,
) -> Result<Option<Value>, sqlx::Error> {
    let row = sqlx::query(
        r#"SELECT id, email, role, COALESCE(is_active,true) AS is_active, scim_external_id
           FROM users WHERE tenant_id = $1 AND scim_id = $2"#,
    )
    .bind(tenant_id)
    .bind(scim_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.map(|r| {
        user_resource(
            scim_id,
            &r.try_get::<String, _>("email").unwrap_or_default(),
            r.try_get::<Option<String>, _>("scim_external_id")
                .ok()
                .flatten()
                .as_deref(),
            r.try_get("is_active").unwrap_or(true),
            &r.try_get::<String, _>("role")
                .unwrap_or_else(|_| roles::VIEWER.into()),
        )
    }))
}

pub async fn scim_users_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let p = match authenticate_scim(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let Some(email) = email_from_user_body(&body) else {
        return scim_error(StatusCode::BAD_REQUEST, "userName (email) required");
    };
    let active = body.get("active").and_then(Value::as_bool).unwrap_or(true);
    let external_id = body
        .get("externalId")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let mut tx = match db::begin_tenant_tx(state.app_pool.as_ref(), p.tenant_id).await {
        Ok(t) => t,
        Err(_) => return scim_error(StatusCode::SERVICE_UNAVAILABLE, "database"),
    };
    if let Ok(Some(_)) = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM users WHERE tenant_id = $1 AND lower(trim(email)) = lower(trim($2))",
    )
    .bind(p.tenant_id)
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await
    {
        let _ = tx.rollback().await;
        return scim_error(StatusCode::CONFLICT, "user already exists");
    }
    let scim_id = Uuid::new_v4();
    let inserted = sqlx::query_scalar::<_, i64>(
        r#"INSERT INTO users (tenant_id, email, password_hash, role, is_active, sso_provider, sso_id, scim_id, scim_external_id)
           VALUES ($1,$2,NULL,'viewer',$3,'scim',$4,$5,$6)
           RETURNING id"#,
    )
    .bind(p.tenant_id)
    .bind(&email)
    .bind(active)
    .bind(external_id.as_deref())
    .bind(scim_id)
    .bind(external_id.as_deref())
    .fetch_one(&mut *tx)
    .await;
    let user_id = match inserted {
        Ok(id) => id,
        Err(e) => {
            let _ = tx.rollback().await;
            return scim_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
    };
    if !active {
        let _ = kill_switch_user(
            &mut tx,
            state.auth_pool.as_ref(),
            p.tenant_id,
            user_id,
            &email,
        )
        .await;
    } else {
        let _ = record_event(
            &mut tx,
            p.tenant_id,
            "joiner",
            &email,
            Some(user_id),
            Some(roles::VIEWER),
            0,
            json!({"scim_id": scim_id.to_string()}),
        )
        .await;
    }
    let body_out = user_resource(
        scim_id,
        &email,
        external_id.as_deref(),
        active,
        roles::VIEWER,
    );
    let _ = tx.commit().await;
    scim_json(StatusCode::CREATED, body_out)
}

async fn patch_or_put_user(
    state: &AppState,
    p: ScimPrincipal,
    id: Uuid,
    body: &Value,
    is_patch: bool,
) -> Response {
    let mut tx = match db::begin_tenant_tx(state.app_pool.as_ref(), p.tenant_id).await {
        Ok(t) => t,
        Err(_) => return scim_error(StatusCode::SERVICE_UNAVAILABLE, "database"),
    };
    let row = sqlx::query(
        r#"SELECT id, email, COALESCE(is_active,true) AS is_active, role
           FROM users WHERE tenant_id = $1 AND scim_id = $2"#,
    )
    .bind(p.tenant_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await;
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            let _ = tx.rollback().await;
            return scim_error(StatusCode::NOT_FOUND, "User not found");
        }
        Err(e) => {
            let _ = tx.rollback().await;
            return scim_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
    };
    let user_id: i64 = row.try_get("id").unwrap_or(0);
    let mut email: String = row.try_get("email").unwrap_or_default();
    let mut active: bool = row.try_get("is_active").unwrap_or(true);
    let role: String = row.try_get("role").unwrap_or_else(|_| roles::VIEWER.into());

    let mut want_active = active;
    if is_patch {
        if let Some(ops) = body.get("Operations").and_then(Value::as_array) {
            for op in ops {
                let path = op
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let value = op.get("value");
                if path == "active" || path.is_empty() {
                    if let Some(v) = value.and_then(|v| {
                        v.as_bool()
                            .or_else(|| v.get("active").and_then(Value::as_bool))
                    }) {
                        want_active = v;
                    }
                }
                if path == "username" {
                    if let Some(v) = value.and_then(Value::as_str) {
                        email = v.trim().to_string();
                    }
                }
            }
        }
    } else {
        if let Some(e) = email_from_user_body(body) {
            email = e;
        }
        if let Some(a) = body.get("active").and_then(Value::as_bool) {
            want_active = a;
        }
        if let Some(ext) = body.get("externalId").and_then(Value::as_str) {
            let _ = sqlx::query(
                "UPDATE users SET scim_external_id = $3 WHERE id = $1 AND tenant_id = $2",
            )
            .bind(user_id)
            .bind(p.tenant_id)
            .bind(ext)
            .execute(&mut *tx)
            .await;
        }
    }

    let _ = sqlx::query(
        "UPDATE users SET email = $3, updated_at = now() WHERE id = $1 AND tenant_id = $2",
    )
    .bind(user_id)
    .bind(p.tenant_id)
    .bind(&email)
    .execute(&mut *tx)
    .await;

    if want_active != active {
        if want_active {
            let _ = reactivate_user(&mut tx, p.tenant_id, user_id).await;
            let _ = record_event(
                &mut tx,
                p.tenant_id,
                "rejoin",
                &email,
                Some(user_id),
                Some(&role),
                0,
                json!({}),
            )
            .await;
        } else {
            let _ = kill_switch_user(
                &mut tx,
                state.auth_pool.as_ref(),
                p.tenant_id,
                user_id,
                &email,
            )
            .await;
        }
        active = want_active;
    }

    let out = user_resource(id, &email, None, active, &role);
    let _ = tx.commit().await;
    scim_json(StatusCode::OK, out)
}

pub async fn scim_users_put(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Response {
    let p = match authenticate_scim(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    patch_or_put_user(&state, p, id, &body, false).await
}

pub async fn scim_users_patch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Response {
    let p = match authenticate_scim(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    patch_or_put_user(&state, p, id, &body, true).await
}

pub async fn scim_users_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let p = match authenticate_scim(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let mut tx = match db::begin_tenant_tx(state.app_pool.as_ref(), p.tenant_id).await {
        Ok(t) => t,
        Err(_) => return scim_error(StatusCode::SERVICE_UNAVAILABLE, "database"),
    };
    let row = sqlx::query("SELECT id, email FROM users WHERE tenant_id = $1 AND scim_id = $2")
        .bind(p.tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await;
    match row {
        Ok(Some(r)) => {
            let uid: i64 = r.try_get("id").unwrap_or(0);
            let email: String = r.try_get("email").unwrap_or_default();
            let _ =
                kill_switch_user(&mut tx, state.auth_pool.as_ref(), p.tenant_id, uid, &email).await;
            let _ = tx.commit().await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(None) => {
            let _ = tx.rollback().await;
            scim_error(StatusCode::NOT_FOUND, "User not found")
        }
        Err(e) => {
            let _ = tx.rollback().await;
            scim_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
        }
    }
}

async fn group_members_json(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    group_id: Uuid,
) -> Result<Vec<Value>, sqlx::Error> {
    let rows = sqlx::query(
        r#"SELECT u.scim_id, u.email FROM weissman_scim_group_members gm
           JOIN users u ON u.id = gm.user_id AND u.tenant_id = gm.tenant_id
           WHERE gm.tenant_id = $1 AND gm.group_id = $2"#,
    )
    .bind(tenant_id)
    .bind(group_id)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            let id: Uuid = r.try_get("scim_id").ok()?;
            let email: String = r.try_get("email").unwrap_or_default();
            Some(json!({"value": id.to_string(), "display": email, "type": "User"}))
        })
        .collect())
}

pub async fn scim_groups_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ScimListQuery>,
) -> Response {
    let p = match authenticate_scim(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let (start, count) = page_bounds(&q);
    let mut tx = match db::begin_tenant_tx(state.app_pool.as_ref(), p.tenant_id).await {
        Ok(t) => t,
        Err(_) => return scim_error(StatusCode::SERVICE_UNAVAILABLE, "database"),
    };
    let parsed = q.filter.as_deref().and_then(parse_scim_eq_filter);
    let rows = if let Some(f) = parsed {
        if f.attr == "displayname" {
            sqlx::query(
                "SELECT id, display_name, external_id FROM weissman_scim_groups WHERE tenant_id = $1 AND display_name = $2 ORDER BY display_name",
            )
            .bind(p.tenant_id)
            .bind(&f.value)
            .fetch_all(&mut *tx)
            .await
        } else if f.attr == "externalid" {
            sqlx::query(
                "SELECT id, display_name, external_id FROM weissman_scim_groups WHERE tenant_id = $1 AND external_id = $2 ORDER BY display_name",
            )
            .bind(p.tenant_id)
            .bind(&f.value)
            .fetch_all(&mut *tx)
            .await
        } else {
            sqlx::query(
                "SELECT id, display_name, external_id FROM weissman_scim_groups WHERE tenant_id = $1 ORDER BY display_name",
            )
            .bind(p.tenant_id)
            .fetch_all(&mut *tx)
            .await
        }
    } else {
        sqlx::query(
            "SELECT id, display_name, external_id FROM weissman_scim_groups WHERE tenant_id = $1 ORDER BY display_name",
        )
        .bind(p.tenant_id)
        .fetch_all(&mut *tx)
        .await
    };
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.rollback().await;
            return scim_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
    };
    let total = rows.len() as i64;
    let mut resources = Vec::new();
    let skip = (start - 1) as usize;
    for r in rows.into_iter().skip(skip).take(count as usize) {
        let gid: Uuid = match r.try_get("id") {
            Ok(id) => id,
            Err(_) => continue,
        };
        let display: String = r.try_get("display_name").unwrap_or_default();
        let ext: Option<String> = r.try_get("external_id").ok().flatten();
        let members = group_members_json(&mut tx, p.tenant_id, gid)
            .await
            .unwrap_or_default();
        resources.push(group_resource(gid, &display, ext.as_deref(), &members));
    }
    let _ = tx.commit().await;
    scim_json(StatusCode::OK, list_response(resources, start, total))
}

pub async fn scim_groups_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let p = match authenticate_scim(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let display = body
        .get("displayName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("");
    if display.is_empty() {
        return scim_error(StatusCode::BAD_REQUEST, "displayName required");
    }
    let external_id = body
        .get("externalId")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let mut tx = match db::begin_tenant_tx(state.app_pool.as_ref(), p.tenant_id).await {
        Ok(t) => t,
        Err(_) => return scim_error(StatusCode::SERVICE_UNAVAILABLE, "database"),
    };
    let gid = Uuid::new_v4();
    if let Err(e) = sqlx::query(
        r#"INSERT INTO weissman_scim_groups (id, tenant_id, external_id, display_name)
           VALUES ($1,$2,$3,$4)"#,
    )
    .bind(gid)
    .bind(p.tenant_id)
    .bind(external_id.as_deref())
    .bind(display)
    .execute(&mut *tx)
    .await
    {
        let _ = tx.rollback().await;
        return scim_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    }
    if let Some(members) = body.get("members").and_then(Value::as_array) {
        if let Err(e) = replace_group_members(&mut tx, p.tenant_id, gid, members).await {
            let _ = tx.rollback().await;
            return scim_error(StatusCode::BAD_REQUEST, &e.to_string());
        }
    }
    let members = group_members_json(&mut tx, p.tenant_id, gid)
        .await
        .unwrap_or_default();
    let _ = record_event(
        &mut tx,
        p.tenant_id,
        "group_create",
        display,
        None,
        None,
        0,
        json!({"group_id": gid.to_string()}),
    )
    .await;
    let _ = tx.commit().await;
    scim_json(
        StatusCode::CREATED,
        group_resource(gid, display, external_id.as_deref(), &members),
    )
}

fn scim_uuid_from_str(raw: &str) -> Option<Uuid> {
    Uuid::parse_str(raw.trim()).ok()
}

/// Ids from PatchOp `value` (array of {value} or strings) and `members[value eq "uuid"]`.
pub fn scim_member_ids_from_op(op: &Value) -> Vec<Uuid> {
    let mut ids = Vec::new();
    match op.get("value") {
        Some(Value::Array(items)) => {
            for m in items {
                if let Some(raw) = m
                    .get("value")
                    .and_then(Value::as_str)
                    .or_else(|| m.as_str())
                {
                    if let Some(id) = scim_uuid_from_str(raw) {
                        ids.push(id);
                    }
                }
            }
        }
        Some(Value::String(s)) => {
            if let Some(id) = scim_uuid_from_str(s) {
                ids.push(id);
            }
        }
        _ => {}
    }
    if let Some(path) = op.get("path").and_then(Value::as_str) {
        let Ok(re) =
            regex::Regex::new(r#"(?i)members\s*\[\s*value\s+eq\s+"([0-9a-fA-F-]{36})"\s*\]"#)
        else {
            return ids;
        };
        if let Some(cap) = re.captures(path) {
            if let Some(id) = cap.get(1).and_then(|m| scim_uuid_from_str(m.as_str())) {
                ids.push(id);
            }
        }
    }
    ids.sort();
    ids.dedup();
    ids
}

async fn add_group_members(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    group_id: Uuid,
    member_scim_ids: &[Uuid],
) -> Result<(), sqlx::Error> {
    for scim_id in member_scim_ids {
        let Some(user_id) = sqlx::query_scalar::<_, i64>(
            "SELECT id FROM users WHERE tenant_id = $1 AND scim_id = $2",
        )
        .bind(tenant_id)
        .bind(scim_id)
        .fetch_optional(&mut **tx)
        .await?
        else {
            continue;
        };
        sqlx::query(
            r#"INSERT INTO weissman_scim_group_members (tenant_id, group_id, user_id)
               VALUES ($1,$2,$3)
               ON CONFLICT (group_id, user_id) DO NOTHING"#,
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
        sync_user_role_from_memberships(tx, tenant_id, user_id).await?;
    }
    Ok(())
}

async fn remove_group_members(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    group_id: Uuid,
    member_scim_ids: &[Uuid],
) -> Result<(), sqlx::Error> {
    for scim_id in member_scim_ids {
        let user_id = sqlx::query_scalar::<_, i64>(
            r#"DELETE FROM weissman_scim_group_members gm
               USING users u
               WHERE gm.user_id = u.id AND gm.tenant_id = $1
                 AND gm.group_id = $2 AND u.scim_id = $3
               RETURNING gm.user_id"#,
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(scim_id)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(uid) = user_id {
            sync_user_role_from_memberships(tx, tenant_id, uid).await?;
        }
    }
    Ok(())
}

async fn replace_group_members(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    group_id: Uuid,
    members: &[Value],
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM weissman_scim_group_members WHERE tenant_id = $1 AND group_id = $2")
        .bind(tenant_id)
        .bind(group_id)
        .execute(&mut **tx)
        .await?;
    let ids: Vec<Uuid> = members
        .iter()
        .filter_map(|m| {
            m.get("value")
                .and_then(Value::as_str)
                .or_else(|| m.as_str())
                .and_then(scim_uuid_from_str)
        })
        .collect();
    add_group_members(tx, tenant_id, group_id, &ids).await
}

async fn sync_user_role_from_memberships(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    user_id: i64,
) -> Result<(), sqlx::Error> {
    let mapped: Vec<String> = sqlx::query_scalar(
        r#"SELECT m.weissman_role
           FROM weissman_scim_group_role_maps m
           JOIN weissman_scim_groups g
             ON g.tenant_id = m.tenant_id
            AND (g.external_id = m.group_external_id OR lower(g.display_name) = lower(m.group_display_name)
                 OR lower(g.display_name) = lower(m.group_external_id))
           JOIN weissman_scim_group_members gm
             ON gm.group_id = g.id AND gm.tenant_id = m.tenant_id
           WHERE m.tenant_id = $1 AND gm.user_id = $2"#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await?;
    if let Some(role) = highest_mapped_role(mapped.iter().map(String::as_str)) {
        sqlx::query(
            r#"UPDATE users SET role = $3, updated_at = now()
               WHERE id = $1 AND tenant_id = $2 AND lower(role) <> 'ceo'"#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(role)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

pub async fn scim_groups_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let p = match authenticate_scim(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let mut tx = match db::begin_tenant_tx(state.app_pool.as_ref(), p.tenant_id).await {
        Ok(t) => t,
        Err(_) => return scim_error(StatusCode::SERVICE_UNAVAILABLE, "database"),
    };
    let row = sqlx::query(
        "SELECT display_name, external_id FROM weissman_scim_groups WHERE tenant_id = $1 AND id = $2",
    )
    .bind(p.tenant_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await;
    match row {
        Ok(Some(r)) => {
            let display: String = r.try_get("display_name").unwrap_or_default();
            let ext: Option<String> = r.try_get("external_id").ok().flatten();
            let members = group_members_json(&mut tx, p.tenant_id, id)
                .await
                .unwrap_or_default();
            let _ = tx.commit().await;
            scim_json(
                StatusCode::OK,
                group_resource(id, &display, ext.as_deref(), &members),
            )
        }
        Ok(None) => {
            let _ = tx.rollback().await;
            scim_error(StatusCode::NOT_FOUND, "Group not found")
        }
        Err(e) => {
            let _ = tx.rollback().await;
            scim_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
        }
    }
}

pub async fn scim_groups_put(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Response {
    let p = match authenticate_scim(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    patch_or_put_group(&state, p, id, &body, false).await
}

pub async fn scim_groups_patch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Response {
    let p = match authenticate_scim(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    patch_or_put_group(&state, p, id, &body, true).await
}

async fn patch_or_put_group(
    state: &AppState,
    p: ScimPrincipal,
    id: Uuid,
    body: &Value,
    is_patch: bool,
) -> Response {
    let mut tx = match db::begin_tenant_tx(state.app_pool.as_ref(), p.tenant_id).await {
        Ok(t) => t,
        Err(_) => return scim_error(StatusCode::SERVICE_UNAVAILABLE, "database"),
    };
    let exists = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM weissman_scim_groups WHERE tenant_id = $1 AND id = $2",
    )
    .bind(p.tenant_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await;
    if !matches!(exists, Ok(Some(_))) {
        let _ = tx.rollback().await;
        return scim_error(StatusCode::NOT_FOUND, "Group not found");
    }
    if let Some(display) = body.get("displayName").and_then(Value::as_str) {
        let _ = sqlx::query(
            "UPDATE weissman_scim_groups SET display_name = $3, updated_at = now() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(p.tenant_id)
        .bind(display.trim())
        .execute(&mut *tx)
        .await;
    }
    if is_patch {
        if let Some(ops) = body.get("Operations").and_then(Value::as_array) {
            for op in ops {
                let verb = op
                    .get("op")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let path = op
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if path.contains("members") || path.is_empty() {
                    let ids = scim_member_ids_from_op(op);
                    if verb == "replace" {
                        if let Some(Value::Array(items)) = op.get("value") {
                            let _ = replace_group_members(&mut tx, p.tenant_id, id, items).await;
                        }
                    } else if verb == "add" {
                        // Incremental add — never wipe existing members (Entra/Okta).
                        let _ = add_group_members(&mut tx, p.tenant_id, id, &ids).await;
                    } else if verb == "remove" {
                        let _ = remove_group_members(&mut tx, p.tenant_id, id, &ids).await;
                    }
                }
            }
        }
    } else if let Some(members) = body.get("members").and_then(Value::as_array) {
        let _ = replace_group_members(&mut tx, p.tenant_id, id, members).await;
    }
    let display: String = sqlx::query_scalar(
        "SELECT display_name FROM weissman_scim_groups WHERE tenant_id = $1 AND id = $2",
    )
    .bind(p.tenant_id)
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or_default();
    let members = group_members_json(&mut tx, p.tenant_id, id)
        .await
        .unwrap_or_default();
    let _ = tx.commit().await;
    scim_json(StatusCode::OK, group_resource(id, &display, None, &members))
}

pub async fn scim_groups_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let p = match authenticate_scim(&state, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let mut tx = match db::begin_tenant_tx(state.app_pool.as_ref(), p.tenant_id).await {
        Ok(t) => t,
        Err(_) => return scim_error(StatusCode::SERVICE_UNAVAILABLE, "database"),
    };
    match sqlx::query("DELETE FROM weissman_scim_groups WHERE tenant_id = $1 AND id = $2")
        .bind(p.tenant_id)
        .bind(id)
        .execute(&mut *tx)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            let _ = tx.commit().await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(_) => {
            let _ = tx.rollback().await;
            scim_error(StatusCode::NOT_FOUND, "Group not found")
        }
        Err(e) => {
            let _ = tx.rollback().await;
            scim_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
        }
    }
}

// ── Operator APIs (JWT) ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct MintTokenBody {
    #[serde(default = "default_token_label")]
    pub label: String,
}

fn default_token_label() -> String {
    "entra-okta".to_string()
}

#[derive(Deserialize)]
pub struct GroupMapBody {
    pub maps: Vec<GroupMapRow>,
}

#[derive(Deserialize)]
pub struct GroupMapRow {
    pub group_external_id: String,
    #[serde(default)]
    pub group_display_name: String,
    pub weissman_role: String,
}

pub async fn api_scim_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = rbac::require_operator(&auth) {
        return r;
    }
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let tokens: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM weissman_scim_tokens WHERE tenant_id = $1 AND revoked_at IS NULL",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let maps: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM weissman_scim_group_role_maps WHERE tenant_id = $1",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM weissman_scim_events WHERE tenant_id = $1 AND created_at > now() - interval '7 days'",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let leavers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM weissman_scim_events WHERE tenant_id = $1 AND action = 'kill_switch' AND created_at > now() - interval '7 days'",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let _ = tx.commit().await;
    Json(json!({
        "ok": true,
        "scim_base": "/scim/v2",
        "active_tokens": tokens,
        "group_maps": maps,
        "events_7d": events,
        "kill_switches_7d": leavers,
        "live": true,
    }))
    .into_response()
}

pub async fn api_scim_tokens_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = rbac::require_admin(&auth) {
        return r;
    }
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let rows = sqlx::query(
        r#"SELECT id, token_prefix, label, created_at, last_used_at, revoked_at
           FROM weissman_scim_tokens WHERE tenant_id = $1
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
                    json!({
                        "id": r.try_get::<i64,_>("id").ok(),
                        "token_prefix": r.try_get::<String,_>("token_prefix").ok(),
                        "label": r.try_get::<String,_>("label").ok(),
                        "created_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at").ok(),
                        "last_used_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("last_used_at").ok().flatten(),
                        "revoked_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("revoked_at").ok().flatten(),
                    })
                })
                .collect();
            Json(json!({"tokens": items})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn api_scim_token_mint(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<MintTokenBody>,
) -> Response {
    if let Err(r) = rbac::require_admin(&auth) {
        return r;
    }
    let mut raw_bytes = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut raw_bytes);
    let raw = format!("wmn_scim_{}", hex::encode(raw_bytes));
    let hash = sha256_token(&raw);
    let prefix: String = raw.chars().take(16).collect();
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let id: Result<i64, _> = sqlx::query_scalar(
        r#"INSERT INTO weissman_scim_tokens (tenant_id, token_hash, token_prefix, label, created_by)
           VALUES ($1,$2,$3,$4,$5) RETURNING id"#,
    )
    .bind(auth.tenant_id)
    .bind(&hash)
    .bind(&prefix)
    .bind(body.label.trim())
    .bind(auth.user_id)
    .fetch_one(&mut *tx)
    .await;
    match id {
        Ok(id) => {
            let _ = tx.commit().await;
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": id,
                    "token": raw,
                    "token_prefix": prefix,
                    "warning": "Store this token in Entra/Okta now. Weissman stores only SHA-256.",
                })),
            )
                .into_response()
        }
        Err(e) => {
            let _ = tx.rollback().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

pub async fn api_scim_token_revoke(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    if let Err(r) = rbac::require_admin(&auth) {
        return r;
    }
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let res = sqlx::query(
        "UPDATE weissman_scim_tokens SET revoked_at = now() WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&mut *tx)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            let _ = tx.commit().await;
            Json(json!({"ok": true})).into_response()
        }
        Ok(_) => {
            let _ = tx.rollback().await;
            (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
        }
        Err(e) => {
            let _ = tx.rollback().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

pub async fn api_scim_group_maps_get(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = rbac::require_operator(&auth) {
        return r;
    }
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let rows = sqlx::query(
        r#"SELECT id, group_external_id, group_display_name, weissman_role, updated_at
           FROM weissman_scim_group_role_maps WHERE tenant_id = $1
           ORDER BY group_external_id"#,
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
                    json!({
                        "id": r.try_get::<i64,_>("id").ok(),
                        "group_external_id": r.try_get::<String,_>("group_external_id").ok(),
                        "group_display_name": r.try_get::<String,_>("group_display_name").ok(),
                        "weissman_role": r.try_get::<String,_>("weissman_role").ok(),
                        "updated_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("updated_at").ok(),
                    })
                })
                .collect();
            Json(json!({"maps": items})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn api_scim_group_maps_put(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<GroupMapBody>,
) -> Response {
    if let Err(r) = rbac::require_admin(&auth) {
        return r;
    }
    for row in &body.maps {
        if sanitize_role(&row.weissman_role).is_none() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid role {}", row.weissman_role)})),
            )
                .into_response();
        }
        if row.group_external_id.trim().is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "group_external_id required"})),
            )
                .into_response();
        }
    }
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    if let Err(e) = sqlx::query("DELETE FROM weissman_scim_group_role_maps WHERE tenant_id = $1")
        .bind(auth.tenant_id)
        .execute(&mut *tx)
        .await
    {
        let _ = tx.rollback().await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }
    for row in &body.maps {
        let role = sanitize_role(&row.weissman_role).unwrap_or(roles::VIEWER);
        if let Err(e) = sqlx::query(
            r#"INSERT INTO weissman_scim_group_role_maps
               (tenant_id, group_external_id, group_display_name, weissman_role)
               VALUES ($1,$2,$3,$4)"#,
        )
        .bind(auth.tenant_id)
        .bind(row.group_external_id.trim())
        .bind(row.group_display_name.trim())
        .bind(role)
        .execute(&mut *tx)
        .await
        {
            let _ = tx.rollback().await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    }
    let _ = tx.commit().await;
    Json(json!({"ok": true, "count": body.maps.len()})).into_response()
}

pub async fn api_scim_events(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = rbac::require_operator(&auth) {
        return r;
    }
    let mut tx = match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let rows = sqlx::query(
        r#"SELECT id, action, user_email, user_id, role, sessions_revoked, details, created_at
           FROM weissman_scim_events WHERE tenant_id = $1
           ORDER BY created_at DESC LIMIT 50"#,
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
                    json!({
                        "id": r.try_get::<i64,_>("id").ok(),
                        "action": r.try_get::<String,_>("action").ok(),
                        "user_email": r.try_get::<String,_>("user_email").ok(),
                        "user_id": r.try_get::<Option<i64>,_>("user_id").ok().flatten(),
                        "role": r.try_get::<Option<String>,_>("role").ok().flatten(),
                        "sessions_revoked": r.try_get::<i32,_>("sessions_revoked").ok(),
                        "details": r.try_get::<Value,_>("details").ok(),
                        "created_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at").ok(),
                    })
                })
                .collect();
            Json(json!({"events": items, "live": true})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[allow(dead_code)]
fn _patch_schema_ref() -> &'static str {
    PATCH_SCHEMA
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_role_allows_staff_and_blocks_ceo() {
        assert_eq!(sanitize_role("Admin"), Some(roles::ADMIN));
        assert_eq!(sanitize_role("analyst"), Some(roles::ANALYST));
        assert_eq!(sanitize_role("ceo"), None);
        assert_eq!(sanitize_role("superadmin"), None);
        assert_eq!(sanitize_role("client"), None);
        assert_eq!(sanitize_role(""), None);
    }

    #[test]
    fn highest_mapped_role_picks_admin_over_viewer() {
        assert_eq!(
            highest_mapped_role(["viewer", "admin", "analyst"]),
            Some(roles::ADMIN)
        );
        assert_eq!(highest_mapped_role(["ceo", "nope"]), None);
    }

    #[test]
    fn parse_scim_eq_filter_username() {
        let f = parse_scim_eq_filter(r#"userName eq "ada@weissman.io""#).unwrap();
        assert_eq!(f.attr, "username");
        assert_eq!(f.value, "ada@weissman.io");
        assert!(parse_scim_eq_filter("userName co ada").is_none());
    }

    #[test]
    fn groups_from_verified_jwt_reads_groups_claim() {
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            br#"{"groups":["Security-Analysts","Platform-Admins"]}"#,
        );
        let jwt = format!("aaa.{payload}.ccc");
        let g = groups_from_verified_jwt(&jwt);
        assert!(g.contains(&"Security-Analysts".into()));
        assert!(g.contains(&"Platform-Admins".into()));
    }

    #[test]
    fn groups_from_saml_xml_member_of() {
        let xml = r#"
        <Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups">
          <AttributeValue>Scan-Operators</AttributeValue>
          <AttributeValue>Security-Analysts</AttributeValue>
        </Attribute>"#;
        let g = groups_from_saml_xml(xml);
        assert!(g.contains(&"Scan-Operators".into()));
        assert!(g.contains(&"Security-Analysts".into()));
    }

    #[test]
    fn default_token_label_is_stable() {
        assert_eq!(default_token_label(), "entra-okta");
    }

    #[test]
    fn scim_member_ids_from_add_value_array() {
        let op = json!({
            "op": "add",
            "path": "members",
            "value": [{"value": "11111111-1111-1111-1111-111111111111"}]
        });
        let ids = scim_member_ids_from_op(&op);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].to_string(), "11111111-1111-1111-1111-111111111111");
    }

    #[test]
    fn scim_member_ids_from_remove_path_eq() {
        let op = json!({
            "op": "remove",
            "path": r#"members[value eq "22222222-2222-2222-2222-222222222222"]"#
        });
        let ids = scim_member_ids_from_op(&op);
        assert_eq!(ids[0].to_string(), "22222222-2222-2222-2222-222222222222");
    }
}
