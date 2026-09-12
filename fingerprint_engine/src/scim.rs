//! SCIM 2.0 (RFC 7643 / 7644) provisioning for Okta / Entra / Google Workspace.
//!
//! Bearers are SHA-256 hashed at rest. Handlers never invent users: they write the
//! live `users` / `scim_groups` tables under tenant RLS after `lookup_scim_token`.

use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::sync::Arc;

use crate::auth_jwt::AuthContext;
use crate::http::AppState;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const WEISSMAN_EXT: &str = "urn:ietf:params:scim:schemas:extension:weissman:2.0:User";
const TOKEN_PREFIX: &str = "wsm_scim_";
const MAX_PAGE: i64 = 200;

struct ScimCtx {
    tenant_id: i64,
    token_id: i64,
}

#[derive(Debug, Deserialize)]
pub struct ScimListQuery {
    #[serde(default)]
    filter: Option<String>,
    #[serde(default, rename = "startIndex")]
    start_index: Option<i64>,
    #[serde(default)]
    count: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ScimPatchBody {
    #[serde(default)]
    operations: Vec<ScimPatchOp>,
    #[serde(default, rename = "Operations")]
    operations_alt: Vec<ScimPatchOp>,
}

#[derive(Debug, Deserialize)]
pub struct ScimPatchOp {
    #[serde(default)]
    op: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    value: Value,
}

#[derive(Debug, Deserialize)]
pub struct MintTokenBody {
    #[serde(default)]
    name: String,
}

fn scim_error(status: StatusCode, detail: &str) -> Response {
    (
        status,
        Json(json!({
            "schemas": [ERROR_SCHEMA],
            "detail": detail,
            "status": status.as_u16().to_string(),
        })),
    )
        .into_response()
}

fn json_ok(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

pub fn hash_scim_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn hashes_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes()
        .iter()
        .zip(b.as_bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn bearer_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim();
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .unwrap_or(raw)
        .trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn parse_eq_filter(filter: &str, attr: &str) -> Option<String> {
    let f = filter.trim();
    let needle = format!("{attr} eq ");
    let lower = f.to_ascii_lowercase();
    let n = needle.to_ascii_lowercase();
    let idx = lower.find(&n)?;
    let rest = f[idx + needle.len()..].trim();
    if rest.len() >= 2 && rest.starts_with('"') {
        let end = rest[1..].find('"')?;
        Some(rest[1..=end].to_string())
    } else {
        Some(rest.split_whitespace().next()?.to_string())
    }
}

fn scim_role(raw: &str) -> Result<String, &'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "viewer" | "user" | "employee" => Ok("viewer".into()),
        "analyst" => Ok("analyst".into()),
        "operator" => Ok("operator".into()),
        "admin" => Ok("admin".into()),
        "ceo" | "superadmin" | "owner" => Err("role cannot be provisioned via SCIM"),
        other if other.len() <= 32 => Ok("viewer".into()),
        _ => Err("invalid role"),
    }
}

fn user_resource(id: i64, email: &str, role: &str, active: bool, external_id: Option<&str>) -> Value {
    let mut schemas = vec![USER_SCHEMA.to_string()];
    if !role.is_empty() {
        schemas.push(WEISSMAN_EXT.to_string());
    }
    let mut body = json!({
        "schemas": schemas,
        "id": id.to_string(),
        "externalId": external_id.unwrap_or(""),
        "userName": email,
        "active": active,
        "emails": [{"value": email, "primary": true, "type": "work"}],
        "name": { "formatted": email, "givenName": email },
        "meta": {
            "resourceType": "User",
            "location": format!("/api/scim/v2/Users/{id}"),
        },
    });
    body[WEISSMAN_EXT] = json!({ "role": role });
    body
}

fn group_resource(id: i64, display: &str, external_id: Option<&str>, members: Vec<(i64, String)>) -> Value {
    json!({
        "schemas": [GROUP_SCHEMA],
        "id": id.to_string(),
        "externalId": external_id.unwrap_or(""),
        "displayName": display,
        "members": members.iter().map(|(uid, email)| json!({
            "value": uid.to_string(),
            "display": email,
            "type": "User",
        })).collect::<Vec<_>>(),
        "meta": {
            "resourceType": "Group",
            "location": format!("/api/scim/v2/Groups/{id}"),
        },
    })
}

fn page_bounds(q: &ScimListQuery) -> (i64, i64) {
    let start = q.start_index.unwrap_or(1).max(1);
    let count = q.count.unwrap_or(100).clamp(1, MAX_PAGE);
    (start, count)
}

async fn authenticate_scim(state: &AppState, headers: &HeaderMap) -> Result<ScimCtx, Response> {
    let Some(token) = bearer_from_headers(headers) else {
        return Err(scim_error(StatusCode::UNAUTHORIZED, "Bearer token required"));
    };
    if !token.starts_with(TOKEN_PREFIX) {
        return Err(scim_error(StatusCode::UNAUTHORIZED, "invalid token"));
    }
    let hash = hash_scim_token(&token);
    let row = sqlx::query("SELECT out_id, out_tenant_id FROM public.lookup_scim_token($1)")
        .bind(&hash)
        .fetch_optional(state.app_pool.as_ref())
        .await
        .map_err(|_| scim_error(StatusCode::SERVICE_UNAVAILABLE, "token lookup failed"))?;
    let Some(row) = row else {
        return Err(scim_error(StatusCode::UNAUTHORIZED, "invalid token"));
    };
    let token_id: i64 = row.try_get("out_id").unwrap_or(0);
    let tenant_id: i64 = row.try_get("out_tenant_id").unwrap_or(0);
    if token_id <= 0 || tenant_id <= 0 {
        return Err(scim_error(StatusCode::UNAUTHORIZED, "invalid token"));
    }
    Ok(ScimCtx { tenant_id, token_id })
}

async fn begin_scim<'a>(
    pool: &'a PgPool,
    ctx: &ScimCtx,
) -> Result<Transaction<'a, Postgres>, Response> {
    crate::db::begin_tenant_tx(pool, ctx.tenant_id)
        .await
        .map_err(|_| scim_error(StatusCode::SERVICE_UNAVAILABLE, "database unavailable"))
}

async fn stamp_token_used(tx: &mut Transaction<'_, Postgres>, token_id: i64) {
    let _ = sqlx::query("UPDATE scim_tokens SET last_used_at = now() WHERE id = $1")
        .bind(token_id)
        .execute(&mut **tx)
        .await;
}

async fn audit_scim(
    tx: &mut Transaction<'_, Postgres>,
    ctx: &ScimCtx,
    method: &str,
    path: &str,
    status: i32,
    detail: &str,
) {
    let _ = sqlx::query(
        r#"INSERT INTO scim_audit_events (tenant_id, token_id, method, path, status, detail)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(ctx.tenant_id)
    .bind(ctx.token_id)
    .bind(method)
    .bind(path)
    .bind(status)
    .bind(detail)
    .execute(&mut **tx)
    .await;
}

fn extract_user_fields(body: &Value) -> Result<(String, bool, String, Option<String>, Option<String>), &'static str> {
    let user_name = body
        .get("userName")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("emails")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(|e| e.get("value").and_then(Value::as_str))
        })
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if user_name.is_empty() || !user_name.contains('@') {
        return Err("userName must be an email");
    }
    let active = body.get("active").and_then(Value::as_bool).unwrap_or(true);
    let ext_role = body
        .get(WEISSMAN_EXT)
        .and_then(|v| v.get("role"))
        .and_then(Value::as_str)
        .or_else(|| body.get("userType").and_then(Value::as_str))
        .unwrap_or("viewer");
    let role = scim_role(ext_role)?;
    let external_id = body
        .get("externalId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let password = body
        .get("password")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Ok((user_name, active, role, external_id, password))
}

fn hash_optional_password(password: Option<&str>) -> Result<String, Response> {
    match password {
        None | Some("") => Ok(String::new()),
        Some(p) if p.len() < 8 => Err(scim_error(
            StatusCode::BAD_REQUEST,
            "password must be at least 8 characters",
        )),
        Some(p) if p.as_bytes().len() > 72 => Err(scim_error(
            StatusCode::BAD_REQUEST,
            "password must be at most 72 bytes",
        )),
        Some(p) => bcrypt::hash(p, bcrypt::DEFAULT_COST)
            .map_err(|_| scim_error(StatusCode::INTERNAL_SERVER_ERROR, "password hash failed")),
    }
}

fn patch_ops(body: &ScimPatchBody) -> Vec<&ScimPatchOp> {
    if !body.operations.is_empty() {
        body.operations.iter().collect()
    } else {
        body.operations_alt.iter().collect()
    }
}

/// GET /api/scim/v2/ServiceProviderConfig
pub async fn scim_service_provider_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = authenticate_scim(&state, &headers).await {
        return r;
    }
    json_ok(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "https://www.rfc-editor.org/rfc/rfc7644",
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": MAX_PAGE },
            "changePassword": { "supported": true },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Weissman SCIM bearer (wsm_scim_*)",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                "primary": true
            }]
        }),
    )
}

/// GET /api/scim/v2/Users
pub async fn scim_users_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ScimListQuery>,
) -> Response {
    let ctx = match authenticate_scim(&state, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut tx = match begin_scim(state.app_pool.as_ref(), &ctx).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    stamp_token_used(&mut tx, ctx.token_id).await;
    let email_eq = q.filter.as_deref().and_then(|f| parse_eq_filter(f, "userName"));
    let ext_eq = q.filter.as_deref().and_then(|f| parse_eq_filter(f, "externalId"));
    let (start, count) = page_bounds(&q);
    let offset = start - 1;
    let rows = sqlx::query(
        r#"SELECT id, email, COALESCE(role,'viewer') AS role,
                  COALESCE(is_active, true) AS is_active, scim_external_id
             FROM users
            WHERE tenant_id = $1
              AND ($2::text IS NULL OR lower(email) = lower($2))
              AND ($3::text IS NULL OR scim_external_id = $3)
            ORDER BY id
            OFFSET $4 LIMIT $5"#,
    )
    .bind(ctx.tenant_id)
    .bind(email_eq.as_deref())
    .bind(ext_eq.as_deref())
    .bind(offset)
    .bind(count)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let total: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM users
            WHERE tenant_id = $1
              AND ($2::text IS NULL OR lower(email) = lower($2))
              AND ($3::text IS NULL OR scim_external_id = $3)"#,
    )
    .bind(ctx.tenant_id)
    .bind(email_eq.as_deref())
    .bind(ext_eq.as_deref())
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let resources: Vec<Value> = rows
        .iter()
        .map(|r| {
            user_resource(
                r.try_get("id").unwrap_or(0),
                &r.try_get::<String, _>("email").unwrap_or_default(),
                &r.try_get::<String, _>("role").unwrap_or_else(|_| "viewer".into()),
                r.try_get("is_active").unwrap_or(true),
                r.try_get::<Option<String>, _>("scim_external_id")
                    .ok()
                    .flatten()
                    .as_deref(),
            )
        })
        .collect();
    audit_scim(&mut tx, &ctx, "GET", "/api/scim/v2/Users", 200, "list").await;
    let _ = tx.commit().await;
    json_ok(
        StatusCode::OK,
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }),
    )
}

/// GET /api/scim/v2/Users/:id
pub async fn scim_users_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let ctx = match authenticate_scim(&state, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut tx = match begin_scim(state.app_pool.as_ref(), &ctx).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    stamp_token_used(&mut tx, ctx.token_id).await;
    let row = sqlx::query(
        r#"SELECT id, email, COALESCE(role,'viewer') AS role,
                  COALESCE(is_active, true) AS is_active, scim_external_id
             FROM users WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(id)
    .bind(ctx.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let Some(r) = row else {
        let _ = tx.rollback().await;
        return scim_error(StatusCode::NOT_FOUND, "user not found");
    };
    audit_scim(&mut tx, &ctx, "GET", &format!("/api/scim/v2/Users/{id}"), 200, "get").await;
    let _ = tx.commit().await;
    json_ok(
        StatusCode::OK,
        user_resource(
            r.try_get("id").unwrap_or(0),
            &r.try_get::<String, _>("email").unwrap_or_default(),
            &r.try_get::<String, _>("role").unwrap_or_else(|_| "viewer".into()),
            r.try_get("is_active").unwrap_or(true),
            r.try_get::<Option<String>, _>("scim_external_id")
                .ok()
                .flatten()
                .as_deref(),
        ),
    )
}

/// POST /api/scim/v2/Users
pub async fn scim_users_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let ctx = match authenticate_scim(&state, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (email, active, role, external_id, password) = match extract_user_fields(&body) {
        Ok(v) => v,
        Err(d) => return scim_error(StatusCode::BAD_REQUEST, d),
    };
    let hash = match hash_optional_password(password.as_deref()) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let mut tx = match begin_scim(state.app_pool.as_ref(), &ctx).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    stamp_token_used(&mut tx, ctx.token_id).await;
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM users WHERE tenant_id = $1 AND lower(email) = $2 LIMIT 1",
    )
    .bind(ctx.tenant_id)
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    if exists.is_some() {
        let _ = tx.rollback().await;
        return scim_error(StatusCode::CONFLICT, "user already exists");
    }
    let inserted = sqlx::query(
        r#"INSERT INTO users (tenant_id, email, password_hash, role, is_superadmin, is_active, scim_external_id)
           VALUES ($1, $2, $3, $4, false, $5, $6)
           RETURNING id"#,
    )
    .bind(ctx.tenant_id)
    .bind(&email)
    .bind(&hash)
    .bind(&role)
    .bind(active)
    .bind(external_id.as_deref())
    .fetch_one(&mut *tx)
    .await;
    match inserted {
        Ok(row) => {
            let id: i64 = row.try_get("id").unwrap_or(0);
            audit_scim(
                &mut tx,
                &ctx,
                "POST",
                "/api/scim/v2/Users",
                201,
                &format!("created {email}"),
            )
            .await;
            let _ = crate::audit_log::insert_audit(
                &mut tx,
                ctx.tenant_id,
                None,
                "scim",
                "scim_user_create",
                &format!("email={email} role={role}"),
                "",
            )
            .await;
            let _ = tx.commit().await;
            json_ok(
                StatusCode::CREATED,
                user_resource(id, &email, &role, active, external_id.as_deref()),
            )
        }
        Err(e) => {
            tracing::error!(target: "scim", error = %e, "user create failed");
            let _ = tx.rollback().await;
            scim_error(StatusCode::INTERNAL_SERVER_ERROR, "create failed")
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_user_update(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    id: i64,
    email: &str,
    role: &str,
    active: bool,
    external_id: Option<&str>,
    password_hash: Option<&str>,
) -> Result<u64, sqlx::Error> {
    let res = if let Some(hash) = password_hash {
        sqlx::query(
            r#"UPDATE users SET email = $1, role = $2, is_active = $3, scim_external_id = $4,
                       password_hash = $5, updated_at = now()
                 WHERE id = $6 AND tenant_id = $7 AND COALESCE(is_superadmin,false) = false
                   AND role NOT IN ('ceo')"#,
        )
        .bind(email)
        .bind(role)
        .bind(active)
        .bind(external_id)
        .bind(hash)
        .bind(id)
        .bind(tenant_id)
        .execute(&mut **tx)
        .await?
    } else {
        sqlx::query(
            r#"UPDATE users SET email = $1, role = $2, is_active = $3, scim_external_id = $4,
                       updated_at = now()
                 WHERE id = $5 AND tenant_id = $6 AND COALESCE(is_superadmin,false) = false
                   AND role NOT IN ('ceo')"#,
        )
        .bind(email)
        .bind(role)
        .bind(active)
        .bind(external_id)
        .bind(id)
        .bind(tenant_id)
        .execute(&mut **tx)
        .await?
    };
    Ok(res.rows_affected())
}

/// PUT /api/scim/v2/Users/:id
pub async fn scim_users_put(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> Response {
    let ctx = match authenticate_scim(&state, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (email, active, role, external_id, password) = match extract_user_fields(&body) {
        Ok(v) => v,
        Err(d) => return scim_error(StatusCode::BAD_REQUEST, d),
    };
    let hash = match hash_optional_password(password.as_deref()) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let mut tx = match begin_scim(state.app_pool.as_ref(), &ctx).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    stamp_token_used(&mut tx, ctx.token_id).await;
    let pwd = if hash.is_empty() { None } else { Some(hash.as_str()) };
    match write_user_update(
        &mut tx,
        ctx.tenant_id,
        id,
        &email,
        &role,
        active,
        external_id.as_deref(),
        pwd,
    )
    .await
    {
        Ok(n) if n > 0 => {
            audit_scim(&mut tx, &ctx, "PUT", &format!("/api/scim/v2/Users/{id}"), 200, "replace")
                .await;
            let _ = tx.commit().await;
            json_ok(
                StatusCode::OK,
                user_resource(id, &email, &role, active, external_id.as_deref()),
            )
        }
        Ok(_) => {
            let _ = tx.rollback().await;
            scim_error(StatusCode::NOT_FOUND, "user not found or protected")
        }
        Err(_) => {
            let _ = tx.rollback().await;
            scim_error(StatusCode::INTERNAL_SERVER_ERROR, "update failed")
        }
    }
}

/// PATCH /api/scim/v2/Users/:id
pub async fn scim_users_patch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<ScimPatchBody>,
) -> Response {
    let ctx = match authenticate_scim(&state, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut tx = match begin_scim(state.app_pool.as_ref(), &ctx).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    stamp_token_used(&mut tx, ctx.token_id).await;
    let row = sqlx::query(
        r#"SELECT email, COALESCE(role,'viewer') AS role, COALESCE(is_active,true) AS is_active,
                  scim_external_id, COALESCE(is_superadmin,false) AS is_superadmin
             FROM users WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(id)
    .bind(ctx.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let Some(r) = row else {
        let _ = tx.rollback().await;
        return scim_error(StatusCode::NOT_FOUND, "user not found");
    };
    if r.try_get::<bool, _>("is_superadmin").unwrap_or(false)
        || r.try_get::<String, _>("role").unwrap_or_default() == "ceo"
    {
        let _ = tx.rollback().await;
        return scim_error(StatusCode::FORBIDDEN, "protected account");
    }
    let mut email: String = r.try_get("email").unwrap_or_default();
    let mut role: String = r.try_get("role").unwrap_or_else(|_| "viewer".into());
    let mut active: bool = r.try_get("is_active").unwrap_or(true);
    let mut external_id: Option<String> = r.try_get("scim_external_id").ok().flatten();
    let mut new_password: Option<String> = None;
    for op in patch_ops(&body) {
        let verb = op.op.trim().to_ascii_lowercase();
        let path = op.path.as_deref().unwrap_or("").trim().trim_start_matches('/');
        match (verb.as_str(), path) {
            ("replace" | "add", "active") => {
                active = op.value.as_bool().or_else(|| {
                    op.value.as_object().and_then(|m| m.get("active")).and_then(Value::as_bool)
                }).unwrap_or(active);
            }
            ("replace" | "add", "username" | "userName") => {
                if let Some(v) = op.value.as_str() {
                    email = v.trim().to_ascii_lowercase();
                }
            }
            ("replace" | "add", "externalid" | "externalId") => {
                external_id = op.value.as_str().map(|s| s.to_string());
            }
            ("replace" | "add", "password") => {
                new_password = op.value.as_str().map(str::to_string);
            }
            ("replace" | "add", p) if p.contains("role") => {
                match scim_role(op.value.as_str().unwrap_or("viewer")) {
                    Ok(rr) => role = rr,
                    Err(d) => {
                        let _ = tx.rollback().await;
                        return scim_error(StatusCode::BAD_REQUEST, d);
                    }
                }
            }
            _ => {}
        }
    }
    let hash = match hash_optional_password(new_password.as_deref()) {
        Ok(h) => h,
        Err(r) => {
            let _ = tx.rollback().await;
            return r;
        }
    };
    let pwd = if hash.is_empty() { None } else { Some(hash.as_str()) };
    match write_user_update(
        &mut tx,
        ctx.tenant_id,
        id,
        &email,
        &role,
        active,
        external_id.as_deref(),
        pwd,
    )
    .await
    {
        Ok(n) if n > 0 => {
            audit_scim(&mut tx, &ctx, "PATCH", &format!("/api/scim/v2/Users/{id}"), 200, "patch")
                .await;
            let _ = tx.commit().await;
            json_ok(
                StatusCode::OK,
                user_resource(id, &email, &role, active, external_id.as_deref()),
            )
        }
        _ => {
            let _ = tx.rollback().await;
            scim_error(StatusCode::NOT_FOUND, "user not found or protected")
        }
    }
}

/// DELETE /api/scim/v2/Users/:id — deactivate (never hard-delete audit identity).
pub async fn scim_users_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let ctx = match authenticate_scim(&state, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut tx = match begin_scim(state.app_pool.as_ref(), &ctx).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    stamp_token_used(&mut tx, ctx.token_id).await;
    let n = sqlx::query(
        r#"UPDATE users SET is_active = false, updated_at = now()
            WHERE id = $1 AND tenant_id = $2
              AND COALESCE(is_superadmin,false) = false AND role NOT IN ('ceo')"#,
    )
    .bind(id)
    .bind(ctx.tenant_id)
    .execute(&mut *tx)
    .await
    .map(|r| r.rows_affected())
    .unwrap_or(0);
    if n == 0 {
        let _ = tx.rollback().await;
        return scim_error(StatusCode::NOT_FOUND, "user not found or protected");
    }
    audit_scim(&mut tx, &ctx, "DELETE", &format!("/api/scim/v2/Users/{id}"), 204, "deactivate")
        .await;
    let _ = crate::audit_log::insert_audit(
        &mut tx,
        ctx.tenant_id,
        None,
        "scim",
        "scim_user_deactivate",
        &format!("id={id}"),
        "",
    )
    .await;
    let _ = tx.commit().await;
    StatusCode::NO_CONTENT.into_response()
}

async fn load_group_members(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    group_id: i64,
) -> Vec<(i64, String)> {
    sqlx::query(
        r#"SELECT u.id, u.email FROM scim_group_members m
             JOIN users u ON u.id = m.user_id
            WHERE m.tenant_id = $1 AND m.group_id = $2
            ORDER BY u.id"#,
    )
    .bind(tenant_id)
    .bind(group_id)
    .fetch_all(&mut **tx)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| {
        (
            r.try_get("id").unwrap_or(0),
            r.try_get::<String, _>("email").unwrap_or_default(),
        )
    })
    .collect()
}

/// GET /api/scim/v2/Groups
pub async fn scim_groups_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ScimListQuery>,
) -> Response {
    let ctx = match authenticate_scim(&state, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut tx = match begin_scim(state.app_pool.as_ref(), &ctx).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    stamp_token_used(&mut tx, ctx.token_id).await;
    let name_eq = q
        .filter
        .as_deref()
        .and_then(|f| parse_eq_filter(f, "displayName"));
    let (start, count) = page_bounds(&q);
    let rows = sqlx::query(
        r#"SELECT id, display_name, external_id FROM scim_groups
            WHERE tenant_id = $1 AND ($2::text IS NULL OR display_name = $2)
            ORDER BY id OFFSET $3 LIMIT $4"#,
    )
    .bind(ctx.tenant_id)
    .bind(name_eq.as_deref())
    .bind(start - 1)
    .bind(count)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let total: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM scim_groups
            WHERE tenant_id = $1 AND ($2::text IS NULL OR display_name = $2)"#,
    )
    .bind(ctx.tenant_id)
    .bind(name_eq.as_deref())
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let mut resources = Vec::new();
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let members = load_group_members(&mut tx, ctx.tenant_id, id).await;
        resources.push(group_resource(
            id,
            &r.try_get::<String, _>("display_name").unwrap_or_default(),
            r.try_get::<Option<String>, _>("external_id")
                .ok()
                .flatten()
                .as_deref(),
            members,
        ));
    }
    audit_scim(&mut tx, &ctx, "GET", "/api/scim/v2/Groups", 200, "list").await;
    let _ = tx.commit().await;
    json_ok(
        StatusCode::OK,
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }),
    )
}

/// GET /api/scim/v2/Groups/:id
pub async fn scim_groups_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let ctx = match authenticate_scim(&state, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut tx = match begin_scim(state.app_pool.as_ref(), &ctx).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    stamp_token_used(&mut tx, ctx.token_id).await;
    let row = sqlx::query(
        "SELECT id, display_name, external_id FROM scim_groups WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(ctx.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let Some(r) = row else {
        let _ = tx.rollback().await;
        return scim_error(StatusCode::NOT_FOUND, "group not found");
    };
    let members = load_group_members(&mut tx, ctx.tenant_id, id).await;
    audit_scim(&mut tx, &ctx, "GET", &format!("/api/scim/v2/Groups/{id}"), 200, "get").await;
    let _ = tx.commit().await;
    json_ok(
        StatusCode::OK,
        group_resource(
            id,
            &r.try_get::<String, _>("display_name").unwrap_or_default(),
            r.try_get::<Option<String>, _>("external_id")
                .ok()
                .flatten()
                .as_deref(),
            members,
        ),
    )
}

/// POST /api/scim/v2/Groups
pub async fn scim_groups_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let ctx = match authenticate_scim(&state, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let display = body
        .get("displayName")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if display.is_empty() {
        return scim_error(StatusCode::BAD_REQUEST, "displayName required");
    }
    let external_id = body
        .get("externalId")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut tx = match begin_scim(state.app_pool.as_ref(), &ctx).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    stamp_token_used(&mut tx, ctx.token_id).await;
    let inserted = sqlx::query(
        r#"INSERT INTO scim_groups (tenant_id, display_name, external_id)
           VALUES ($1, $2, $3) RETURNING id"#,
    )
    .bind(ctx.tenant_id)
    .bind(&display)
    .bind(external_id.as_deref())
    .fetch_one(&mut *tx)
    .await;
    match inserted {
        Ok(row) => {
            let id: i64 = row.try_get("id").unwrap_or(0);
            if let Some(members) = body.get("members").and_then(Value::as_array) {
                for m in members {
                    if let Some(uid) = m
                        .get("value")
                        .and_then(|v| v.as_str().and_then(|s| s.parse::<i64>().ok()).or_else(|| v.as_i64()))
                    {
                        let _ = sqlx::query(
                            r#"INSERT INTO scim_group_members (tenant_id, group_id, user_id)
                               SELECT $1, $2, id FROM users WHERE id = $3 AND tenant_id = $1
                               ON CONFLICT DO NOTHING"#,
                        )
                        .bind(ctx.tenant_id)
                        .bind(id)
                        .bind(uid)
                        .execute(&mut *tx)
                        .await;
                    }
                }
            }
            let loaded = load_group_members(&mut tx, ctx.tenant_id, id).await;
            audit_scim(&mut tx, &ctx, "POST", "/api/scim/v2/Groups", 201, "created").await;
            let _ = tx.commit().await;
            json_ok(
                StatusCode::CREATED,
                group_resource(id, &display, external_id.as_deref(), loaded),
            )
        }
        Err(_) => {
            let _ = tx.rollback().await;
            scim_error(StatusCode::CONFLICT, "group already exists")
        }
    }
}

/// PATCH /api/scim/v2/Groups/:id
pub async fn scim_groups_patch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<ScimPatchBody>,
) -> Response {
    let ctx = match authenticate_scim(&state, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut tx = match begin_scim(state.app_pool.as_ref(), &ctx).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    stamp_token_used(&mut tx, ctx.token_id).await;
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM scim_groups WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(ctx.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    if exists.is_none() {
        let _ = tx.rollback().await;
        return scim_error(StatusCode::NOT_FOUND, "group not found");
    }
    for op in patch_ops(&body) {
        let verb = op.op.trim().to_ascii_lowercase();
        let path = op.path.as_deref().unwrap_or("").to_ascii_lowercase();
        if path.contains("displayname") {
            if let Some(name) = op.value.as_str() {
                let _ = sqlx::query(
                    "UPDATE scim_groups SET display_name = $1, updated_at = now() WHERE id = $2 AND tenant_id = $3",
                )
                .bind(name)
                .bind(id)
                .bind(ctx.tenant_id)
                .execute(&mut *tx)
                .await;
            }
        }
        if path.contains("members") || path.is_empty() {
            let values = if op.value.is_array() {
                op.value.as_array().cloned().unwrap_or_default()
            } else {
                op.value
                    .get("members")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
            };
            if verb == "replace" && (path.contains("members") || path.is_empty()) {
                if path.contains("members") {
                    let _ = sqlx::query(
                        "DELETE FROM scim_group_members WHERE group_id = $1 AND tenant_id = $2",
                    )
                    .bind(id)
                    .bind(ctx.tenant_id)
                    .execute(&mut *tx)
                    .await;
                }
            }
            for m in values {
                let Some(uid) = m
                    .get("value")
                    .and_then(|v| v.as_str().and_then(|s| s.parse::<i64>().ok()).or_else(|| v.as_i64()))
                else {
                    continue;
                };
                if verb == "remove" {
                    let _ = sqlx::query(
                        "DELETE FROM scim_group_members WHERE group_id = $1 AND user_id = $2 AND tenant_id = $3",
                    )
                    .bind(id)
                    .bind(uid)
                    .bind(ctx.tenant_id)
                    .execute(&mut *tx)
                    .await;
                } else {
                    let _ = sqlx::query(
                        r#"INSERT INTO scim_group_members (tenant_id, group_id, user_id)
                           SELECT $1, $2, id FROM users WHERE id = $3 AND tenant_id = $1
                           ON CONFLICT DO NOTHING"#,
                    )
                    .bind(ctx.tenant_id)
                    .bind(id)
                    .bind(uid)
                    .execute(&mut *tx)
                    .await;
                }
            }
        }
    }
    let row = sqlx::query(
        "SELECT display_name, external_id FROM scim_groups WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(ctx.tenant_id)
    .fetch_one(&mut *tx)
    .await;
    let Ok(r) = row else {
        let _ = tx.rollback().await;
        return scim_error(StatusCode::NOT_FOUND, "group not found");
    };
    let members = load_group_members(&mut tx, ctx.tenant_id, id).await;
    audit_scim(&mut tx, &ctx, "PATCH", &format!("/api/scim/v2/Groups/{id}"), 200, "patch").await;
    let _ = tx.commit().await;
    json_ok(
        StatusCode::OK,
        group_resource(
            id,
            &r.try_get::<String, _>("display_name").unwrap_or_default(),
            r.try_get::<Option<String>, _>("external_id")
                .ok()
                .flatten()
                .as_deref(),
            members,
        ),
    )
}

/// DELETE /api/scim/v2/Groups/:id
pub async fn scim_groups_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let ctx = match authenticate_scim(&state, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut tx = match begin_scim(state.app_pool.as_ref(), &ctx).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    stamp_token_used(&mut tx, ctx.token_id).await;
    let n = sqlx::query("DELETE FROM scim_groups WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(ctx.tenant_id)
        .execute(&mut *tx)
        .await
        .map(|r| r.rows_affected())
        .unwrap_or(0);
    if n == 0 {
        let _ = tx.rollback().await;
        return scim_error(StatusCode::NOT_FOUND, "group not found");
    }
    audit_scim(&mut tx, &ctx, "DELETE", &format!("/api/scim/v2/Groups/{id}"), 204, "delete").await;
    let _ = tx.commit().await;
    StatusCode::NO_CONTENT.into_response()
}

fn mint_plaintext_token() -> String {
    format!("{TOKEN_PREFIX}{}", hex::encode(rand::random::<[u8; 32]>()))
}

/// GET /api/admin/scim/tokens
pub async fn api_admin_scim_tokens_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let mut tx = match crate::db::begin_tenant_tx(state.app_pool.as_ref(), auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false})),
            )
                .into_response();
        }
    };
    let rows = sqlx::query(
        r#"SELECT id, name, token_prefix, last_used_at, revoked_at, created_at
             FROM scim_tokens WHERE tenant_id = $1 ORDER BY id DESC"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let tokens: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "name": r.try_get::<String,_>("name").unwrap_or_default(),
                "token_prefix": r.try_get::<String,_>("token_prefix").unwrap_or_default(),
                "last_used_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("last_used_at").ok().flatten().map(|d| d.to_rfc3339()),
                "revoked_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("revoked_at").ok().flatten().map(|d| d.to_rfc3339()),
                "created_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("created_at").ok().flatten().map(|d| d.to_rfc3339()),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "tokens": tokens,
            "base_path": "/api/scim/v2",
            "secret_storage": "sha256_hex_only",
        })),
    )
        .into_response()
}

/// POST /api/admin/scim/tokens
pub async fn api_admin_scim_tokens_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<MintTokenBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 80 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "name required (1–80 chars)"})),
        )
            .into_response();
    }
    let plaintext = mint_plaintext_token();
    let hash = hash_scim_token(&plaintext);
    let prefix: String = plaintext.chars().take(16).collect();
    let mut tx = match crate::db::begin_tenant_tx(state.app_pool.as_ref(), auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false})),
            )
                .into_response();
        }
    };
    let inserted = sqlx::query(
        r#"INSERT INTO scim_tokens (tenant_id, name, token_hash, token_prefix, created_by)
           VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at"#,
    )
    .bind(auth.tenant_id)
    .bind(name)
    .bind(&hash)
    .bind(&prefix)
    .bind(auth.user_id)
    .fetch_one(&mut *tx)
    .await;
    match inserted {
        Ok(row) => {
            let id: i64 = row.try_get("id").unwrap_or(0);
            let _ = crate::audit_log::insert_audit(
                &mut tx,
                auth.tenant_id,
                Some(auth.user_id),
                "admin",
                "scim_token_mint",
                &format!("id={id} name={name}"),
                "",
            )
            .await;
            let _ = tx.commit().await;
            (
                StatusCode::CREATED,
                Json(json!({
                    "ok": true,
                    "id": id,
                    "name": name,
                    "token": plaintext,
                    "token_prefix": prefix,
                    "shown_once": true,
                    "base_path": "/api/scim/v2",
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(target: "scim", error = %e, "token mint failed");
            let _ = tx.rollback().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "mint failed"})),
            )
                .into_response()
        }
    }
}

/// DELETE /api/admin/scim/tokens/:id
pub async fn api_admin_scim_tokens_revoke(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let mut tx = match crate::db::begin_tenant_tx(state.app_pool.as_ref(), auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false})),
            )
                .into_response();
        }
    };
    let n = sqlx::query(
        r#"UPDATE scim_tokens SET revoked_at = now()
            WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL"#,
    )
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&mut *tx)
    .await
    .map(|r| r.rows_affected())
    .unwrap_or(0);
    if n == 0 {
        let _ = tx.rollback().await;
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "token not found"})),
        )
            .into_response();
    }
    let _ = crate::audit_log::insert_audit(
        &mut tx,
        auth.tenant_id,
        Some(auth.user_id),
        "admin",
        "scim_token_revoke",
        &format!("id={id}"),
        "",
    )
    .await;
    let _ = tx.commit().await;
    (StatusCode::OK, Json(json!({"ok": true, "id": id, "revoked": true}))).into_response()
}

/// GET /api/admin/scim/audit
pub async fn api_admin_scim_audit(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    let mut tx = match crate::db::begin_tenant_tx(state.app_pool.as_ref(), auth.tenant_id).await {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false})),
            )
                .into_response();
        }
    };
    let rows = sqlx::query(
        r#"SELECT id, method, path, status, detail, created_at
             FROM scim_audit_events WHERE tenant_id = $1
             ORDER BY id DESC LIMIT 200"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let events: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "method": r.try_get::<String,_>("method").unwrap_or_default(),
                "path": r.try_get::<String,_>("path").unwrap_or_default(),
                "status": r.try_get::<i32,_>("status").unwrap_or(0),
                "detail": r.try_get::<String,_>("detail").unwrap_or_default(),
                "created_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("created_at").ok().flatten().map(|d| d.to_rfc3339()),
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({"ok": true, "events": events}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_is_64_hex_and_stable() {
        let t = "wsm_scim_deadbeef";
        let h = hash_scim_token(t);
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_scim_token(t));
        assert_ne!(h, hash_scim_token("wsm_scim_other"));
    }

    #[test]
    fn hashes_eq_is_length_safe() {
        assert!(hashes_eq("aa", "aa"));
        assert!(!hashes_eq("aa", "ab"));
        assert!(!hashes_eq("aa", "aaa"));
    }

    #[test]
    fn parse_username_eq_filter() {
        assert_eq!(
            parse_eq_filter(r#"userName eq "ops@weissman.io""#, "userName").as_deref(),
            Some("ops@weissman.io")
        );
        assert_eq!(
            parse_eq_filter("userName eq ops@weissman.io", "userName").as_deref(),
            Some("ops@weissman.io")
        );
    }

    #[test]
    fn scim_role_never_promotes_owner() {
        assert_eq!(scim_role("analyst").unwrap(), "analyst");
        assert!(scim_role("ceo").is_err());
        assert!(scim_role("superadmin").is_err());
        assert_eq!(scim_role("").unwrap(), "viewer");
    }

    #[test]
    fn mint_token_uses_live_prefix() {
        let t = mint_plaintext_token();
        assert!(t.starts_with(TOKEN_PREFIX));
        assert!(t.len() > 20);
    }

    #[test]
    fn extract_email_from_scim_user() {
        let body = json!({
            "schemas": [USER_SCHEMA],
            "userName": "Ada@Weissman.io",
            "active": true,
            "userType": "operator"
        });
        let (email, active, role, _, _) = extract_user_fields(&body).unwrap();
        assert_eq!(email, "ada@weissman.io");
        assert!(active);
        assert_eq!(role, "operator");
    }

    #[test]
    fn patch_schema_constant_is_rfc() {
        assert!(PATCH_SCHEMA.contains("PatchOp"));
    }

    #[test]
    fn user_resource_uses_extension_urn_not_placeholder() {
        let v = user_resource(9, "ops@weissman.io", "operator", true, Some("ext-1"));
        assert!(v.get(WEISSMAN_EXT).is_some());
        assert!(v.get("WEISSMAN_EXT").is_none());
        assert_eq!(v[WEISSMAN_EXT]["role"], "operator");
        assert_eq!(v["userName"], "ops@weissman.io");
    }
}
