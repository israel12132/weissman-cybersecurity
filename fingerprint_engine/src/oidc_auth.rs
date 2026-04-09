//! OpenID Connect: discovery, PKCE, authorization redirect, code exchange, id_token verification, JIT user provisioning.

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use oauth2::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope,
};
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{AuthenticationFlow, IssuerUrl, Nonce};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::audit_log;
use crate::db;
use crate::http::AppState;

#[derive(Deserialize)]
pub struct OidcBeginQuery {
    pub tenant_slug: String,
    pub idp_name: String,
}

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    code: String,
    state: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct IdpBeginRow {
    id: i64,
    tenant_id: i64,
    issuer_url: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_path: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct IdpCbRow {
    issuer_url: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OidcStateFull {
    idp_id: i64,
    tenant_id: i64,
    nonce: String,
    exp: i64,
    pkce_verifier: String,
}

fn public_base_url() -> String {
    std::env::var("WEISSMAN_PUBLIC_BASE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8000".to_string())
}

/// GET /api/auth/oidc/begin
pub async fn oidc_begin(
    State(state): State<Arc<AppState>>,
    Query(q): Query<OidcBeginQuery>,
) -> Result<Redirect, (StatusCode, Json<serde_json::Value>)> {
    let auth = state.auth_pool.as_ref();
    let slug = q.tenant_slug.trim();
    let name = q.idp_name.trim();
    if slug.is_empty() || name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "tenant_slug and idp_name required"})),
        ));
    }
    let row = sqlx::query_as::<_, IdpBeginRow>(
        r#"SELECT i.id, i.tenant_id, i.issuer_url, i.client_id, i.client_secret, i.redirect_path
           FROM tenant_idps i
           INNER JOIN tenants t ON t.id = i.tenant_id
           WHERE t.slug = $1 AND i.name = $2 AND i.provider = 'oidc' AND i.active = true AND t.active = true"#,
    )
    .bind(slug)
    .bind(name)
    .fetch_optional(auth)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": format!("db: {}", e)})),
        )
    })?;
    let Some(r) = row else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "IdP not found for tenant"})),
        ));
    };
    let IdpBeginRow {
        id: idp_id,
        tenant_id,
        issuer_url: issuer,
        client_id,
        client_secret,
        redirect_path,
    } = r;
    if !redirect_path.starts_with('/') {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": "redirect_path must start with /"})),
        ));
    }
    let issuer_url = IssuerUrl::new(issuer).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "invalid issuer_url in DB"})),
        )
    })?;
    let metadata =
        CoreProviderMetadata::discover_async(issuer_url, &oauth2::reqwest::async_http_client)
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"ok": false, "detail": format!("OIDC discovery failed: {}", e)})),
                )
            })?;
    let base = public_base_url().trim_end_matches('/').to_string();
    let redirect_full = format!("{}{}", base, redirect_path);
    let redirect_url = RedirectUrl::new(redirect_full).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": "invalid redirect URL"})),
        )
    })?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(client_id),
        client_secret.map(ClientSecret::new),
    )
    .set_redirect_uri(redirect_url);
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let nonce = Nonce::new_random();
    let nonce_secret = nonce.secret().clone();
    let exp = chrono::Utc::now().timestamp() + 600;
    let state_full = OidcStateFull {
        idp_id,
        tenant_id,
        nonce: nonce_secret.clone(),
        exp,
        pkce_verifier: pkce_verifier.secret().clone(),
    };
    let state_jwt = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &state_full,
        &jsonwebtoken::EncodingKey::from_secret(crate::auth_jwt::jwt_secret()),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": "state jwt encode"})),
        )
    })?;
    let state_jwt_for_csrf = state_jwt.clone();
    let nonce_secret_for_closure = nonce_secret.clone();
    let (auth_url, _csrf, _) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            move || CsrfToken::new(state_jwt_for_csrf.clone()),
            move || Nonce::new(nonce_secret_for_closure.clone()),
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();
    Ok(Redirect::temporary(auth_url.as_str()))
}

/// GET /api/auth/oidc/callback
pub async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<OidcCallbackQuery>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let mut validation = jsonwebtoken::Validation::default();
    validation.validate_exp = true;
    let state_data = jsonwebtoken::decode::<OidcStateFull>(
        &q.state,
        &jsonwebtoken::DecodingKey::from_secret(crate::auth_jwt::jwt_secret()),
        &validation,
    )
    .map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "invalid state"})),
        )
    })?
    .claims;
    if state_data.exp < chrono::Utc::now().timestamp() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "state expired"})),
        ));
    }
    let auth = state.auth_pool.as_ref();
    let row = sqlx::query_as::<_, IdpCbRow>(
        r#"SELECT i.issuer_url, i.client_id, i.client_secret, i.redirect_path
           FROM tenant_idps i WHERE i.id = $1 AND i.tenant_id = $2 AND i.provider = 'oidc'"#,
    )
    .bind(state_data.idp_id)
    .bind(state_data.tenant_id)
    .fetch_optional(auth)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": format!("{}", e)})),
        )
    })?;
    let Some(IdpCbRow {
        issuer_url: issuer,
        client_id,
        client_secret,
        redirect_path,
    }) = row
    else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "IdP configuration gone"})),
        ));
    };
    let issuer_url = IssuerUrl::new(issuer).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": "issuer"})),
        )
    })?;
    let metadata =
        CoreProviderMetadata::discover_async(issuer_url, &oauth2::reqwest::async_http_client)
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"ok": false, "detail": format!("{}", e)})),
                )
            })?;
    let base = public_base_url().trim_end_matches('/').to_string();
    let redirect_full = format!("{}{}", base, redirect_path);
    let redirect_url = RedirectUrl::new(redirect_full).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": "redirect"})),
        )
    })?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(client_id),
        client_secret.map(ClientSecret::new),
    )
    .set_redirect_uri(redirect_url);
    let token_res = client
        .exchange_code(AuthorizationCode::new(q.code.clone()))
        .set_pkce_verifier(oauth2::PkceCodeVerifier::new(state_data.pkce_verifier))
        .request_async(&oauth2::reqwest::async_http_client)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"ok": false, "detail": format!("token: {}", e)})),
            )
        })?;
    let nonce = Nonce::new(state_data.nonce.clone());
    let id_token_verifier = client.id_token_verifier();
    let id_token_claims = token_res
        .extra_fields()
        .id_token()
        .ok_or_else(|| {
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"ok": false, "detail": "no id_token"})),
            )
        })?
        .claims(&id_token_verifier, &nonce)
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"ok": false, "detail": format!("id_token: {}", e)})),
            )
        })?;
    let email = match id_token_claims.email() {
        Some(e) if !e.is_empty() => e.to_string(),
        _ => id_token_claims
            .preferred_username()
            .map(|s| s.to_string())
            .filter(|s| s.contains('@'))
            .unwrap_or_default(),
    };
    if email.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(
                json!({"ok": false, "detail": "email or preferred_username (email-shaped) required in id_token"}),
            ),
        ));
    }
    weissman_db::auth_access::record_auth_access(auth, state_data.tenant_id, "oidc_callback")
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": format!("auth audit: {}", e)})),
            )
        })?;
    let user_id: i64 = if let Some(uid) = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM auth.v_user_lookup WHERE tenant_id = $1 AND lower(trim(email)) = lower(trim($2)) AND is_active = true",
    )
    .bind(state_data.tenant_id)
    .bind(&email)
    .fetch_optional(auth)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": format!("{}", e)})),
        )
    })? {
        uid
    } else {
        weissman_db::auth_access::insert_user_auth(auth, state_data.tenant_id, &email, None, "viewer")
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"ok": false, "detail": format!("provision: {}", e)})),
                )
            })?
    };
    let ip = crate::http::extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, state_data.tenant_id).await {
        let _ = audit_log::insert_audit(
            &mut tx,
            state_data.tenant_id,
            Some(user_id),
            email.as_str(),
            "login",
            "OIDC session created",
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }
    let (_access_jwt, access_line, refresh_line) =
        crate::auth_refresh::build_session_cookie_headers(auth, user_id, state_data.tenant_id)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"ok": false, "detail": format!("session: {}", e)})),
                )
            })?;
    let mut res = Redirect::to("/command-center/").into_response();
    if let Ok(v) = HeaderValue::from_str(&access_line) {
        res.headers_mut().append(SET_COOKIE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&refresh_line) {
        res.headers_mut().append(SET_COOKIE, v);
    }
    Ok(res)
}
