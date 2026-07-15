#[derive(serde::Deserialize)]
struct MfaVerifyBody {
    mfa_token: String,
    code: String,
}

#[derive(serde::Deserialize)]
struct MfaEnableBody {
    code: String,
}

async fn api_auth_mfa_verify(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::extract::Json<MfaVerifyBody>,
) -> Response {
    let ip = extract_client_ip(&headers, addr);
    let pending = body.mfa_token.trim();
    let code = body.code.trim();
    let Some(ctx) = crate::auth_jwt::verify_mfa_pending_token(pending) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "detail": "Invalid or expired MFA session"})),
        )
            .into_response();
    };
    let row = match sqlx::query(
        r#"SELECT COALESCE(mfa_secret,'') AS mfa_secret, COALESCE(mfa_enabled, false) AS mfa_enabled,
                  COALESCE(NULLIF(trim(email), ''), '') AS email
           FROM users WHERE id = $1 AND tenant_id = $2 AND is_active = true"#,
    )
    .bind(ctx.user_id)
    .bind(ctx.tenant_id)
    .fetch_optional(state.app_pool.as_ref())
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"ok": false, "detail": "User not found"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(target: "auth", error = %e, "MFA verify user lookup failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "ok": false,
                    "detail": "Authentication service temporarily unavailable",
                    "code": "auth_degraded"
                })),
            )
                .into_response();
        }
    };
    let stored_secret: String = row.try_get("mfa_secret").unwrap_or_default();
    let secret: String = crate::auth_mfa::decrypt_secret_at_rest(&stored_secret);
    let enabled: bool = row.try_get("mfa_enabled").unwrap_or(false);
    let email: String = row.try_get("email").unwrap_or_default();
    match crate::http::check_lockout_status(ctx.tenant_id, &email).await {
        crate::http::LockoutStatus::Locked(retry_after) => {
            return crate::http::locked_response(retry_after);
        }
        crate::http::LockoutStatus::DistributedStoreUnavailable => {
            return crate::http::rate_limit_redis::distributed_store_unavailable_response();
        }
        crate::http::LockoutStatus::Allowed => {}
    }
    if !enabled || secret.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "MFA not enabled for this account"})),
        )
            .into_response();
    }
    if !crate::auth_mfa::verify_code(&secret, code) {
        crate::http::record_failure(ctx.tenant_id, &email).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "detail": "Invalid verification code"})),
        )
            .into_response();
    }
    // Lazy at-rest migration: the user just proved possession of the seed, so if
    // it is still stored as legacy plaintext, re-persist it encrypted. Best-effort
    // and self-limiting (skips once the row is already an envelope / when no key).
    if !crate::auth_mfa::is_secret_encrypted(&stored_secret) {
        let reencrypted = crate::auth_mfa::encrypt_secret_at_rest(&secret);
        if crate::auth_mfa::is_secret_encrypted(&reencrypted) {
            let _ = sqlx::query(
                "UPDATE users SET mfa_secret = $1 WHERE id = $2 AND tenant_id = $3",
            )
            .bind(reencrypted)
            .bind(ctx.user_id)
            .bind(ctx.tenant_id)
            .execute(state.app_pool.as_ref())
            .await;
        }
    }
    let mut tx = match db::begin_tenant_tx(&state.app_pool, ctx.tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(target: "auth", error = %e, "MFA verify audit tx failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "ok": false,
                    "detail": "Authentication service temporarily unavailable",
                    "code": "auth_degraded"
                })),
            )
                .into_response();
        }
    };
    let _ = audit_log::insert_audit(
        &mut tx,
        ctx.tenant_id,
        Some(ctx.user_id),
        &email,
        "mfa_verify",
        "TOTP verified",
        &ip,
    )
    .await;
    let _ = tx.commit().await;
    let binding = crate::auth_jwt::StreamBinding::from_http(&headers, addr);
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
                tracing::error!(target: "auth", error = %e, "MFA session cookie build failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"ok": false, "detail": "session issuance failed"})),
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
    crate::http::clear_failures(ctx.tenant_id, &email).await;
    append_set_cookie(response.headers_mut(), &access_cookie);
    append_set_cookie(response.headers_mut(), &refresh_cookie);
    response
}

async fn api_auth_mfa_setup(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let secret = crate::auth_mfa::generate_secret();
    let email_row = sqlx::query_scalar::<_, String>(
        "SELECT email FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(auth.user_id)
    .bind(auth.tenant_id)
    .fetch_optional(state.app_pool.as_ref())
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| format!("user{}", auth.user_id));
    let otpauth = crate::auth_mfa::otpauth_uri(&secret, &email_row).unwrap_or_default();
    // Persist the seed encrypted at rest; the plaintext `secret` is only returned
    // once (below) so the user can enrol it in their authenticator app.
    let _ = sqlx::query(
        "UPDATE users SET mfa_secret = $1, mfa_enabled = false WHERE id = $2 AND tenant_id = $3",
    )
    .bind(crate::auth_mfa::encrypt_secret_at_rest(&secret))
    .bind(auth.user_id)
    .bind(auth.tenant_id)
    .execute(state.app_pool.as_ref())
    .await;
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "secret": secret,
            "otpauth_url": otpauth,
        })),
    )
        .into_response()
}

async fn api_auth_mfa_enable(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    body: axum::extract::Json<MfaEnableBody>,
) -> Response {
    let row = sqlx::query(
        "SELECT COALESCE(mfa_secret,'') AS mfa_secret FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(auth.user_id)
    .bind(auth.tenant_id)
    .fetch_optional(state.app_pool.as_ref())
    .await
    .ok()
    .flatten();
    let secret: String = row
        .and_then(|r| r.try_get::<String, _>("mfa_secret").ok())
        .map(|s| crate::auth_mfa::decrypt_secret_at_rest(&s))
        .unwrap_or_default();
    if secret.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "Call /api/auth/mfa/setup first"})),
        )
            .into_response();
    }
    if !crate::auth_mfa::verify_code(&secret, body.code.trim()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "detail": "Invalid verification code"})),
        )
            .into_response();
    }
    let _ = sqlx::query(
        "UPDATE users SET mfa_enabled = true WHERE id = $1 AND tenant_id = $2",
    )
    .bind(auth.user_id)
    .bind(auth.tenant_id)
    .execute(state.app_pool.as_ref())
    .await;
    (
        StatusCode::OK,
        Json(json!({"ok": true, "mfa_enabled": true})),
    )
        .into_response()
}

#[derive(serde::Deserialize)]
struct MfaDisableBody {
    code: String,
}

async fn api_auth_mfa_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let row = sqlx::query(
        "SELECT COALESCE(mfa_enabled, false) AS mfa_enabled, COALESCE(mfa_secret,'') AS mfa_secret
         FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(auth.user_id)
    .bind(auth.tenant_id)
    .fetch_optional(state.app_pool.as_ref())
    .await
    .ok()
    .flatten();
    let enabled = row
        .as_ref()
        .and_then(|r| r.try_get::<bool, _>("mfa_enabled").ok())
        .unwrap_or(false);
    let provisioned = row
        .as_ref()
        .and_then(|r| r.try_get::<String, _>("mfa_secret").ok())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "mfa_enabled": enabled,
            "mfa_provisioned": provisioned,
        })),
    )
        .into_response()
}

async fn api_auth_mfa_disable(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    body: axum::extract::Json<MfaDisableBody>,
) -> Response {
    let row = sqlx::query(
        "SELECT COALESCE(mfa_secret,'') AS mfa_secret, COALESCE(mfa_enabled,false) AS mfa_enabled
         FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(auth.user_id)
    .bind(auth.tenant_id)
    .fetch_optional(state.app_pool.as_ref())
    .await
    .ok()
    .flatten();
    let secret: String = row
        .as_ref()
        .and_then(|r| r.try_get::<String, _>("mfa_secret").ok())
        .map(|s| crate::auth_mfa::decrypt_secret_at_rest(&s))
        .unwrap_or_default();
    let enabled: bool = row
        .as_ref()
        .and_then(|r| r.try_get("mfa_enabled").ok())
        .unwrap_or(false);
    if !enabled {
        return (
            StatusCode::OK,
            Json(json!({"ok": true, "mfa_enabled": false, "detail": "MFA already disabled"})),
        )
            .into_response();
    }
    if secret.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "No MFA secret on file"})),
        )
            .into_response();
    }
    if !crate::auth_mfa::verify_code(&secret, body.code.trim()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "detail": "Invalid verification code"})),
        )
            .into_response();
    }
    let _ = sqlx::query(
        "UPDATE users SET mfa_enabled = false, mfa_secret = '' WHERE id = $1 AND tenant_id = $2",
    )
    .bind(auth.user_id)
    .bind(auth.tenant_id)
    .execute(state.app_pool.as_ref())
    .await;
    (
        StatusCode::OK,
        Json(json!({"ok": true, "mfa_enabled": false})),
    )
        .into_response()
}
