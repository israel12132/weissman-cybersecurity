fn append_set_cookie(headers: &mut HeaderMap, line: &str) {
    match HeaderValue::from_str(line) {
        Ok(v) => {
            headers.append(axum::http::header::SET_COOKIE, v);
        }
        Err(e) => {
            tracing::warn!(
                target: "auth",
                error = %e,
                "Set-Cookie value rejected by HTTP parser"
            );
        }
    }
}

async fn api_logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let mut revoke_failed = false;
    if let Some(access_raw) = extract_access_cookie(&headers) {
        if let Some((jti, exp)) = crate::auth_jwt::access_token_revocation_info(&access_raw) {
            let expires_at = chrono::DateTime::<chrono::Utc>::from_timestamp(exp, 0)
                .unwrap_or_else(chrono::Utc::now);
            if let Err(e) = crate::auth_refresh::revoke_access_jti(
                state.auth_pool.as_ref(),
                &jti,
                expires_at,
            )
            .await
            {
                tracing::warn!(target: "auth", error = %e, "access jti revocation failed on logout");
                revoke_failed = true;
            }
            // The refresh cookie is scoped Path=/api/auth and is never attached to /api/logout, so
            // the branch below cannot fire for a browser and the opaque refresh token would survive
            // logout for its full TTL. Revoke it via the access_jti linkage kept at issuance.
            if let Err(e) = sqlx::query(
                "UPDATE user_refresh_tokens SET revoked_at = now() WHERE access_jti = $1 AND revoked_at IS NULL",
            )
            .bind(&jti)
            .execute(state.auth_pool.as_ref())
            .await
            {
                tracing::warn!(target: "auth", error = %e, "refresh revoke-by-access-jti failed on logout");
                revoke_failed = true;
            }
        }
    }
    if let Some(refresh_raw) = extract_refresh_cookie(&headers) {
        if let Err(e) = crate::auth_refresh::revoke_refresh_token_by_raw(
            state.auth_pool.as_ref(),
            &refresh_raw,
        )
        .await
        {
            tracing::warn!(target: "auth", error = %e, "refresh token revocation failed on logout");
            revoke_failed = true;
        }
    }
    let mut res = if revoke_failed {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::http_unavailable::auth_degraded_unavailable_json(
                "session revocation unavailable",
            )),
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            Json(json!({"ok": true, "detail": "session cleared"})),
        )
            .into_response()
    };
    append_set_cookie(res.headers_mut(), &crate::auth_jwt::session_cookie_clear_value());
    append_set_cookie(
        res.headers_mut(),
        &crate::auth_refresh::refresh_cookie_clear_value(),
    );
    res
}

async fn api_auth_refresh(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let raw = extract_refresh_cookie(&headers);
    let Some(raw) = raw else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "detail": "missing refresh token"})),
        )
            .into_response();
    };
    match crate::auth_refresh::rotate_refresh_token(state.auth_pool.as_ref(), &raw).await {
        Ok((user_id, tenant_id, new_refresh)) => {
            let (role, is_superadmin, assigned_client_id) =
                match crate::auth_refresh::user_rbac_snapshot(state.auth_pool.as_ref(), user_id).await
                {
                    Ok(Some(p)) => p,
                    Ok(None) => {
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({"ok": false, "detail": "account inactive or not found"})),
                        )
                            .into_response();
                    }
                    Err(e) => {
                        tracing::error!(target: "auth", error = %e, "rbac snapshot failed on refresh");
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(crate::http_unavailable::auth_degraded_unavailable_json(
                                "rbac lookup unavailable",
                            )),
                        )
                            .into_response();
                    }
                };
            let binding = crate::auth_jwt::StreamBinding::from_http(&headers, addr);
            let minted = match crate::auth_jwt::create_access_token(
                user_id,
                tenant_id,
                role.as_str(),
                is_superadmin,
                &binding,
                assigned_client_id,
            ) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(target: "auth", error = %e, "access token mint failed on refresh");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"ok": false, "detail": "token mint failed"})),
                    )
                        .into_response();
                }
            };
            if let Err(e) = crate::auth_refresh::store_refresh_access_jti(
                state.auth_pool.as_ref(),
                &new_refresh,
                &minted.jti,
            )
            .await
            {
                tracing::error!(target: "auth", error = %e, "failed to link refresh row to access jti");
                let mut res = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(crate::http_unavailable::auth_degraded_unavailable_json(
                        "session link unavailable",
                    )),
                )
                    .into_response();
                append_set_cookie(
                    res.headers_mut(),
                    &crate::auth_refresh::refresh_cookie_value(&new_refresh),
                );
                return res;
            }
            let mut res = (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "role": role,
                    "is_superadmin": is_superadmin,
                    "assigned_client_id": assigned_client_id,
                    "access_token": minted.token,
                })),
            )
                .into_response();
            append_set_cookie(
                res.headers_mut(),
                &crate::auth_jwt::session_cookie_value(&minted.token),
            );
            append_set_cookie(
                res.headers_mut(),
                &crate::auth_refresh::refresh_cookie_value(&new_refresh),
            );
            res
        }
        Err(crate::auth_refresh::RefreshTokenError::InvalidOrRevoked) => {
            tracing::warn!(target: "auth", "refresh rejected: invalid or revoked");
            let mut res = (
                StatusCode::UNAUTHORIZED,
                Json(json!({"ok": false, "detail": "invalid refresh token"})),
            )
                .into_response();
            append_set_cookie(res.headers_mut(), &crate::auth_refresh::refresh_cookie_clear_value());
            res
        }
        Err(crate::auth_refresh::RefreshTokenError::Db(e)) => {
            tracing::error!(target: "auth", error = %e, "refresh rotation database error");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(crate::http_unavailable::auth_degraded_unavailable_json(
                    "database unavailable",
                )),
            )
                .into_response()
        }
    }
}

async fn api_auth_me(Extension(auth): Extension<AuthContext>) -> Response {
    let mut body = json!({
        "ok": true,
        "user_id": auth.user_id,
        "tenant_id": auth.tenant_id,
        "role": auth.role,
        "is_superadmin": auth.is_superadmin,
        "is_ceo": crate::http::ceo_rbac::auth_is_ceo(&auth),
        "assigned_client_id": auth.assigned_client_id,
    });
    if let (Some(obj), Some(caps)) = (
        body.as_object_mut(),
        crate::client_isolation::capabilities_json(&auth).as_object(),
    ) {
        for (k, v) in caps {
            obj.insert(k.clone(), v.clone());
        }
    }
    (StatusCode::OK, Json(body)).into_response()
}

/// GET /api/auth/sessions -- the caller's own active refresh sessions
/// (created_at, last_used_at, expires_at, origin ip when captured at mint).
async fn api_auth_sessions_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let sessions = match crate::auth_refresh::list_active_sessions_for_user(
        state.auth_pool.as_ref(),
        auth.user_id,
        auth.tenant_id,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(target: "auth", error = %e, "session list query failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(crate::http_unavailable::auth_degraded_unavailable_json(
                    "session store unavailable",
                )),
            )
                .into_response();
        }
    };
    let items: Vec<Value> = sessions
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "created_at": s.created_at.to_rfc3339(),
                "last_used_at": s.last_used_at.map(|d| d.to_rfc3339()),
                "expires_at": s.expires_at.to_rfc3339(),
                "ip": s.ip,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "count": items.len(), "sessions": items })),
    )
        .into_response()
}

/// POST /api/auth/sessions/revoke-all -- "sign out everywhere" for the current user.
/// Revokes every active refresh token and the access JWTs bound to them, audits the
/// action, and clears the caller's own cookies.
async fn api_auth_sessions_revoke_all(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let revoked = match crate::auth_refresh::revoke_all_sessions_for_user(
        state.auth_pool.as_ref(),
        auth.user_id,
    )
    .await
    {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(target: "auth", error = %e, "revoke-all sessions failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(crate::http_unavailable::auth_degraded_unavailable_json(
                    "session revocation unavailable",
                )),
            )
                .into_response();
        }
    };
    // Best-effort audit on the app pool (audit_logs is tenant-scoped + FORCE RLS).
    let ip = extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let _ = audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &format!("user:{}", auth.user_id),
            "session_revoke_all",
            &format!("revoked {revoked} active session(s) (sign out everywhere)"),
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }
    let mut res = (
        StatusCode::OK,
        Json(json!({ "ok": true, "revoked": revoked })),
    )
        .into_response();
    append_set_cookie(
        res.headers_mut(),
        &crate::auth_jwt::session_cookie_clear_value(),
    );
    append_set_cookie(
        res.headers_mut(),
        &crate::auth_refresh::refresh_cookie_clear_value(),
    );
    res
}

fn extract_access_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_h = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    let prefix = format!("{}=", crate::auth_jwt::WEISSMAN_COOKIE_NAME);
    for part in cookie_h.split(';') {
        let part = part.trim();
        if part.starts_with(&prefix) {
            let v = part[prefix.len()..].trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn extract_refresh_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_h = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    let prefix = format!("{}=", crate::auth_refresh::REFRESH_COOKIE_NAME);
    for part in cookie_h.split(';') {
        let part = part.trim();
        if part.starts_with(&prefix) {
            let v = part[prefix.len()..].trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}
