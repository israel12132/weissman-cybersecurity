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

async fn api_logout() -> Response {
    let mut res = (
        StatusCode::OK,
        Json(json!({"ok": true, "detail": "session cleared"})),
    )
        .into_response();
    append_set_cookie(res.headers_mut(), &crate::auth_jwt::session_cookie_clear_value());
    append_set_cookie(
        res.headers_mut(),
        &crate::auth_refresh::refresh_cookie_clear_value(),
    );
    res
}

async fn api_auth_refresh(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
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
            let (role, is_superadmin) =
                match crate::auth_refresh::user_rbac_snapshot(state.auth_pool.as_ref(), user_id).await
                {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!(target: "auth", error = %e, "rbac snapshot failed on refresh");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"ok": false, "detail": "rbac lookup failed"})),
                        )
                            .into_response();
                    }
                };
            let access = match crate::auth_jwt::create_access_token(
                user_id,
                tenant_id,
                role.as_str(),
                is_superadmin,
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
            let mut res = (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "role": role,
                    "is_superadmin": is_superadmin,
                    "access_token": access,
                })),
            )
                .into_response();
            append_set_cookie(
                res.headers_mut(),
                &crate::auth_jwt::session_cookie_value(&access),
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
                Json(json!({"ok": false, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

async fn api_auth_me(Extension(auth): Extension<AuthContext>) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "user_id": auth.user_id,
            "tenant_id": auth.tenant_id,
            "role": auth.role,
            "is_superadmin": auth.is_superadmin,
            "is_ceo": crate::http::ceo_rbac::auth_is_ceo(&auth),
        })),
    )
        .into_response()
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
