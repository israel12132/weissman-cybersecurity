async fn api_dashboard_stats(State(state): State<Arc<AppState>>, Extension(auth): Extension<AuthContext>) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"total_vulnerabilities":0,"active_scans":0,"security_score":0,"assets_monitored":0,"threats_mitigated":0}))).into_response();
    };
    let vuln_count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM vulnerabilities")
        .fetch_one(&mut *tx).await.unwrap_or(0);
    let client_count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM clients")
        .fetch_one(&mut *tx).await.unwrap_or(0);
    let score: i64 = sqlx::query_scalar::<_, String>("SELECT summary FROM report_runs ORDER BY created_at DESC LIMIT 1")
        .fetch_optional(&mut *tx).await.ok().flatten()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|j| {
            let by = j.get("by_severity")?.as_object()?;
            let crit = by.get("critical").and_then(Value::as_i64).unwrap_or(0);
            let high = by.get("high").and_then(Value::as_i64).unwrap_or(0);
            let med = by.get("medium").and_then(Value::as_i64).unwrap_or(0);
            Some((100i64 - crit * 25 - high * 15 - med * 5).max(0))
        }).unwrap_or(0);
    let summary_json: Option<Value> = sqlx::query_scalar::<_, String>("SELECT summary FROM report_runs ORDER BY created_at DESC LIMIT 1")
        .fetch_optional(&mut *tx).await.ok().flatten()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok());
    let _ = tx.commit().await;
    let active = crate::orchestrator::is_scanning_active();
    let attack_surface_targets = summary_json.as_ref().and_then(|j| j.get("attack_surface_targets")).and_then(Value::as_u64).unwrap_or(0) as i64;
    let attack_surface_paths = summary_json.as_ref().and_then(|j| j.get("attack_surface_paths")).and_then(Value::as_u64).unwrap_or(0) as i64;
    (StatusCode::OK, Json(json!({
        "total_vulnerabilities": vuln_count,
        "active_scans": if active { 1 } else { 0 },
        "security_score": score,
        "assets_monitored": client_count,
        "threats_mitigated": vuln_count,
        "attack_surface_targets": attack_surface_targets,
        "attack_surface_paths": attack_surface_paths,
    }))).into_response()
}

async fn api_findings(State(state): State<Arc<AppState>>, Extension(auth): Extension<AuthContext>) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(Value::Array(vec![]))).into_response();
    };
    let rows = sqlx::query("SELECT id, finding_id, title, severity, source, status, client_id::text FROM vulnerabilities ORDER BY discovered_at DESC LIMIT 500")
        .fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;
    let mut out = Vec::new();
    for r in rows {
        out.push(json!({
            "id": format!("VLN-{}", r.try_get::<i64,_>("id").unwrap_or(0)),
            "title": r.try_get::<String,_>("title").unwrap_or_else(|_| "Finding".to_string()),
            "source": r.try_get::<String,_>("source").unwrap_or_else(|_| "NVD".to_string()),
            "severity": r.try_get::<String,_>("severity").unwrap_or_else(|_| "MEDIUM".to_string()),
            "status": r.try_get::<String,_>("status").unwrap_or_else(|_| "OPEN".to_string()),
            "client": r.try_get::<String,_>("client_id").unwrap_or_default(),
            "risk_score": 5.0
        }));
    }
    (StatusCode::OK, Json(Value::Array(out))).into_response()
}

async fn api_reports(State(state): State<Arc<AppState>>, Extension(auth): Extension<AuthContext>) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(Value::Array(vec![]))).into_response();
    };
    let rows = sqlx::query("SELECT id, created_at, pdf_path FROM report_runs ORDER BY created_at DESC LIMIT 100")
        .fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;
    let out: Vec<Value> = rows.into_iter().map(|r| json!({
        "id": r.try_get::<i64,_>("id").unwrap_or(0),
        "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").ok().map(|d| d.to_rfc3339()),
        "pdf_path": r.try_get::<Option<String>,_>("pdf_path").ok().flatten(),
    })).collect();
    (StatusCode::OK, Json(Value::Array(out))).into_response()
}

async fn api_login(State(state): State<Arc<AppState>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap, body: axum::extract::Json<LoginBody>) -> Response {
    let ip = extract_client_ip(&headers, addr);
    let email = body.email.trim();
    let password = body.password.as_str();
    let slug = body.tenant_slug.trim();
    let slug = if slug.is_empty() { "default" } else { slug };
    let tenant_key: i64 = match sqlx::query_scalar::<_, i64>(
        "SELECT id FROM tenants WHERE slug = $1 AND active = true LIMIT 1",
    )
    .bind(slug)
    .fetch_optional(state.auth_pool.as_ref())
    .await
    {
        Ok(Some(id)) => id,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"ok": false, "detail": "Invalid email or password"})),
            )
                .into_response();
        }
    };
    if let Err(e) = weissman_db::auth_access::record_auth_access(
        state.auth_pool.as_ref(),
        tenant_key,
        "password_login",
    )
    .await
    {
        tracing::warn!(
            target: "security_audit",
            error = %e,
            "audit_auth_access failed; continuing login attempt"
        );
    }
    let row = sqlx::query(
        r#"SELECT u.id, COALESCE(u.password_hash,'') AS password_hash, u.tenant_id,
                  COALESCE(NULLIF(trim(u.role), ''), 'viewer') AS role,
                  COALESCE(u.is_superadmin, false) AS is_superadmin
           FROM auth.v_user_lookup u
           WHERE u.tenant_id = $1 AND lower(trim(u.email)) = lower(trim($2)) AND u.is_active = true"#,
    )
    .bind(tenant_key)
    .bind(email)
    .fetch_optional(state.auth_pool.as_ref())
    .await
    .ok()
    .flatten();
    let (user_id, hash, tenant_id, role, is_superadmin) = match row {
        Some(r) => (
            r.try_get::<i64, _>("id").unwrap_or(0),
            r.try_get::<String, _>("password_hash").unwrap_or_default(),
            r.try_get::<i64, _>("tenant_id").unwrap_or(0),
            r.try_get::<String, _>("role").unwrap_or_else(|_| "viewer".into()),
            r.try_get::<bool, _>("is_superadmin").unwrap_or(false),
        ),
        None => return (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "detail": "Invalid email or password"}))).into_response(),
    };
    if hash.is_empty() { return (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "detail": "Invalid email or password"}))).into_response(); }
    match bcrypt::verify(password, &hash) {
        Ok(true) => {
            let mut tx = match db::begin_tenant_tx(&state.app_pool, tenant_id).await { Ok(t) => t, Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response() };
            let _ = audit_log::insert_audit(&mut tx, tenant_id, Some(user_id), email, "login", "session created", &ip).await;
            let _ = tx.commit().await;
            let (access_jwt, access_cookie, refresh_cookie) = match crate::auth_refresh::build_session_cookie_headers(state.auth_pool.as_ref(), user_id, tenant_id).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(target: "auth", error = %e, "login session cookie build failed");
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": "session issuance failed"}))).into_response();
                }
            };
            eprintln!("[Weissman][API] Login OK: user_id={} tenant_id={}", user_id, tenant_id);
            let mut response = (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "role": role,
                    "is_superadmin": is_superadmin,
                    "access_token": access_jwt,
                })),
            )
                .into_response();
            append_set_cookie(response.headers_mut(), &access_cookie);
            append_set_cookie(response.headers_mut(), &refresh_cookie);
            response
        }
        _ => (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "detail": "Invalid email or password"}))).into_response(),
    }
}
