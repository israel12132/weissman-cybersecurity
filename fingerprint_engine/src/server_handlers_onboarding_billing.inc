#[derive(Deserialize)]
struct OnboardingRegisterBody {
    organization_name: String,
    tenant_slug: String,
    email: String,
    password: String,
    #[serde(default = "default_onboarding_plan")]
    plan_slug: String,
}

fn default_onboarding_plan() -> String {
    "starter".to_string()
}

#[derive(Deserialize)]
struct OnboardingTargetBody {
    name: String,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    ip_ranges: Vec<String>,
}

#[derive(Deserialize)]
struct BillingCheckoutBody {
    plan_slug: String,
}

async fn api_onboarding_register(
    State(state): State<Arc<AppState>>,
    axum::extract::Json(body): axum::extract::Json<OnboardingRegisterBody>,
) -> Response {
    let slug_norm = match crate::billing::normalize_tenant_slug(&body.tenant_slug) {
        Ok(s) => s,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "detail": e}))).into_response();
        }
    };
    match crate::billing::register_tenant_and_admin(
        state.auth_pool.as_ref(),
        &body.organization_name,
        &slug_norm,
        &body.email,
        &body.password,
        body.plan_slug.trim(),
    )
    .await
    {
        Ok((tid, uid)) => {
            let token = match crate::auth_jwt::create_access_token(uid, tid, "admin", false) {
                Ok(t) => t,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"ok": false, "detail": "token generation failed"})),
                    )
                        .into_response();
                }
            };
            let cookie_value = crate::auth_jwt::session_cookie_value(&token);
            let checkout_required = crate::billing::billing_strict_enabled();
            let mut response = (
                StatusCode::CREATED,
                Json(json!({
                    "ok": true,
                    "tenant_id": tid,
                    "user_id": uid,
                    "tenant_slug": slug_norm,
                    "checkout_required": checkout_required,
                    "role": "admin",
                    "is_superadmin": false,
                    "access_token": token,
                })),
            )
                .into_response();
            if let Ok(hv) = HeaderValue::from_str(&cookie_value) {
                response.headers_mut().insert(axum::http::header::SET_COOKIE, hv);
            }
            response
        }
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": msg})),
        )
            .into_response(),
    }
}

async fn api_onboarding_target(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    axum::extract::Json(body): axum::extract::Json<OnboardingTargetBody>,
) -> Response {
    let name = body.name.trim();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "name required"})),
        )
            .into_response();
    }
    if let Err(detail) =
        crate::billing::enforce_client_create(state.auth_pool.as_ref(), auth.tenant_id).await
    {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({"ok": false, "detail": detail})),
        )
            .into_response();
    }
    let domains_json =
        serde_json::to_string(&body.domains).unwrap_or_else(|_| "[]".to_string());
    let ip_json = serde_json::to_string(&body.ip_ranges).unwrap_or_else(|_| "[]".to_string());
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "database unavailable"})),
        )
            .into_response();
    };
    let id: i64 = match sqlx::query_scalar::<_, i64>(
        "INSERT INTO clients (tenant_id, name, domains, tech_stack, ip_ranges) VALUES ($1, $2, $3, '[]', $4) RETURNING id",
    )
    .bind(auth.tenant_id)
    .bind(name)
    .bind(&domains_json)
    .bind(&ip_json)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(i) => i,
        Err(e) => {
            let _ = tx.rollback().await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": e.to_string()})),
            )
                .into_response();
        }
    };
    let _ = tx.commit().await;
    (
        StatusCode::OK,
        Json(json!({"ok": true, "client_id": id, "message": "target configured"})),
    )
        .into_response()
}

async fn api_onboarding_launch_scan(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    trace_ext: Option<Extension<crate::request_trace::TraceId>>,
) -> Response {
    if let Err(detail) =
        crate::billing::enforce_scan_start(state.auth_pool.as_ref(), auth.tenant_id).await
    {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({"ok": false, "detail": detail})),
        )
            .into_response();
    }
    if let Err(e) = crate::billing::record_scan_started(state.auth_pool.as_ref(), auth.tenant_id).await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": e.to_string()})),
        )
            .into_response();
    }
    let ip = extract_client_ip(&headers, addr);
    if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        let u = audit_log::user_email_for_id(&state.auth_pool, auth.user_id).await;
        let _ = audit_log::insert_audit(
            &mut tx,
            auth.tenant_id,
            Some(auth.user_id),
            &u,
            "scan_initiated",
            "onboarding enterprise scan (single-tenant)",
            &ip,
        )
        .await;
        let _ = tx.commit().await;
    }
    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "onboarding_tenant_scan",
        json!({}),
        trace_ext.map(|Extension(t)| t.0),
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "ok": true,
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "message": "Enterprise scan queued; poll status_url for progress",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "enqueue onboarding_tenant_scan failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn api_billing_usage(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    match crate::billing::usage_dashboard_json(state.auth_pool.as_ref(), auth.tenant_id).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": e})),
        )
            .into_response(),
    }
}

async fn api_billing_sync_paddle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    match crate::billing::refresh_subscription_from_paddle_api(
        state.auth_pool.as_ref(),
        auth.tenant_id,
    )
    .await
    {
        Ok(msg) => (
            StatusCode::OK,
            Json(json!({"ok": true, "detail": msg})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": e})),
        )
            .into_response(),
    }
}

async fn api_billing_checkout_session(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<BillingCheckoutBody>,
) -> Response {
    match crate::billing::create_checkout_session_url(
        state.auth_pool.as_ref(),
        auth.tenant_id,
        auth.user_id,
        body.plan_slug.trim(),
    )
    .await
    {
        Ok(url) => (
            StatusCode::OK,
            Json(json!({"ok": true, "url": url})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": e})),
        )
            .into_response(),
    }
}

async fn api_paddle_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let sig = headers
        .get("paddle-signature")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if sig.is_empty() {
        tracing::warn!(target: "paddle_webhook", "missing Paddle-Signature header");
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"received": false, "detail": "missing signature"})),
        )
            .into_response();
    }
    match crate::billing::handle_paddle_webhook(state.auth_pool.as_ref(), sig, body.as_ref()).await {
        Ok(()) => (StatusCode::OK, Json(json!({"received": true}))).into_response(),
        Err(e) => match e {
            crate::billing::PaddleWebhookError::SecretMissing
            | crate::billing::PaddleWebhookError::SecretInvalid
            | crate::billing::PaddleWebhookError::Signature(_) => {
                tracing::warn!(target: "paddle_webhook", error = %e, "paddle webhook rejected (crypto)");
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"received": false, "detail": "invalid signature"})),
                )
                    .into_response()
            }
            _ => {
                tracing::error!(target: "paddle_webhook", error = %e, "paddle webhook processing failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"received": false, "detail": "processing error"})),
                )
                    .into_response()
            }
        },
    }
}
