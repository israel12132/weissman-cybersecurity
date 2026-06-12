// Onboarding + billing HTTP handlers (Paddle Billing + B2B self-serve register).

#[derive(Debug, Deserialize)]
struct OnboardingRegisterBody {
    organization_name: String,
    tenant_slug: String,
    email: String,
    password: String,
    #[serde(default = "onboarding_default_plan_slug")]
    plan_slug: String,
}

fn onboarding_default_plan_slug() -> String {
    "starter".to_string()
}

#[derive(Debug, Deserialize)]
struct BillingCheckoutBody {
    plan_slug: String,
}

fn paddle_api_configured() -> bool {
    std::env::var("PADDLE_API_KEY")
        .map(|k| !k.trim().is_empty())
        .unwrap_or(false)
}

fn paddle_webhook_secret_configured() -> bool {
    std::env::var("PADDLE_WEBHOOK_SECRET")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

fn billing_unavailable(detail: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "ok": false,
            "code": "billing_provider_not_configured",
            "detail": detail,
            "hint": "Set PADDLE_API_KEY, PADDLE_WEBHOOK_SECRET, and WEISSMAN_PADDLE_PRICE_* (or billing_plans.paddle_price_id)."
        })),
    )
        .into_response()
}

fn paddle_webhook_error_response(err: crate::billing::PaddleWebhookError) -> Response {
    use crate::billing::PaddleWebhookError;
    match err {
        PaddleWebhookError::SecretMissing | PaddleWebhookError::SecretInvalid => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "ok": false, "detail": err.to_string() })),
        )
            .into_response(),
        PaddleWebhookError::Signature(msg) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "detail": msg })),
        )
            .into_response(),
        PaddleWebhookError::Json(msg) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": msg })),
        )
            .into_response(),
        PaddleWebhookError::MissingEventId => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": err.to_string() })),
        )
            .into_response(),
        PaddleWebhookError::Apply(msg) => {
            tracing::warn!(target: "paddle_webhook", error = %msg, "webhook apply failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "detail": msg })),
            )
                .into_response()
        }
        PaddleWebhookError::Sql(e) => {
            tracing::warn!(target: "paddle_webhook", error = %e, "webhook db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "detail": "database error processing webhook" })),
            )
                .into_response()
        }
    }
}

/// `GET /api/billing/usage` — subscription status + tenant usage counters.
async fn api_billing_usage(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    match crate::billing::usage_dashboard_json(state.auth_pool.as_ref(), auth.tenant_id).await {
        Ok(mut body) => {
            if let Some(obj) = body.as_object_mut() {
                obj.insert("ok".to_string(), json!(true));
            } else {
                body = json!({ "ok": true, "data": body });
            }
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

/// `POST /api/billing/checkout-session` — Paddle Checkout URL for plan upgrade.
async fn api_billing_checkout_session(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<BillingCheckoutBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    if !paddle_api_configured() {
        return billing_unavailable(
            "Paddle Billing is not configured on this deployment. Set PADDLE_API_KEY to enable checkout.",
        );
    }
    let plan = body.plan_slug.trim();
    if plan.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "code": "invalid_plan",
                "detail": "plan_slug required"
            })),
        )
            .into_response();
    }
    match crate::billing::create_checkout_session_url(
        state.auth_pool.as_ref(),
        auth.tenant_id,
        auth.user_id,
        plan,
    )
    .await
    {
        Ok(url) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "checkout_url": url })),
        )
            .into_response(),
        Err(e) if e.contains("PADDLE_API_KEY not configured") => billing_unavailable(&e),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

/// `POST /api/billing/sync-paddle` — refresh tenant subscription from Paddle Billing API.
async fn api_billing_sync_paddle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = crate::rbac::require_admin(&auth) {
        return r;
    }
    if !paddle_api_configured() {
        return billing_unavailable(
            "Paddle Billing is not configured on this deployment. Set PADDLE_API_KEY to sync subscriptions.",
        );
    }
    match crate::billing::refresh_subscription_from_paddle_api(state.auth_pool.as_ref(), auth.tenant_id)
        .await
    {
        Ok(msg) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "detail": msg })),
        )
            .into_response(),
        Err(e) if e.contains("PADDLE_API_KEY not configured") => billing_unavailable(&e),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "detail": e })),
        )
            .into_response(),
    }
}

/// `POST /api/webhooks/paddle` — Paddle Billing signed webhook (no JWT).
async fn api_paddle_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !paddle_webhook_secret_configured() {
        tracing::warn!(
            target: "paddle_webhook",
            "PADDLE_WEBHOOK_SECRET not configured — rejecting webhook delivery to avoid silently missing billing events in production"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "code": "webhook_secret_not_configured",
                "detail": "Paddle webhook secret not configured. Set PADDLE_WEBHOOK_SECRET to enable webhook processing."
            })),
        )
            .into_response();
    }
    let sig = headers
        .get("Paddle-Signature")
        .or_else(|| headers.get("paddle-signature"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if sig.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "detail": "Missing Paddle-Signature header"
            })),
        )
            .into_response();
    }
    match crate::billing::handle_paddle_webhook(state.auth_pool.as_ref(), sig, &body).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(e) => paddle_webhook_error_response(e),
    }
}

/// `POST /api/onboarding/register` — B2B self-serve tenant + admin provisioning.
async fn api_onboarding_register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<OnboardingRegisterBody>,
) -> Response {
    if !crate::signup::self_serve_enabled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "code": "self_serve_disabled",
                "detail": "Self-serve signup is not enabled on this deployment. Set WEISSMAN_SELF_SERVE_SIGNUP=true or contact sales@weissman.io.",
                "available_paths": [
                    "POST /api/admin/users          (admin invites users)",
                    "POST /api/clients              (create client + scope)",
                    "POST /api/agents/enrollment-tokens (issue agent token)"
                ]
            })),
        )
            .into_response();
    }

    let slug = match crate::billing::normalize_tenant_slug(&body.tenant_slug) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "code": "validation_failed", "detail": e })),
            )
                .into_response();
        }
    };

    match crate::billing::register_tenant_and_admin(
        state.auth_pool.as_ref(),
        &body.organization_name,
        &slug,
        &body.email,
        &body.password,
        body.plan_slug.trim(),
    )
    .await
    {
        Ok((tenant_id, user_id)) => {
            let ip = extract_client_ip(&headers, addr);
            if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, tenant_id).await {
                let actor = body.email.trim();
                let _ = audit_log::insert_audit(
                    &mut tx,
                    tenant_id,
                    Some(user_id),
                    actor,
                    "onboarding_register",
                    "self-serve tenant provisioned",
                    &ip,
                )
                .await;
                let _ = tx.commit().await;
            }

            let (access_jwt, access_cookie, refresh_cookie) =
                match crate::auth_refresh::build_session_cookie_headers(
                    state.auth_pool.as_ref(),
                    user_id,
                    tenant_id,
                )
                .await
                {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!(target: "onboarding", error = %e, "session cookie build failed");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({
                                "ok": false,
                                "detail": "tenant created but session issuance failed; sign in manually"
                            })),
                        )
                            .into_response();
                    }
                };

            tracing::info!(
                target: "onboarding",
                tenant_id,
                user_id,
                tenant_slug = %slug,
                "self-serve B2B onboarding register"
            );

            let mut response = (
                StatusCode::CREATED,
                Json(json!({
                    "ok": true,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "tenant_slug": slug,
                    "role": "admin",
                    "billing_strict": crate::billing::billing_strict_enabled(),
                    "access_token": access_jwt,
                })),
            )
                .into_response();
            append_set_cookie(response.headers_mut(), &access_cookie);
            append_set_cookie(response.headers_mut(), &refresh_cookie);
            response
        }
        Err(e) => {
            let status = if e.contains("already registered") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            (
                status,
                Json(json!({ "ok": false, "detail": e })),
            )
                .into_response()
        }
    }
}
