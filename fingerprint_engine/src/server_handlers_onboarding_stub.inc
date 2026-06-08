// Onboarding + billing endpoint stubs.
//
// These endpoints are reserved for the self-serve signup + Paddle/Stripe flow. Until those
// integrations ship, the stubs return `501 Not Implemented` with a structured body explaining
// what's available today (admin-driven enrollment, contact sales) instead of 404 — so the
// frontend can show "Coming soon" instead of crashing.

async fn api_onboarding_register_stub() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "ok": false,
            "code": "self_serve_signup_not_yet_available",
            "detail": "Self-serve signup is not enabled on this deployment. Contact sales (sales@weissman.io) or have an admin invite you via /admin/users.",
            "available_paths": [
                "POST /api/admin/users          (admin invites users)",
                "POST /api/clients              (create client + scope)",
                "POST /api/agents/enrollment-tokens (issue agent token)"
            ]
        })),
    )
        .into_response()
}

async fn api_onboarding_target_stub() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "ok": false,
            "code": "onboarding_target_not_yet_available",
            "detail": "Use POST /api/clients with `domains` and `ip_ranges` to register a scan target. This stub returns 501 so the client can show 'Coming soon' instead of 404."
        })),
    )
        .into_response()
}

async fn api_onboarding_launch_scan_stub() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "ok": false,
            "code": "onboarding_launch_scan_not_yet_available",
            "detail": "Use POST /api/command-center/scan with engine + client_id + target after creating a client. This stub returns 501 so the UI can degrade gracefully."
        })),
    )
        .into_response()
}

async fn api_billing_usage_stub(Extension(auth): Extension<AuthContext>) -> Response {
    // Return whatever quota state we can compute from system_configs + jobs, so a fresh
    // dashboard isn't blank. Real billing aggregation lives in src/billing/.
    let _ = auth;
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "plan": "self_hosted",
            "billing_active": false,
            "detail": "This deployment is in self-hosted mode. Add WEISSMAN_BILLING_PROVIDER=paddle and the Paddle keys to enable usage billing.",
            "ai_daily_scan_quota_default": crate::scan_routing::DEFAULT_AI_DAILY_SCAN_QUOTA,
        })),
    )
        .into_response()
}

async fn api_billing_checkout_session_stub() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "ok": false,
            "code": "billing_provider_not_configured",
            "detail": "No billing provider is configured. Set WEISSMAN_BILLING_PROVIDER=paddle and PADDLE_API_KEY to enable checkout."
        })),
    )
        .into_response()
}

async fn api_billing_sync_paddle_stub() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "ok": false,
            "code": "billing_provider_not_configured",
            "detail": "Paddle integration is not enabled on this deployment."
        })),
    )
        .into_response()
}

async fn api_paddle_webhook_stub() -> Response {
    // Webhooks must return 200 quickly even when ignored, or Paddle will retry forever.
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "ignored": true,
            "detail": "Paddle webhook stub: integration not enabled on this deployment."
        })),
    )
        .into_response()
}
