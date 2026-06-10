// Onboarding endpoint stubs (target + launch-scan only).
//
// Billing + self-serve register live in server_handlers_onboarding_billing.inc.
// These stubs return `501 Not Implemented` with a structured body so the frontend
// can show "Coming soon" instead of 404.

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
