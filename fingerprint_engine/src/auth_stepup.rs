//! Step-up (fresh re-auth) gate for privileged operations.
//!
//! A valid session proves *who* you are; a step-up assertion proves you re-authenticated
//! *recently*. Privileged handlers (owner/CEO role grants today; tenant/client deletion,
//! GDPR erase, API-key creation and break-glass when those endpoints exist) call
//! [`require_step_up`] in addition to their normal RBAC gate. The client obtains a step-up
//! token from `POST /api/auth/step-up` (fresh TOTP) and presents it in the
//! `X-Weissman-StepUp` header. The token is a stateless, short-lived (default 5 min) signed
//! JWT — see [`crate::auth_jwt::create_step_up_token`] / [`crate::auth_jwt::verify_step_up_token`].

use crate::auth_jwt::{self, AuthContext};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// HTTP header carrying the step-up assertion token minted by `POST /api/auth/step-up`.
pub const STEP_UP_HEADER: &str = "X-Weissman-StepUp";

/// Gate a privileged operation on a FRESH step-up assertion.
///
/// Returns `Ok(())` only when `headers` carry a valid, unexpired step-up token whose subject
/// and tenant match the live session `auth`. Otherwise returns `Err(Response)` (403 with a JSON
/// `error_code: "step_up_required"`) so callers can short-circuit:
/// `if let Err(r) = require_step_up(&headers, &auth) { return r; }`.
pub fn require_step_up(headers: &HeaderMap, auth: &AuthContext) -> Result<(), Response> {
    // Enforcement is OFF by default so shipping this gate does not break the owner/CEO grant
    // flow before the Command Center learns to obtain a step-up token (POST /api/auth/step-up)
    // and send X-Weissman-StepUp. Set WEISSMAN_REQUIRE_STEPUP=1 to fail-close once the UI is wired.
    if !matches!(
        std::env::var("WEISSMAN_REQUIRE_STEPUP").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    ) {
        return Ok(());
    }
    require_step_up_enforced(headers, auth)
}

/// The actual step-up verification, independent of the `WEISSMAN_REQUIRE_STEPUP` master switch.
/// [`require_step_up`] is the env-gated wrapper that callers use; this is what runs once
/// enforcement is enabled, and what the unit tests exercise directly (so they test the real
/// verification logic rather than the default-off switch).
pub(crate) fn require_step_up_enforced(
    headers: &HeaderMap,
    auth: &AuthContext,
) -> Result<(), Response> {
    let Some(token) = headers
        .get(STEP_UP_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err(step_up_required(
            auth,
            "step-up required: obtain a token from POST /api/auth/step-up and send it in the X-Weissman-StepUp header",
        ));
    };
    match auth_jwt::verify_step_up_token(token) {
        Some((uid, tid)) if uid == auth.user_id && tid == auth.tenant_id => Ok(()),
        Some((uid, tid)) => {
            tracing::warn!(
                target: "auth_stepup",
                session_user = auth.user_id,
                session_tenant = auth.tenant_id,
                token_user = uid,
                token_tenant = tid,
                "step-up token subject/tenant does not match session"
            );
            Err(step_up_required(
                auth,
                "step-up token does not match the current session",
            ))
        }
        None => Err(step_up_required(
            auth,
            "step-up token is missing, invalid, or expired",
        )),
    }
}

fn step_up_required(auth: &AuthContext, detail: &str) -> Response {
    tracing::warn!(
        target: "auth_stepup",
        user_id = auth.user_id,
        tenant_id = auth.tenant_id,
        role = %auth.role,
        denial_reason = %detail,
        "step-up gate denial"
    );
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "ok": false,
            "detail": detail,
            "error_code": "step_up_required",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> AuthContext {
        AuthContext {
            user_id: 7,
            tenant_id: 3,
            role: "admin".to_string(),
            is_superadmin: false,
            agent_id: None,
            jti: Some("j".to_string()),
            bind_ip: None,
            bind_tls_fp: None,
            assigned_client_id: None,
        }
    }

    #[test]
    fn missing_header_is_rejected() {
        let headers = HeaderMap::new();
        assert!(require_step_up_enforced(&headers, &ctx()).is_err());
    }

    #[test]
    fn blank_or_garbage_header_is_rejected() {
        // No JWT secret needed: verify_step_up_token returns None for an unverifiable token,
        // and a whitespace-only header is filtered out before verification.
        let mut headers = HeaderMap::new();
        headers.insert(STEP_UP_HEADER, "   ".parse().unwrap());
        assert!(require_step_up_enforced(&headers, &ctx()).is_err());
        let mut headers = HeaderMap::new();
        headers.insert(STEP_UP_HEADER, "not-a-jwt".parse().unwrap());
        assert!(require_step_up_enforced(&headers, &ctx()).is_err());
    }
}
