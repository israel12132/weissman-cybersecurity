//! Stateful session tracking for BOLA / GraphQL to suppress false positives
//! caused by temporary auth/permission churn (token refresh, 401 then 200).

use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionHealth {
    Stable,
    Churn,
    Unauthenticated,
}

#[derive(Debug, Clone)]
pub struct ProbeStatus {
    pub authenticated: bool,
    pub http_status: u16,
    pub at: Instant,
}

/// If the authenticated probe itself received 401/403, the session expired —
/// do not emit a BOLA/authz finding from that round.
pub fn classify(auth_status: u16, unauth_status: u16) -> SessionHealth {
    if matches!(auth_status, 401 | 403) {
        return SessionHealth::Churn;
    }
    if matches!(unauth_status, 401 | 403) && (200..300).contains(&auth_status) {
        return SessionHealth::Stable;
    }
    if (200..300).contains(&auth_status) && (200..300).contains(&unauth_status) {
        return SessionHealth::Unauthenticated;
    }
    SessionHealth::Stable
}

pub fn should_emit_authz_finding(auth_status: u16, unauth_status: u16) -> bool {
    classify(auth_status, unauth_status) != SessionHealth::Churn
}

pub fn statuses_are_fresh(a: Instant, b: Instant, max_skew: Duration) -> bool {
    a.saturating_duration_since(b) <= max_skew && b.saturating_duration_since(a) <= max_skew
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_session_is_churn() {
        assert_eq!(classify(401, 200), SessionHealth::Churn);
        assert!(!should_emit_authz_finding(403, 200));
    }

    #[test]
    fn true_broken_auth_is_unauthenticated() {
        assert_eq!(classify(200, 200), SessionHealth::Unauthenticated);
        assert!(should_emit_authz_finding(200, 200));
    }

    #[test]
    fn healthy_boundary() {
        assert_eq!(classify(200, 401), SessionHealth::Stable);
    }
}
