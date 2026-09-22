//! GDPR data-subject-rights (DSR) helpers: pure, side-effect-free building blocks
//! shared by the `/api/gdpr/*` handlers (`server_handlers_gdpr.inc`).
//!
//! Kept in a standalone module (not the `include!` fragment) so the anonymization
//! and validation logic stays unit-testable without an HTTP/DB harness.

/// Deterministic, PII-free tombstone email for an anonymized `users` row.
///
/// Right-to-erasure anonymizes the `users` row **in place** rather than deleting
/// it, so foreign keys (`audit_logs.actor_user_id`, `client_messages.sender_user_id`)
/// and the tamper-evident audit hash chain stay intact. The tombstone must satisfy
/// the `UNIQUE (tenant_id, email)` invariant, so it embeds the user id (unique
/// within the tenant) and uses the reserved, non-routable `.invalid` TLD (RFC 6761).
#[must_use]
pub fn tombstone_email(user_id: i64) -> String {
    format!("erased-user-{user_id}@erased.invalid")
}

/// Lightweight structural check for a data-subject email. Not RFC 5322-complete —
/// just enough to reject obviously-malformed input before it reaches SQL (rejects
/// whitespace / empty / oversized / dotless-domain forms). The database
/// `lower(email) = lower($1)` comparison remains authoritative for matching.
#[must_use]
pub fn looks_like_email(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 320 || s.chars().any(char::is_whitespace) {
        return false;
    }
    let mut parts = s.split('@');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(local), Some(domain), None) => {
            !local.is_empty()
                && domain.len() >= 3
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tombstone_is_unique_per_user_and_non_routable() {
        assert_eq!(tombstone_email(42), "erased-user-42@erased.invalid");
        assert_ne!(tombstone_email(1), tombstone_email(2));
        assert!(tombstone_email(7).ends_with("@erased.invalid"));
    }

    #[test]
    fn accepts_plain_addresses() {
        assert!(looks_like_email("alice@example.com"));
        assert!(looks_like_email("  Bob.Jones@sub.example.co.uk  "));
    }

    #[test]
    fn rejects_malformed_addresses() {
        assert!(!looks_like_email(""));
        assert!(!looks_like_email("   "));
        assert!(!looks_like_email("no-at-sign"));
        assert!(!looks_like_email("two@@example.com"));
        assert!(!looks_like_email("a@b")); // domain has no dot
        assert!(!looks_like_email("a@.com")); // domain starts with dot
        assert!(!looks_like_email("a@example.")); // domain ends with dot
        assert!(!looks_like_email("has space@example.com"));
        assert!(!looks_like_email("@example.com")); // empty local
    }
}
