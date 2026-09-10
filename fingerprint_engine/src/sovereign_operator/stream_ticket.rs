//! One-time SSE tickets for the Sovereign Operator theater stream.
//!
//! Browsers cannot attach `Authorization` on native EventSource. A ticket in the URL is a
//! UUID, not a JWT: 5s TTL, bound to tenant+user, destroyed on handshake so access logs
//! cannot replay a session token.

use dashmap::DashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const TTL: Duration = Duration::from_secs(5);

struct Ticket {
    tenant_id: i64,
    user_id: i64,
    expires_at: Instant,
}

fn store() -> &'static DashMap<Uuid, Ticket> {
    static STORE: OnceLock<DashMap<Uuid, Ticket>> = OnceLock::new();
    STORE.get_or_init(DashMap::new)
}

fn sweep(now: Instant) {
    store().retain(|_, t| t.expires_at > now);
}

pub fn issue(tenant_id: i64, user_id: i64) -> Uuid {
    issue_with_ttl(tenant_id, user_id, TTL)
}

pub fn issue_with_ttl(tenant_id: i64, user_id: i64, ttl: Duration) -> Uuid {
    let now = Instant::now();
    sweep(now);
    let id = Uuid::new_v4();
    store().insert(
        id,
        Ticket {
            tenant_id,
            user_id,
            expires_at: now + ttl,
        },
    );
    id
}

/// Consume-once. Wrong tenant/user or expiry burns the ticket (fail closed).
pub fn consume(id: Uuid, tenant_id: i64, user_id: i64) -> bool {
    let now = Instant::now();
    sweep(now);
    match store().remove(&id) {
        Some((_, t)) if t.tenant_id == tenant_id && t.user_id == user_id && t.expires_at > now => {
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_once_then_reject() {
        let id = issue(7, 9);
        assert!(consume(id, 7, 9));
        assert!(!consume(id, 7, 9));
    }

    #[test]
    fn wrong_principal_burns_ticket() {
        let id = issue(1, 2);
        assert!(!consume(id, 1, 99));
        assert!(!consume(id, 1, 2));
    }

    #[test]
    fn expired_ticket_rejected() {
        let id = issue_with_ttl(3, 4, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(!consume(id, 3, 4));
    }
}
