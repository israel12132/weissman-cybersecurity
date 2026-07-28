//! Durable cross-replica self-heal gate — fleet-wide coordination of the in-process load-shed /
//! backoff recovery gates ([`crate::self_heal_recovery`]).
//!
//! The recovery engine engages its `shed_load` / `backoff` gates on the *one* replica whose 10s
//! health loop diagnosed the saturation. But a load balancer spreads new scan intake across every
//! replica, so a purely local gate only sheds ~1/N of it. This module lifts those gates to a
//! **fleet** signal backed by a tiny Postgres table (`weissman_self_heal_gate`):
//!
//! - **Publish** (once per health round): a replica whose *local* gate is engaged writes the gate's
//!   remaining TTL to the shared row, upsert-EXTENDing the expiry ([`should_publish`]).
//! - **Refresh** (once per health round): every replica reads the fleet-max expiry into a local
//!   cache of atomics.
//! - **Read** (hot path): [`crate::self_heal_recovery::load_shed_active`] / `backoff_active` OR-in
//!   [`shed_active`] / [`backoff_active`] here — lock-free atomic reads, no DB on the request path.
//!
//! # Safety
//! - **Opt-in.** Coordination is off unless `WEISSMAN_SELFHEAL_SHARED_STATE_ENABLED` is truthy —
//!   it changes cross-process failure semantics, so it is never on by accident. Disabled ⇒ publish
//!   and refresh are no-ops and the cache stays 0 (readers see only their local gate, i.e. exactly
//!   today's behavior).
//! - **Fail-open.** Both DB calls are best-effort. A publish error is logged and dropped. A refresh
//!   error leaves the cache *untouched* — each cached expiry is absolute, so it drains on its own
//!   without flapping, and a store outage degrades to local-only gating rather than wedging intake.
//! - **Clock-skew robust.** Expiry is anchored to the DB clock on every write (`now() + ttl`) and
//!   remaining time is computed by the DB on read, so replica/DB clock skew cannot over- or
//!   under-hold a gate.
//! - **Bounded.** At most two rows (PK on `gate`); engagements overwrite, readers filter on
//!   `expires_at > now()`, so nothing accumulates.
//!
//! # Testability
//! The decision core ([`gate_active_at`], [`should_publish`], [`remaining_ttl`],
//! [`parse_enabled`], [`resolve_replica_id`]) is **pure** and unit-tested here; the SQL round-trip
//! is exercised by `tests/self_heal_shared_integration.rs` against a live Postgres.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use sqlx::PgPool;

/// Upsert-EXTEND a fleet gate: set its expiry to `now() + $2 seconds`, keeping the later of the
/// existing and incoming expiry so a shorter remaining never shortens another replica's engagement.
/// Bind order: `$1` gate name, `$2` remaining TTL (seconds, bigint), `$3` replica id.
/// Public so `tests/self_heal_shared_integration.rs` exercises the exact production SQL.
pub const PUBLISH_SQL: &str =
    "INSERT INTO weissman_self_heal_gate (gate, expires_at, engaged_by, updated_at) \
     VALUES ($1, now() + ($2 * interval '1 second'), $3, now()) \
     ON CONFLICT (gate) DO UPDATE \
       SET expires_at = GREATEST(weissman_self_heal_gate.expires_at, EXCLUDED.expires_at), \
           engaged_by = EXCLUDED.engaged_by, \
           updated_at = now()";

/// Read each still-live fleet gate and the remaining seconds until it expires, computed on the DB
/// clock (skew-robust). Rows: `(gate, secs_left)`. Public for the integration test (see above).
pub const REFRESH_SQL: &str =
    "SELECT gate, CEIL(EXTRACT(EPOCH FROM (expires_at - now())))::bigint AS secs_left \
     FROM weissman_self_heal_gate WHERE expires_at > now()";

/// Hard ceiling on each shared-gate DB call. Publish/refresh run inside the 10s health-loop tick,
/// so a slow-but-reachable Postgres (lock contention, a network hiccup) must fail *promptly* through
/// the fail-open path rather than block the whole tick — "fail-open" has to cover *slow*, not only
/// *unreachable*.
const SHARED_GATE_DB_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Which fleet gate a shared row / cache slot refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedGate {
    LoadShed,
    Backoff,
}

impl SharedGate {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SharedGate::LoadShed => "load_shed",
            SharedGate::Backoff => "backoff",
        }
    }
}

/// Parse the master flag. Default **false**: absent or non-truthy ⇒ coordination off.
#[must_use]
pub fn parse_enabled(v: Option<&str>) -> bool {
    matches!(
        v.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// Whether cross-replica coordination is enabled (cached; read once from env at first use).
#[must_use]
pub fn enabled() -> bool {
    static E: OnceLock<bool> = OnceLock::new();
    *E.get_or_init(|| {
        parse_enabled(
            std::env::var("WEISSMAN_SELFHEAL_SHARED_STATE_ENABLED")
                .ok()
                .as_deref(),
        )
    })
}

/// Resolve the replica identity written to `engaged_by`: explicit id, else hostname, else
/// `"unknown"`. Blank/whitespace values fall through.
#[must_use]
pub fn resolve_replica_id(explicit: Option<String>, hostname: Option<String>) -> String {
    // Trim-and-drop-blank on EACH candidate before choosing, so a whitespace-only explicit id
    // still falls through to the hostname (rather than short-circuiting to "unknown").
    let clean = |s: String| {
        let t = s.trim().to_string();
        (!t.is_empty()).then_some(t)
    };
    explicit
        .and_then(clean)
        .or_else(|| hostname.and_then(clean))
        .unwrap_or_else(|| "unknown".to_string())
}

fn replica_id() -> &'static str {
    static R: OnceLock<String> = OnceLock::new();
    R.get_or_init(|| {
        resolve_replica_id(
            std::env::var("WEISSMAN_REPLICA_ID").ok(),
            std::env::var("HOSTNAME").ok(),
        )
    })
}

/// This replica's cached view of the fleet gate expiries (epoch-secs; 0 ⇒ off).
struct SharedCache {
    shed_until: AtomicU64,
    backoff_until: AtomicU64,
}

fn cache() -> &'static SharedCache {
    static C: OnceLock<SharedCache> = OnceLock::new();
    C.get_or_init(|| SharedCache {
        shed_until: AtomicU64::new(0),
        backoff_until: AtomicU64::new(0),
    })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pure: a fleet gate is engaged iff its cached expiry is still in the future.
#[must_use]
pub fn gate_active_at(cached_until: u64, now: u64) -> bool {
    cached_until > now
}

/// Pure: remaining seconds a local gate stays engaged (0 once expired).
#[must_use]
pub fn remaining_ttl(local_until: u64, now: u64) -> u64 {
    local_until.saturating_sub(now)
}

/// Pure: a locally-engaged gate is worth publishing iff it still has time left to run.
#[must_use]
pub fn should_publish(local_until: u64, now: u64) -> bool {
    remaining_ttl(local_until, now) > 0
}

/// Fleet-wide load-shed as observed by this replica (cached; refreshed each health round).
/// Reads "off" when coordination is disabled.
#[must_use]
pub fn shed_active() -> bool {
    enabled() && gate_active_at(cache().shed_until.load(Ordering::SeqCst), now_secs())
}

/// Fleet-wide backoff as observed by this replica. Reads "off" when coordination is disabled.
#[must_use]
pub fn backoff_active() -> bool {
    enabled() && gate_active_at(cache().backoff_until.load(Ordering::SeqCst), now_secs())
}

/// Publish this replica's currently-engaged local gates to the shared store. Best-effort and
/// fail-open: only gates that are still locally active are written, the expiry is EXTENDED
/// (`GREATEST`) so a shorter remaining never shortens another replica's engagement, and any error
/// is logged and dropped. No-op unless coordination is enabled.
pub async fn publish_gates(pool: &PgPool, local_shed_until: u64, local_backoff_until: u64) {
    if !enabled() {
        return;
    }
    let now = now_secs();
    let rid = replica_id();
    for (gate, until) in [
        (SharedGate::LoadShed, local_shed_until),
        (SharedGate::Backoff, local_backoff_until),
    ] {
        if !should_publish(until, now) {
            continue;
        }
        let ttl = i64::try_from(remaining_ttl(until, now)).unwrap_or(i64::MAX);
        let exec = sqlx::query(PUBLISH_SQL)
            .bind(gate.as_str())
            .bind(ttl)
            .bind(rid)
            .execute(pool);
        // Timeout → PoolTimedOut so a slow store flows through the same fail-open error path.
        let res = tokio::time::timeout(SHARED_GATE_DB_TIMEOUT, exec)
            .await
            .unwrap_or(Err(sqlx::Error::PoolTimedOut));
        let outcome = if res.is_ok() { "ok" } else { "error" };
        metrics::counter!(
            "weissman_self_heal_shared_publish_total",
            "gate" => gate.as_str(),
            "outcome" => outcome,
        )
        .increment(1);
        if let Err(e) = res {
            tracing::debug!(
                target: "self_heal_shared",
                gate = gate.as_str(),
                error = %e,
                "shared gate publish failed (fail-open — local gate still applies)"
            );
        }
    }
}

/// Refresh this replica's cached view of the fleet gates from the shared store. Best-effort and
/// fail-open: on success each cached expiry becomes the fleet-max future expiry (0 if none, so a
/// cleared gate returns to "off"); on error the cache is left untouched (it drains on its own
/// absolute epoch — no flap). No-op unless coordination is enabled.
pub async fn refresh(pool: &PgPool) {
    if !enabled() {
        return;
    }
    // The DB computes remaining seconds on its own clock, so gating is skew-robust.
    let fetch = sqlx::query_as::<_, (String, i64)>(REFRESH_SQL).fetch_all(pool);
    // Timeout → PoolTimedOut so a slow store leaves the cache untouched (drains on its own epoch).
    let rows = tokio::time::timeout(SHARED_GATE_DB_TIMEOUT, fetch)
        .await
        .unwrap_or(Err(sqlx::Error::PoolTimedOut));
    let now = now_secs();
    match rows {
        Ok(rows) => {
            let mut shed = 0u64;
            let mut backoff = 0u64;
            for (gate, secs_left) in rows {
                let until = now.saturating_add(u64::try_from(secs_left).unwrap_or(0));
                match gate.as_str() {
                    "load_shed" => shed = until,
                    "backoff" => backoff = until,
                    _ => {}
                }
            }
            cache().shed_until.store(shed, Ordering::SeqCst);
            cache().backoff_until.store(backoff, Ordering::SeqCst);
            metrics::gauge!("weissman_self_heal_shared_gate_active", "gate" => "load_shed")
                .set(if gate_active_at(shed, now) { 1.0 } else { 0.0 });
            metrics::gauge!("weissman_self_heal_shared_gate_active", "gate" => "backoff").set(
                if gate_active_at(backoff, now) {
                    1.0
                } else {
                    0.0
                },
            );
            metrics::counter!("weissman_self_heal_shared_refresh_total", "outcome" => "ok")
                .increment(1);
        }
        Err(e) => {
            metrics::counter!("weissman_self_heal_shared_refresh_total", "outcome" => "error")
                .increment(1);
            tracing::debug!(
                target: "self_heal_shared",
                error = %e,
                "shared gate refresh failed (fail-open — cache drains on its own expiry)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_str_names_are_stable() {
        assert_eq!(SharedGate::LoadShed.as_str(), "load_shed");
        assert_eq!(SharedGate::Backoff.as_str(), "backoff");
    }

    #[test]
    fn parse_enabled_defaults_off_and_reads_truthy() {
        assert!(!parse_enabled(None));
        assert!(!parse_enabled(Some("")));
        assert!(!parse_enabled(Some("0")));
        assert!(!parse_enabled(Some("false")));
        assert!(!parse_enabled(Some("off")));
        assert!(parse_enabled(Some("1")));
        assert!(parse_enabled(Some("true")));
        assert!(parse_enabled(Some(" TRUE ")));
        assert!(parse_enabled(Some("yes")));
        assert!(parse_enabled(Some("on")));
    }

    #[test]
    fn replica_id_prefers_explicit_then_hostname_then_unknown() {
        assert_eq!(
            resolve_replica_id(Some("pod-a".into()), Some("host-b".into())),
            "pod-a"
        );
        assert_eq!(resolve_replica_id(None, Some("host-b".into())), "host-b");
        assert_eq!(resolve_replica_id(None, None), "unknown");
        // Blank explicit falls through to hostname; blank both ⇒ unknown.
        assert_eq!(
            resolve_replica_id(Some("  ".into()), Some("host-b".into())),
            "host-b"
        );
        assert_eq!(
            resolve_replica_id(Some("  ".into()), Some("  ".into())),
            "unknown"
        );
    }

    #[test]
    fn gate_active_only_while_future() {
        assert!(gate_active_at(1_100, 1_000)); // future ⇒ engaged
        assert!(!gate_active_at(1_000, 1_000)); // exactly now ⇒ expired
        assert!(!gate_active_at(900, 1_000)); // past ⇒ off
        assert!(!gate_active_at(0, 1_000)); // never set ⇒ off
    }

    #[test]
    fn remaining_ttl_saturates_at_zero() {
        assert_eq!(remaining_ttl(1_030, 1_000), 30);
        assert_eq!(remaining_ttl(1_000, 1_000), 0);
        assert_eq!(remaining_ttl(900, 1_000), 0); // already expired ⇒ 0, never underflows
    }

    #[test]
    fn should_publish_only_live_gates() {
        assert!(should_publish(1_030, 1_000)); // 30s left ⇒ publish
        assert!(!should_publish(1_000, 1_000)); // nothing left ⇒ skip
        assert!(!should_publish(0, 1_000)); // never engaged ⇒ skip
    }

    #[test]
    fn disabled_readers_are_off_regardless_of_cache() {
        // With the default flag (off in the test env), the fleet readers never engage even if the
        // cache were populated — they gate on `enabled()` first.
        if !enabled() {
            assert!(!shed_active());
            assert!(!backoff_active());
        }
    }
}
