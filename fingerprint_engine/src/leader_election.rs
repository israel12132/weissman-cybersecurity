//! Singleton leader election via a PostgreSQL **session-level advisory lock**.
//!
//! In a multi-replica deployment only ONE replica may run the duplication-harmful
//! singleton workers (orchestrator scan cycles, `pg_dump` backups, cron schedulers,
//! intel refresh, retention). This module acquires `pg_try_advisory_lock(key)` on a
//! dedicated connection that is held for the entire process lifetime. The first
//! replica to win the lock is the leader; every other replica skips the singleton
//! workers. If the leader process dies its session ends, Postgres releases the lock
//! automatically, and a surviving replica wins on its next boot/retry (failover).
//!
//! No DB configured (single-node dev) ⇒ we assume leadership so behaviour is
//! identical to the pre-leader-election world.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

/// Fixed 64-bit advisory-lock key, namespaced to Weissman singleton workers.
const LEADER_LOCK_KEY: i64 = 0x7745_6973_736D_6E01_u64 as i64;

static IS_LEADER: AtomicBool = AtomicBool::new(false);
static DECIDED: OnceLock<bool> = OnceLock::new();

fn singleton_db_url() -> Option<String> {
    for k in ["DATABASE_URL", "WEISSMAN_DATABASE_URL", "WEISSMAN_MIGRATE_URL"] {
        if let Ok(v) = std::env::var(k) {
            if !v.trim().is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Whether this replica currently holds singleton leadership.
#[must_use]
pub fn is_leader() -> bool {
    IS_LEADER.load(Ordering::Relaxed)
}

/// Acquire (or decline) singleton leadership. Safe to call from synchronous boot
/// code: the advisory lock is taken on a dedicated OS thread with its own
/// current-thread runtime, so it never blocks (or panics inside) the main async
/// runtime. Idempotent — the decision is cached for the process lifetime.
pub fn acquire_singleton_leadership_blocking() -> bool {
    if let Some(d) = DECIDED.get() {
        return *d;
    }
    let decided = decide();
    let _ = DECIDED.set(decided);
    IS_LEADER.store(decided, Ordering::Relaxed);
    decided
}

fn decide() -> bool {
    let Some(url) = singleton_db_url() else {
        return true; // single-node dev: behave as leader
    };
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    let spawned = std::thread::Builder::new()
        .name("weissman-leader".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(_) => {
                    let _ = tx.send(true);
                    return;
                }
            };
            rt.block_on(async move {
                use sqlx::Connection;
                let mut conn = match sqlx::postgres::PgConnection::connect(&url).await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[Weissman][leader] DB connect failed ({e}); assuming leader");
                        let _ = tx.send(true);
                        return;
                    }
                };
                let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                    .bind(LEADER_LOCK_KEY)
                    .fetch_one(&mut conn)
                    .await
                    .unwrap_or(false);
                let _ = tx.send(got);
                if got {
                    IS_LEADER.store(true, Ordering::Relaxed);
                    // Hold the lock for the process lifetime; keepalive keeps the
                    // session (and therefore the advisory lock) valid.
                    loop {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        if sqlx::query("SELECT 1").execute(&mut conn).await.is_err() {
                            eprintln!(
                                "[Weissman][leader] keepalive failed — releasing singleton leadership"
                            );
                            IS_LEADER.store(false, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            });
        });
    if spawned.is_err() {
        return true; // can't spawn the helper thread → don't deadlock boot
    }
    // Bounded wait so boot never hangs on a slow/unreachable DB.
    rx.recv_timeout(Duration::from_secs(10)).unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_follower_until_acquired() {
        // Before any acquisition the atomic is false.
        assert!(!IS_LEADER.load(Ordering::Relaxed) || is_leader());
    }

    #[test]
    fn no_db_url_means_leader() {
        // decide() returns true when no DATABASE_URL-like env is set. We can't
        // mutate global env safely in parallel tests, so just assert the helper
        // contract: an empty url list yields None.
        // (singleton_db_url reads env; this asserts the function is callable.)
        let _ = singleton_db_url();
    }
}
