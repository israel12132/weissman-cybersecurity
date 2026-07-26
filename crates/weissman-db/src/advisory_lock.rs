//! Bounded Postgres advisory locks.
//!
//! # Why this module exists
//!
//! `pg_advisory_xact_lock()` waits **forever** by contract. Postgres' deadlock detector only
//! breaks true *cycles* — a plain "A holds the lock, B waits" chain is not a cycle, so B is
//! never woken and never errors. Whether such a wait is bounded at all therefore depends
//! entirely on the `lock_timeout` / `statement_timeout` carried by the connection the caller
//! happened to be handed, which is a **non-local property set somewhere else entirely**.
//!
//! That is exactly how the CI hang in `docs/TECH_DEBT_flaky_db_test_hang.md` happened:
//!
//! * the product pools in [`crate`] set `statement_timeout` in `after_connect`, so a blocked
//!   advisory lock in the server/worker dies (crudely) after ~120 s;
//! * every **test** pool is built from a bare `PgPoolOptions::new()`, which inherits
//!   `lock_timeout = 0` and `statement_timeout = 0` — *infinite*;
//! * so the identical code path that is bounded in production is unbounded under
//!   `cargo test`, and one stuck holder wedged the whole workspace test binary until the
//!   45-minute GitHub step timeout SIGKILLed it with no diagnostic.
//!
//! The fix is to make the bound **intrinsic to the lock itself** rather than a property of the
//! pool: every advisory-lock acquisition in this workspace goes through the helpers below,
//! which issue a transaction-scoped `SET LOCAL lock_timeout` immediately before the wait.
//! An unavailable lock then fails fast with SQLSTATE `55P03` (`lock_not_available`) naming the
//! key, instead of hanging — in tests, in production, and in any future caller, regardless of
//! how its pool was constructed.
//!
//! # This does not weaken serialization
//!
//! Every current caller takes the lock to make a read-then-append pair atomic (tamper-evident
//! hash chains, single-flight guards). On timeout these helpers return `Err` so the caller's
//! transaction aborts; the protected work is **never** performed unserialized. "Fail loudly and
//! fast" replaces "hang forever" — it does not replace "hold the lock".
//!
//! # Scope of `SET LOCAL`
//!
//! `SET LOCAL` reverts automatically when the transaction ends, so it cannot leak onto a pooled
//! connection. It is deliberately **not** reset after the lock is taken: the remainder of a
//! transaction that needed serialization is exactly the code that must not block forever on a
//! row lock either, and skipping the restore keeps this to one extra round trip on a hot path.

use std::time::Duration;

/// Default bound on a single advisory-lock wait.
///
/// Uncontended acquisition is sub-millisecond and even a pathological burst on one key queues
/// for well under a second, so 15 s is ~3 orders of magnitude of headroom. It is also
/// deliberately far below the 120 s app-pool `statement_timeout`, so a genuine lock problem
/// surfaces as a precise `lock_not_available` naming this module rather than as a generic
/// "statement timeout" that could have come from anywhere.
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(15);

/// Env override for [`DEFAULT_LOCK_TIMEOUT`], in milliseconds.
///
/// Mirrors the `WEISSMAN_APP_STATEMENT_TIMEOUT_MS` convention used by the pool builders.
/// `0` is rejected (it means *infinite* to Postgres, which is the bug this module exists to
/// prevent) and falls back to the default.
pub const LOCK_TIMEOUT_ENV: &str = "WEISSMAN_ADVISORY_LOCK_TIMEOUT_MS";

/// Resolve the configured advisory-lock wait bound.
pub fn lock_timeout() -> Duration {
    std::env::var(LOCK_TIMEOUT_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_LOCK_TIMEOUT)
}

/// True when `err` is Postgres' `lock_not_available` (SQLSTATE `55P03`) — i.e. this module's
/// bound fired rather than some unrelated database failure.
///
/// Callers that are legitimately fail-open (best-effort single-flight guards) use this to log
/// contention distinctly from a real error.
pub fn is_lock_timeout(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db) if db.code().as_deref() == Some("55P03"))
}

/// Apply the transaction-scoped wait bound. Must run inside an open transaction; `SET LOCAL`
/// outside one is a no-op that Postgres only warns about, which would silently restore the
/// unbounded behaviour — so the callers below always pair it with an `_xact_` lock.
async fn set_local_lock_timeout(conn: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let ms = lock_timeout().as_millis().max(1);
    // Interpolated, not bound: `SET` takes a literal, not a placeholder, and `ms` is a u128
    // derived from our own parse — no untrusted input reaches this string.
    sqlx::query(&format!("SET LOCAL lock_timeout = {ms}"))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Transaction-scoped advisory lock on an `i64` key, bounded by [`lock_timeout`].
///
/// Released when the surrounding transaction commits or rolls back. Returns
/// `Err(sqlx::Error::Database)` with SQLSTATE `55P03` if the lock could not be taken in time —
/// see [`is_lock_timeout`].
pub async fn advisory_xact_lock(
    conn: &mut sqlx::PgConnection,
    key: i64,
) -> Result<(), sqlx::Error> {
    set_local_lock_timeout(&mut *conn).await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            if is_lock_timeout(&e) {
                tracing::error!(
                    target: "weissman_db",
                    advisory_key = key,
                    timeout_ms = lock_timeout().as_millis() as u64,
                    "advisory lock wait exceeded its bound — another transaction is holding this key"
                );
            }
            e
        })?;
    Ok(())
}

/// Transaction-scoped advisory lock on a text key, bounded by [`lock_timeout`].
///
/// The key is folded to `bigint` with `hashtextextended(key, 0)` — Postgres' advisory-lock
/// space is integer-only, and this is the exact expression the pre-existing call sites used, so
/// lock identities are unchanged by the introduction of this helper.
pub async fn advisory_xact_lock_text(
    conn: &mut sqlx::PgConnection,
    key: &str,
) -> Result<(), sqlx::Error> {
    set_local_lock_timeout(&mut *conn).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(key)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            if is_lock_timeout(&e) {
                tracing::error!(
                    target: "weissman_db",
                    advisory_key = key,
                    timeout_ms = lock_timeout().as_millis() as u64,
                    "advisory lock wait exceeded its bound — another transaction is holding this key"
                );
            }
            e
        })?;
    Ok(())
}

/// Savepoint name used by [`advisory_xact_lock_text_or_skip`]. Fixed identifier: the helper is
/// never nested inside itself, and a literal keeps the statement free of interpolation.
const SKIP_SAVEPOINT: &str = "weissman_advisory_lock";

/// Bounded advisory lock for **best-effort** single-flight guards: returns `Ok(false)` when the
/// lock could not be taken in time, leaving the caller's transaction usable.
///
/// Prefer [`advisory_xact_lock_text`] whenever the protected work is correctness-critical.
///
/// # Why a savepoint
///
/// In Postgres *any* error inside a transaction aborts it — every later statement then fails with
/// `25P02 current_transaction_is_aborted`. So a plain bounded lock cannot be "fail-open": the
/// fallback path the caller intended to run would itself error out. Wrapping the attempt in a
/// savepoint and rolling back to it on failure keeps the transaction alive, and — because
/// `SET LOCAL` is savepoint-aware — also reverts `lock_timeout`, leaving the caller's transaction
/// in exactly the state it was in before the attempt.
///
/// A blocking (bounded) wait is used rather than `pg_try_advisory_xact_lock`, which would give up
/// instantly: the common case this guard exists for is a *short* race between two workers, and
/// waiting for the holder to commit is precisely what makes the guard work.
pub async fn advisory_xact_lock_text_or_skip(
    conn: &mut sqlx::PgConnection,
    key: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query(&format!("SAVEPOINT {SKIP_SAVEPOINT}"))
        .execute(&mut *conn)
        .await?;

    match advisory_xact_lock_text(&mut *conn, key).await {
        Ok(()) => {
            sqlx::query(&format!("RELEASE SAVEPOINT {SKIP_SAVEPOINT}"))
                .execute(&mut *conn)
                .await?;
            Ok(true)
        }
        Err(e) => {
            sqlx::query(&format!("ROLLBACK TO SAVEPOINT {SKIP_SAVEPOINT}"))
                .execute(&mut *conn)
                .await?;
            tracing::warn!(
                target: "weissman_db",
                advisory_key = key,
                contended = is_lock_timeout(&e),
                error = %e,
                "advisory lock skipped; caller continues without serialization"
            );
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_applies_when_env_is_absent_or_nonsense() {
        // The suite is single-process; keep these on one test so the env is not raced.
        std::env::remove_var(LOCK_TIMEOUT_ENV);
        assert_eq!(lock_timeout(), DEFAULT_LOCK_TIMEOUT);

        std::env::set_var(LOCK_TIMEOUT_ENV, "not-a-number");
        assert_eq!(lock_timeout(), DEFAULT_LOCK_TIMEOUT);

        // 0 means "wait forever" to Postgres — precisely the failure mode this module exists
        // to remove, so it must never be honoured as an override.
        std::env::set_var(LOCK_TIMEOUT_ENV, "0");
        assert_eq!(lock_timeout(), DEFAULT_LOCK_TIMEOUT);

        std::env::set_var(LOCK_TIMEOUT_ENV, "2500");
        assert_eq!(lock_timeout(), Duration::from_millis(2500));

        std::env::remove_var(LOCK_TIMEOUT_ENV);
    }

    #[test]
    fn non_lock_errors_are_not_classified_as_timeouts() {
        assert!(!is_lock_timeout(&sqlx::Error::PoolTimedOut));
        assert!(!is_lock_timeout(&sqlx::Error::RowNotFound));
    }
}
