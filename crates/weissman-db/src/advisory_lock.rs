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
//!
//! # Row locks are the same bug
//!
//! `lock_timeout` is not advisory-lock-specific — Postgres applies it to *any* wait for *any*
//! lock. `SELECT … FOR UPDATE` is therefore the same defect in different syntax: it blocks
//! indefinitely under a bare test pool, for the same reason, with the same symptom (a wedged
//! test binary and no diagnostic). Advisory-lock call sites were only the ones this workspace
//! happened to notice first.
//!
//! So the bound is applied one level up as well: [`crate::set_tenant_tx`] — the single funnel
//! every tenant transaction passes through — sets it alongside the RLS GUC, in the *same*
//! statement, so it costs no extra round trip and covers every present and future blocking wait
//! inside a tenant transaction rather than only the ones someone remembered to wrap.
//! [`bound_lock_wait`] is public for the few transactions that do not carry a tenant GUC
//! (`auth_refresh`, which runs on the auth pool).
//!
//! `FOR UPDATE SKIP LOCKED` (the job-queue claim path) never waits and is unaffected either way.

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
pub const LOCK_TIMEOUT_ENV: &str = "WEISSMAN_LOCK_TIMEOUT_MS";

/// Previous name for [`LOCK_TIMEOUT_ENV`], still honoured when the current one is unset.
///
/// The bound started out governing advisory locks only; it now bounds **every** lock wait in a
/// tenant transaction (see [`bound_lock_wait`]), which made the old name actively misleading.
/// Deployments that already set it keep working — the current name simply wins when both exist.
pub const LEGACY_LOCK_TIMEOUT_ENV: &str = "WEISSMAN_ADVISORY_LOCK_TIMEOUT_MS";

/// Pure parser behind [`lock_timeout`], split out so it can be tested without mutating the
/// process environment — `std::env::set_var` races with any other thread reading the environment
/// (and is `unsafe` from edition 2024), which is not something a test suite should introduce.
fn parse_lock_timeout(raw: Option<&str>) -> Duration {
    raw.and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_LOCK_TIMEOUT)
}

/// Pure resolution of the two accepted env names, split out for the same reason as
/// [`parse_lock_timeout`].
///
/// A *present* primary wins outright — including when its value is nonsense. Falling through to
/// the legacy name on a typo would silently apply a different bound than the operator last
/// edited, which is precisely the kind of non-local surprise this module exists to remove.
fn resolve_lock_timeout(primary: Option<&str>, legacy: Option<&str>) -> Duration {
    match primary {
        Some(_) => parse_lock_timeout(primary),
        None => parse_lock_timeout(legacy),
    }
}

/// Resolve the configured lock-wait bound.
pub fn lock_timeout() -> Duration {
    resolve_lock_timeout(
        std::env::var(LOCK_TIMEOUT_ENV).ok().as_deref(),
        std::env::var(LEGACY_LOCK_TIMEOUT_ENV).ok().as_deref(),
    )
}

/// The configured bound rendered as a Postgres `lock_timeout` value (milliseconds, as text).
///
/// Exists so a caller can fold the bound into a statement it was already sending — see
/// [`crate::set_tenant_tx`], which passes this to `set_config` alongside the RLS GUC and so pays
/// **no** extra round trip for it.
pub fn lock_timeout_setting() -> String {
    lock_timeout().as_millis().max(1).to_string()
}

/// True when `err` is Postgres' `lock_not_available` (SQLSTATE `55P03`) — i.e. this module's
/// bound fired rather than some unrelated database failure.
///
/// Callers that are legitimately fail-open (best-effort single-flight guards) use this to log
/// contention distinctly from a real error.
pub fn is_lock_timeout(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db) if db.code().as_deref() == Some("55P03"))
}

/// Apply the transaction-scoped wait bound to **every** lock this transaction goes on to take.
///
/// `lock_timeout` is not advisory-lock-specific: Postgres applies it to any wait for any lock,
/// so this one statement also bounds `SELECT … FOR UPDATE`, `UPDATE`/`DELETE` on a contended row,
/// `LOCK TABLE` and DDL. That is why it is public — a transaction that takes a **blocking row
/// lock** has exactly the failure mode this module was written for, and
/// `SELECT … FOR UPDATE` is simply a different spelling of "wait forever by default".
///
/// Must run inside an open transaction; `SET LOCAL` outside one is a no-op that Postgres only
/// warns about, which would silently restore the unbounded behaviour — so every caller pairs it
/// with a transaction it has already begun.
pub async fn bound_lock_wait(
    conn: &mut sqlx::PgConnection,
    bound: Duration,
) -> Result<(), sqlx::Error> {
    let ms = bound.as_millis().max(1);
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
    advisory_xact_lock_with_timeout(conn, key, lock_timeout()).await
}

/// [`advisory_xact_lock`] with an explicit bound instead of the configured one.
///
/// Exists so the regression tests can drive a short bound without mutating the process
/// environment (which races with any concurrent reader). Production code should call
/// [`advisory_xact_lock`] and let the bound come from configuration.
pub async fn advisory_xact_lock_with_timeout(
    conn: &mut sqlx::PgConnection,
    key: i64,
    bound: Duration,
) -> Result<(), sqlx::Error> {
    bound_lock_wait(&mut *conn, bound).await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *conn)
        .await
        // `inspect_err`, not `map_err`: this only observes the error to log it and must return it
        // unchanged. Saying so in the combinator keeps that guarantee from depending on the
        // trailing `e` in a closure body.
        .inspect_err(|e| {
            if is_lock_timeout(e) {
                tracing::error!(
                    target: "weissman_db",
                    advisory_key = key,
                    timeout_ms = bound.as_millis() as u64,
                    "advisory lock wait exceeded its bound — another transaction is holding this key"
                );
            }
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
    advisory_xact_lock_text_with_timeout(conn, key, lock_timeout()).await
}

/// [`advisory_xact_lock_text`] with an explicit bound. See
/// [`advisory_xact_lock_with_timeout`] for why this exists.
pub async fn advisory_xact_lock_text_with_timeout(
    conn: &mut sqlx::PgConnection,
    key: &str,
    bound: Duration,
) -> Result<(), sqlx::Error> {
    bound_lock_wait(&mut *conn, bound).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(key)
        .execute(&mut *conn)
        .await
        // See the sibling helper above: observe-and-rethrow, never transform.
        .inspect_err(|e| {
            if is_lock_timeout(e) {
                tracing::error!(
                    target: "weissman_db",
                    advisory_key = key,
                    timeout_ms = bound.as_millis() as u64,
                    "advisory lock wait exceeded its bound — another transaction is holding this key"
                );
            }
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
    advisory_xact_lock_text_or_skip_with_timeout(conn, key, lock_timeout()).await
}

/// [`advisory_xact_lock_text_or_skip`] with an explicit bound. See
/// [`advisory_xact_lock_with_timeout`] for why this exists.
pub async fn advisory_xact_lock_text_or_skip_with_timeout(
    conn: &mut sqlx::PgConnection,
    key: &str,
    bound: Duration,
) -> Result<bool, sqlx::Error> {
    sqlx::query(&format!("SAVEPOINT {SKIP_SAVEPOINT}"))
        .execute(&mut *conn)
        .await?;

    match advisory_xact_lock_text_with_timeout(&mut *conn, key, bound).await {
        Ok(()) => {
            sqlx::query(&format!("RELEASE SAVEPOINT {SKIP_SAVEPOINT}"))
                .execute(&mut *conn)
                .await?;
            Ok(true)
        }
        Err(e) => {
            // Restore the transaction to its pre-attempt state (this also reverts the
            // `SET LOCAL lock_timeout`), then drop the savepoint so repeated calls in one
            // transaction do not stack them.
            sqlx::query(&format!("ROLLBACK TO SAVEPOINT {SKIP_SAVEPOINT}"))
                .execute(&mut *conn)
                .await?;
            sqlx::query(&format!("RELEASE SAVEPOINT {SKIP_SAVEPOINT}"))
                .execute(&mut *conn)
                .await?;

            // ONLY contention is "skip". A connection drop, a syntax error or a permissions
            // failure must not be laundered into `Ok(false)` — that would send the caller down
            // its racy fail-open path on a real database fault, which is precisely the kind of
            // silent degradation this module exists to remove.
            if !is_lock_timeout(&e) {
                return Err(e);
            }
            tracing::warn!(
                target: "weissman_db",
                advisory_key = key,
                error = %e,
                "advisory lock contended; caller continues without serialization"
            );
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drives the parser directly rather than through the environment: `std::env::set_var` races
    /// with any other thread reading the environment, so a test suite must not introduce it.
    #[test]
    fn default_applies_when_override_is_absent_or_nonsense() {
        assert_eq!(parse_lock_timeout(None), DEFAULT_LOCK_TIMEOUT);
        assert_eq!(
            parse_lock_timeout(Some("not-a-number")),
            DEFAULT_LOCK_TIMEOUT
        );
        assert_eq!(parse_lock_timeout(Some("")), DEFAULT_LOCK_TIMEOUT);
        assert_eq!(parse_lock_timeout(Some("-1")), DEFAULT_LOCK_TIMEOUT);

        // 0 means "wait forever" to Postgres — precisely the failure mode this module exists
        // to remove, so it must never be honoured as an override.
        assert_eq!(parse_lock_timeout(Some("0")), DEFAULT_LOCK_TIMEOUT);

        assert_eq!(
            parse_lock_timeout(Some("2500")),
            Duration::from_millis(2500)
        );
        assert_eq!(
            parse_lock_timeout(Some("  2500  ")),
            Duration::from_millis(2500)
        );
    }

    /// The legacy name must keep working for deployments that already set it, but must never
    /// override a name the operator has set more recently.
    #[test]
    fn legacy_env_name_is_a_fallback_not_an_override() {
        // Neither set → default.
        assert_eq!(resolve_lock_timeout(None, None), DEFAULT_LOCK_TIMEOUT);

        // Only the legacy name set → honoured, so an existing deployment is not silently
        // reverted to the default by this rename.
        assert_eq!(
            resolve_lock_timeout(None, Some("2500")),
            Duration::from_millis(2500)
        );

        // Both set → the current name wins.
        assert_eq!(
            resolve_lock_timeout(Some("1000"), Some("2500")),
            Duration::from_millis(1000)
        );

        // Primary present but unparseable → default, NOT the legacy value. Falling through
        // would apply a bound the operator did not last write, which is worse than being
        // obviously wrong.
        assert_eq!(
            resolve_lock_timeout(Some("bogus"), Some("2500")),
            DEFAULT_LOCK_TIMEOUT
        );
        // Same for the 0-means-infinite rejection.
        assert_eq!(
            resolve_lock_timeout(Some("0"), Some("2500")),
            DEFAULT_LOCK_TIMEOUT
        );
    }

    /// `set_config` takes text, and a `lock_timeout` of `0` means *infinite* — the exact bug
    /// this module removes. The rendered value must never be `0`.
    #[test]
    fn rendered_setting_is_positive_milliseconds() {
        let s = lock_timeout_setting();
        let ms: u128 = s
            .parse()
            .expect("lock_timeout_setting must render an integer");
        assert!(ms > 0, "rendered lock_timeout must never be 0 (= infinite)");
    }

    #[test]
    fn non_lock_errors_are_not_classified_as_timeouts() {
        assert!(!is_lock_timeout(&sqlx::Error::PoolTimedOut));
        assert!(!is_lock_timeout(&sqlx::Error::RowNotFound));
    }
}
