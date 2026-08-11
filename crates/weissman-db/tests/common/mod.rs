//! Shared helpers for the DB integration tests.

use sqlx::pool::PoolConnection;
use sqlx::Postgres;

/// Advisory-lock key shared by every test that CLAIMS from `weissman_async_jobs`.
///
/// Claiming is global: `reserve_next` / `claim_next` take the oldest eligible row in the whole
/// table, so two tests running concurrently dequeue each other's fixtures and both fail with
/// "claimed an unrelated job". Per-tenant and per-kind isolation fixes *cleanup*, not *claiming* —
/// nothing in the claim predicate is scoped to a test.
///
/// Arbitrary constant, chosen not to collide with `advisory_lock::tenant_key` values (which are
/// tenant ids).
const CLAIM_SERIALIZER_KEY: i64 = 0x7745_1553_4D41_4E01_u64 as i64;

/// Serialize claim-based tests against one another, across test binaries.
///
/// Held for as long as the returned connection is alive; drop it to release. Uses the
/// **non-blocking** `pg_try_advisory_lock` in a bounded retry rather than `pg_advisory_lock`:
/// `no_unbounded_lock_waits.rs` forbids the blocking forms precisely because a test pool has no
/// `lock_timeout`, so a blocking wait here would hang the binary until CI SIGKILLs it with no
/// diagnostic. If the lock cannot be taken in time we panic with a clear message instead.
pub async fn lock_claims(pool: &sqlx::PgPool) -> PoolConnection<Postgres> {
    let mut conn = pool.acquire().await.expect("acquire serializer connection");
    for _ in 0..600 {
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(CLAIM_SERIALIZER_KEY)
            .fetch_one(&mut *conn)
            .await
            .expect("pg_try_advisory_lock");
        if got {
            return conn;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!(
        "could not take the claim serializer lock within 30s — another claim test is stuck holding \
         it, or a previous run leaked the session"
    );
}
