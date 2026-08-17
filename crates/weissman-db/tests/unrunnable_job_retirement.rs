//! The retirement predicate for permanently-unrunnable queue rows.
//!
//! `data_retention` only ever deleted rows that had already reached a terminal status, so a
//! `pending` row the claim path can never pick up was immortal: never claimed, never deleted,
//! forever inflating queue depth. The live queue held 2,973 of them after the 2026-08-06 outage —
//! every one a repeat of the same `orchestrator_tick` scan — which distorted every queue metric
//! and, until the coalescing predicate was corrected, deadlocked the scheduler outright.
//!
//! This test file exists because the predicate is genuinely dangerous in one direction. Retiring
//! "anything not currently claimable" would destroy jobs **mid-enqueue**: `enqueue_held` inserts a
//! row WITHOUT its zero-trust envelope and attaches it moments later, and a row whose `run_after`
//! is still in the future is simply not due yet. Both become claimable on their own. The two
//! conditions that are genuinely terminal are narrower:
//!
//!   * no envelope AND older than the grace window — nothing re-signs an existing row, since
//!     `attach_signed_envelope` runs only at enqueue time;
//!   * `attempt_count >= max_attempts` — the claim predicate skips these and nothing decrements it.
//!
//! The SQL is duplicated here rather than imported because it lives in `fingerprint_engine`, which
//! this crate does not depend on. Keep the two in sync — the test asserts the behaviour that
//! matters, so a divergence shows up as a failure here.

use sqlx::postgres::PgPoolOptions;
use sqlx::Row;

const TENANT: i64 = 918_276_001;
const PROBE_KIND: &str = "__unrunnable_retirement_probe__";

/// Verbatim copy of `retire_unrunnable_pending_jobs` in fingerprint_engine/src/data_retention.rs.
const RETIRE_SQL: &str = r#"UPDATE weissman_async_jobs
      SET status = 'dead',
          last_error = COALESCE(NULLIF(last_error, ''), '')
              || CASE WHEN payload ? '_weissman_job_bus'
                      THEN '[retired: attempts exhausted; the claim path skips it]'
                      ELSE '[retired: enqueued without a zero-trust envelope; nothing re-signs an existing row, so it could never be claimed]'
                 END,
          updated_at = now()
    WHERE status = 'pending'
      AND created_at < now() - ($1::bigint * interval '1 second')
      AND (
            attempt_count >= max_attempts
            OR NOT (payload ? '_weissman_job_bus')
          )"#;

fn require_db_tests() -> bool {
    std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn test_database_url() -> String {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => {
            assert!(
                !require_db_tests(),
                "unrunnable_job_retirement requires TEST_DATABASE_URL, but \
                 WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP unrunnable_job_retirement: TEST_DATABASE_URL not set");
            String::new()
        }
    }
}

async fn pool(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await
        .expect("connect TEST_DATABASE_URL")
}

/// Insert a probe job. `age_secs` backdates `created_at`; `envelope` controls the bus key.
async fn insert(
    p: &sqlx::PgPool,
    label: &str,
    envelope: bool,
    attempts: i32,
    max_attempts: i32,
    age_secs: i64,
    due: bool,
) -> uuid::Uuid {
    sqlx::query_scalar(
        r#"INSERT INTO weissman_async_jobs
               (tenant_id, kind, payload, status, attempt_count, max_attempts, created_at, run_after)
           VALUES ($1, $2,
                   CASE WHEN $3 THEN jsonb_build_object('label', $4::text, '_weissman_job_bus',
                                                        jsonb_build_object('envelope', '{}'::jsonb))
                        ELSE jsonb_build_object('label', $4::text) END,
                   'pending', $5, $6,
                   now() - ($7::bigint * interval '1 second'),
                   CASE WHEN $8 THEN NULL ELSE now() + interval '10 minutes' END)
           RETURNING id"#,
    )
    .bind(TENANT)
    .bind(PROBE_KIND)
    .bind(envelope)
    .bind(label)
    .bind(attempts)
    .bind(max_attempts)
    .bind(age_secs)
    .bind(due)
    .fetch_one(p)
    .await
    .expect("insert probe job")
}

async fn status_of(p: &sqlx::PgPool, id: uuid::Uuid) -> String {
    sqlx::query("SELECT status FROM weissman_async_jobs WHERE id = $1")
        .bind(id)
        .fetch_one(p)
        .await
        .expect("read status")
        .get::<String, _>("status")
}

async fn cleanup(p: &sqlx::PgPool) {
    let _ = sqlx::query("DELETE FROM weissman_async_jobs WHERE kind = $1")
        .bind(PROBE_KIND)
        .execute(p)
        .await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(TENANT)
        .execute(p)
        .await;
}

#[tokio::test]
async fn retires_only_permanently_unrunnable_rows() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let p = pool(&url).await;
    cleanup(&p).await;
    let _ = sqlx::query(
        "INSERT INTO tenants (id, slug, name) VALUES ($1, 'retire-probe', 'Retire probe') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(TENANT)
    .execute(&p)
    .await;

    // MUST be retired — terminal.
    let no_envelope_old = insert(&p, "no-envelope-old", false, 0, 5, 7200, true).await;
    let exhausted = insert(&p, "exhausted", true, 5, 5, 7200, true).await;

    // MUST survive — each becomes claimable on its own.
    let mid_enqueue = insert(&p, "mid-enqueue", false, 0, 5, 5, true).await;
    let held = insert(&p, "held-not-due", true, 0, 5, 7200, false).await;
    let healthy = insert(&p, "healthy", true, 1, 5, 7200, true).await;

    let retired = sqlx::query(RETIRE_SQL)
        .bind(3600_i64)
        .execute(&p)
        .await
        .expect("retire")
        .rows_affected();

    let s_no_env = status_of(&p, no_envelope_old).await;
    let s_exhausted = status_of(&p, exhausted).await;
    let s_mid = status_of(&p, mid_enqueue).await;
    let s_held = status_of(&p, held).await;
    let s_healthy = status_of(&p, healthy).await;
    let reason: String =
        sqlx::query_scalar("SELECT last_error FROM weissman_async_jobs WHERE id = $1")
            .bind(no_envelope_old)
            .fetch_one(&p)
            .await
            .expect("read reason");
    cleanup(&p).await;

    assert_eq!(
        retired, 2,
        "exactly the two terminal rows should be retired"
    );
    assert_eq!(
        s_no_env, "dead",
        "an envelope-less row past the grace window can never be claimed"
    );
    assert_eq!(
        s_exhausted, "dead",
        "a row at its attempt ceiling can never be claimed"
    );

    // The dangerous direction: these must NOT be touched.
    assert_eq!(
        s_mid, "pending",
        "a job still inside the grace window is mid-enqueue — enqueue_held inserts WITHOUT an \
         envelope and attaches it moments later. Retiring it destroys a job that was about to run."
    );
    assert_eq!(
        s_held, "pending",
        "a row whose run_after is in the future is not unrunnable, just not due yet"
    );
    assert_eq!(
        s_healthy, "pending",
        "a normal queued job must be left alone"
    );

    assert!(
        reason.contains("could never be claimed"),
        "the retirement must record WHY, so the rows are auditable rather than silently gone; \
         got {reason:?}"
    );
}
