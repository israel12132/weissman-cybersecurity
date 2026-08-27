//! Live Postgres binary COPY of `agent_metric_samples`.
//!
//! ```text
//! TEST_DATABASE_URL='postgres://weissman_app:…@127.0.0.1:5432/weissman' \
//!   cargo test -p fingerprint_engine --test postgres_bulk_copy_integration -- --nocapture
//! ```
//! Skips (not fails) when TEST_DATABASE_URL is unset, unless WEISSMAN_REQUIRE_DB_TESTS=1.

use chrono::Utc;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use weissman_db::pg_binary_copy::{
    agent_metric_samples_copy_sql, assert_agent_metric_samples_schema, encode_agent_metric_sample,
    PgBinaryCopyBuf,
};

fn test_db_url() -> String {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            assert!(
                !std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
                    .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
                    .unwrap_or(false),
                "postgres_bulk_copy_integration requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP postgres_bulk_copy_integration: TEST_DATABASE_URL not set");
            String::new()
        }
    }
}

async fn pool() -> Option<PgPool> {
    let url = test_db_url();
    if url.is_empty() {
        return None;
    }
    Some(
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("connect TEST_DATABASE_URL"),
    )
}

#[tokio::test]
async fn binary_copy_roundtrips_one_agent_metric_sample() {
    let Some(pool) = pool().await else { return };

    let mut tx = match fingerprint_engine::db::begin_tenant_tx(&pool, 1).await {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("SKIP: begin_tenant_tx tenant=1 failed: {e}");
            return;
        }
    };
    let client_id: Option<i64> = sqlx::query_scalar("SELECT id FROM clients LIMIT 1")
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let Some(client_id) = client_id else {
        let _ = tx.rollback().await;
        eprintln!("SKIP: no clients row visible under tenant_id=1");
        return;
    };

    assert_agent_metric_samples_schema(&mut *tx)
        .await
        .expect("schema contract must match live catalog");

    let id: i64 = sqlx::query_scalar("SELECT nextval('agent_metric_samples_id_seq')")
        .fetch_one(&mut *tx)
        .await
        .expect("nextval");

    let metrics = json!({"open_port_count": 3, "process_count": 12});
    let sampled_at = Utc::now();
    let marker = format!("copy-itest-{id}");
    let mut buf = PgBinaryCopyBuf::new();
    encode_agent_metric_sample(
        &mut buf,
        id,
        1,
        &marker,
        client_id,
        sampled_at.timestamp_micros(),
        16,
        &metrics,
        64,
    );
    let binary = buf.finish();

    let mut writer = tx
        .copy_in_raw(agent_metric_samples_copy_sql())
        .await
        .expect("copy_in_raw");
    writer.send(&binary).await.expect("copy send");
    let copied = writer.finish().await.expect("copy finish");
    assert_eq!(copied, 1, "COPY should insert exactly one row");

    let row: (i64, String, i16, serde_json::Value, i32) = sqlx::query_as(
        r#"SELECT id, agent_id, hour_of_week, metrics, raw_size_bytes
             FROM agent_metric_samples WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .expect("select copied row");
    assert_eq!(row.0, id);
    assert_eq!(row.1, marker);
    assert_eq!(row.2, 16);
    assert_eq!(row.3["open_port_count"], 3);
    assert_eq!(row.4, 64);

    sqlx::query("DELETE FROM agent_metric_samples WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .expect("cleanup");
    tx.commit().await.expect("commit");
}

/// A finished COPY inside an uncommitted transaction must disappear on rollback.
/// This is the atomicity contract: a mid-stream disconnect must not leave rows.
#[tokio::test]
async fn binary_copy_rollback_drops_the_batch() {
    let Some(pool) = pool().await else { return };

    let mut tx = match fingerprint_engine::db::begin_tenant_tx(&pool, 1).await {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("SKIP: begin_tenant_tx tenant=1 failed: {e}");
            return;
        }
    };
    let client_id: Option<i64> = sqlx::query_scalar("SELECT id FROM clients LIMIT 1")
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let Some(client_id) = client_id else {
        let _ = tx.rollback().await;
        eprintln!("SKIP: no clients row visible under tenant_id=1");
        return;
    };

    let id: i64 = sqlx::query_scalar("SELECT nextval('agent_metric_samples_id_seq')")
        .fetch_one(&mut *tx)
        .await
        .expect("nextval");
    let marker = format!("copy-rollback-{id}");
    let mut buf = PgBinaryCopyBuf::new();
    encode_agent_metric_sample(
        &mut buf,
        id,
        1,
        &marker,
        client_id,
        Utc::now().timestamp_micros(),
        3,
        &json!({"open_port_count": 1}),
        8,
    );
    let binary = buf.finish();

    let mut writer = tx
        .copy_in_raw(agent_metric_samples_copy_sql())
        .await
        .expect("copy_in_raw");
    writer.send(&binary).await.expect("copy send");
    let copied = writer.finish().await.expect("copy finish");
    assert_eq!(copied, 1);

    let visible: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM agent_metric_samples WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .expect("select in-tx");
    assert_eq!(visible, Some(id), "row must be visible inside the open tx");

    tx.rollback().await.expect("rollback");

    let mut check = match fingerprint_engine::db::begin_tenant_tx(&pool, 1).await {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("SKIP: begin_tenant_tx after rollback failed: {e}");
            return;
        }
    };
    let leftover: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM agent_metric_samples WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *check)
    .await
    .expect("select after rollback");
    let _ = check.rollback().await;
    assert!(
        leftover.is_none(),
        "rolled-back COPY must not leave a committed row"
    );
}

/// abort() mid-stream must not commit a partial tuple.
#[tokio::test]
async fn binary_copy_abort_leaves_no_row() {
    let Some(pool) = pool().await else { return };

    let mut tx = match fingerprint_engine::db::begin_tenant_tx(&pool, 1).await {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("SKIP: begin_tenant_tx tenant=1 failed: {e}");
            return;
        }
    };
    let client_id: Option<i64> = sqlx::query_scalar("SELECT id FROM clients LIMIT 1")
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    let Some(client_id) = client_id else {
        let _ = tx.rollback().await;
        eprintln!("SKIP: no clients row visible under tenant_id=1");
        return;
    };

    let id: i64 = sqlx::query_scalar("SELECT nextval('agent_metric_samples_id_seq')")
        .fetch_one(&mut *tx)
        .await
        .expect("nextval");
    let marker = format!("copy-abort-{id}");
    let mut buf = PgBinaryCopyBuf::new();
    encode_agent_metric_sample(
        &mut buf,
        id,
        1,
        &marker,
        client_id,
        Utc::now().timestamp_micros(),
        4,
        &json!({"open_port_count": 2}),
        8,
    );
    let binary = buf.finish();

    let mut writer = tx
        .copy_in_raw(agent_metric_samples_copy_sql())
        .await
        .expect("copy_in_raw");
    writer.send(&binary).await.expect("copy send");
    let _ = writer.abort("integration-test abort").await;
    tx.rollback().await.expect("rollback after abort");

    let mut check = match fingerprint_engine::db::begin_tenant_tx(&pool, 1).await {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("SKIP: begin_tenant_tx after abort failed: {e}");
            return;
        }
    };
    let leftover: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM agent_metric_samples WHERE agent_id = $1",
    )
    .bind(&marker)
    .fetch_optional(&mut *check)
    .await
    .expect("select after abort");
    let _ = check.rollback().await;
    assert!(leftover.is_none(), "aborted COPY must not persist the sample");
}
