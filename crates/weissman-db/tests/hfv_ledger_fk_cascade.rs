//! HFV ledger is append-only for application DML, but client/tenant DELETE
//! must still CASCADE (offboarding + cargo-test cleanup).
//!
//! # Running
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p weissman-db --test hfv_ledger_fk_cascade -- --nocapture
//! ```

use sqlx::postgres::PgPoolOptions;

const SLUG: &str = "__hfv_ledger_cascade_tenant__";
const CLIENT: &str = "__hfv_ledger_cascade_client__";

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
                "hfv_ledger_fk_cascade requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP hfv_ledger_fk_cascade: TEST_DATABASE_URL not set (no test Postgres)");
            String::new()
        }
    }
}

async fn connect(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await
        .expect("connect TEST_DATABASE_URL")
}

/// Seed a tenant + client + report_run + vulnerability. The AFTER INSERT trigger
/// on `vulnerabilities` appends the OPENED ledger row.
async fn seed_finding(pool: &sqlx::PgPool) -> (i64, i64, i64) {
    sqlx::query("DELETE FROM clients WHERE name = $1")
        .bind(CLIENT)
        .execute(pool)
        .await
        .expect("delete leftover cascade-probe client");
    sqlx::query(
        r#"INSERT INTO tenants (slug, name) VALUES ($1, 'hfv ledger cascade')
           ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name"#,
    )
    .bind(SLUG)
    .execute(pool)
    .await
    .expect("seed tenant");
    let tenant_id: i64 = sqlx::query_scalar("SELECT id FROM tenants WHERE slug = $1")
        .bind(SLUG)
        .fetch_one(pool)
        .await
        .expect("tenant id");
    let client_id: i64 =
        sqlx::query_scalar("INSERT INTO clients (tenant_id, name) VALUES ($1, $2) RETURNING id")
            .bind(tenant_id)
            .bind(CLIENT)
            .fetch_one(pool)
            .await
            .expect("client id");
    let run_id: i64 = sqlx::query_scalar(
        "INSERT INTO report_runs (tenant_id, findings_json, summary) VALUES ($1, '[]', '{}') RETURNING id",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .expect("run id");
    let vuln_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO vulnerabilities
             (run_id, tenant_id, client_id, finding_id, title, severity, source, status)
           VALUES ($1, $2, $3, 'hfv-cascade-probe', 'cascade probe', 'info', 'hfv_cascade_probe', 'OPEN')
           RETURNING id"#,
    )
    .bind(run_id)
    .bind(tenant_id)
    .bind(client_id)
    .fetch_one(pool)
    .await
    .expect("vuln id");
    (tenant_id, client_id, vuln_id)
}

#[tokio::test]
async fn client_delete_cascades_ledger_but_direct_delete_is_blocked() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;
    let (_tenant_id, client_id, _vuln_id) = seed_finding(&pool).await;

    let ledger: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM vulnerability_lifecycle_events WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_one(&pool)
    .await
    .expect("count ledger");
    assert!(
        ledger >= 1,
        "AFTER INSERT trigger must append an OPENED ledger row; got {ledger}"
    );

    let direct = sqlx::query("DELETE FROM vulnerability_lifecycle_events WHERE client_id = $1")
        .bind(client_id)
        .execute(&pool)
        .await;
    assert!(
        direct.is_err(),
        "direct DELETE on the ledger must raise append-only, got {direct:?}"
    );

    sqlx::query("DELETE FROM clients WHERE id = $1")
        .bind(client_id)
        .execute(&pool)
        .await
        .expect("DELETE FROM clients must CASCADE ledger rows (FK nested trigger depth)");

    let leftover_client: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM clients WHERE id = $1")
            .bind(client_id)
            .fetch_one(&pool)
            .await
            .expect("count client");
    let leftover_ledger: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM vulnerability_lifecycle_events WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_one(&pool)
    .await
    .expect("count leftover ledger");
    assert_eq!(leftover_client, 0, "client row must be gone");
    assert_eq!(
        leftover_ledger, 0,
        "ledger rows must cascade away with the client"
    );
}
