//! Least-privilege lock-in for `weissman_analytics` and `weissman_worker`.

use sqlx::postgres::PgPoolOptions;

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
                "analytics_worker_roles requires TEST_DATABASE_URL"
            );
            eprintln!("SKIP analytics_worker_roles: TEST_DATABASE_URL not set");
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

#[tokio::test]
async fn analytics_role_cannot_read_customer_or_job_tables() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;

    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL ROLE weissman_analytics")
        .execute(&mut *tx)
        .await
        .expect("SET ROLE weissman_analytics");

    let quota_ok = sqlx::query("SELECT used FROM weissman_tenant_quota_usage LIMIT 1")
        .fetch_optional(&mut *tx)
        .await;
    assert!(
        quota_ok.is_ok(),
        "analytics must SELECT quota metrics: {:?}",
        quota_ok.err()
    );

    let vuln = sqlx::query("SELECT 1 FROM vulnerabilities LIMIT 1")
        .fetch_optional(&mut *tx)
        .await;
    assert!(vuln.is_err(), "analytics must not read vulnerabilities");

    let jobs = sqlx::query("SELECT 1 FROM weissman_async_jobs LIMIT 1")
        .fetch_optional(&mut *tx)
        .await;
    assert!(jobs.is_err(), "analytics must not read the job-bus");

    let anom = sqlx::query("SELECT 1 FROM agent_anomalies LIMIT 1")
        .fetch_optional(&mut *tx)
        .await;
    assert!(anom.is_err(), "analytics must not read agent_anomalies");

    let bypass: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user")
            .fetch_one(&mut *tx)
            .await
            .expect("rolbypassrls");
    assert!(
        bypass,
        "weissman_analytics must BYPASSRLS for global aggregates"
    );
    let _ = tx.rollback().await;
}

#[tokio::test]
async fn worker_role_cannot_read_vulnerabilities() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;

    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL ROLE weissman_worker")
        .execute(&mut *tx)
        .await
        .expect("SET ROLE weissman_worker");

    let jobs_ok = sqlx::query("SELECT 1 FROM weissman_async_jobs LIMIT 1")
        .fetch_optional(&mut *tx)
        .await;
    assert!(
        jobs_ok.is_ok(),
        "worker must SELECT job-bus: {:?}",
        jobs_ok.err()
    );

    let vuln = sqlx::query("SELECT 1 FROM vulnerabilities LIMIT 1")
        .fetch_optional(&mut *tx)
        .await;
    assert!(
        vuln.is_err(),
        "weissman_worker must not read tenant findings"
    );
    let _ = tx.rollback().await;
}

#[tokio::test]
async fn roles_exist_with_expected_bypass_flags() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;
    let rows: Vec<(String, bool, bool)> = sqlx::query_as(
        r#"SELECT rolname::text, rolbypassrls, rolsuper
           FROM pg_roles
           WHERE rolname IN ('weissman_analytics', 'weissman_worker', 'weissman_app')
           ORDER BY 1"#,
    )
    .fetch_all(&pool)
    .await
    .expect("pg_roles");
    let map: std::collections::HashMap<_, _> =
        rows.into_iter().map(|(n, b, s)| (n, (b, s))).collect();
    assert_eq!(map.get("weissman_app"), Some(&(false, false)));
    assert_eq!(map.get("weissman_analytics"), Some(&(true, false)));
    assert_eq!(map.get("weissman_worker"), Some(&(true, false)));
}
