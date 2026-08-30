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

/// Dedicated connection under `SET ROLE`. Permission errors must not share a
/// transaction with later assertions (25P02 aborted-tx).
async fn conn_as_role(
    pool: &sqlx::PgPool,
    role: &str,
) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query(&format!("SET ROLE {role}"))
        .execute(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("SET ROLE {role}: {e}"));
    conn
}

#[tokio::test]
async fn analytics_role_cannot_read_customer_or_job_tables() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;
    let mut conn = conn_as_role(&pool, "weissman_analytics").await;

    let snap_ok = sqlx::query("SELECT scans_started FROM weissman_billing_usage_snapshot LIMIT 1")
        .fetch_optional(&mut *conn)
        .await;
    assert!(
        snap_ok.is_ok(),
        "analytics must SELECT the billing snapshot: {:?}",
        snap_ok.err()
    );

    let plans_ok = sqlx::query("SELECT slug FROM billing_plans LIMIT 1")
        .fetch_optional(&mut *conn)
        .await;
    assert!(
        plans_ok.is_ok(),
        "analytics must SELECT billing_plans: {:?}",
        plans_ok.err()
    );

    let bypass: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user")
            .fetch_one(&mut *conn)
            .await
            .expect("rolbypassrls");
    assert!(
        bypass,
        "weissman_analytics must BYPASSRLS for global snapshot reads"
    );

    for (sql, label) in [
        ("SELECT 1 FROM vulnerabilities LIMIT 1", "vulnerabilities"),
        ("SELECT 1 FROM weissman_async_jobs LIMIT 1", "the job-bus"),
        ("SELECT 1 FROM agent_anomalies LIMIT 1", "agent_anomalies"),
        (
            "SELECT used FROM weissman_tenant_quota_usage LIMIT 1",
            "raw quota meters",
        ),
        (
            "SELECT scans_started FROM tenant_usage_counters LIMIT 1",
            "raw scan counters",
        ),
        (
            "SELECT total_tokens FROM tenant_llm_usage LIMIT 1",
            "raw LLM meters",
        ),
    ] {
        let err = sqlx::query(sql).fetch_optional(&mut *conn).await;
        assert!(err.is_err(), "analytics must not read {label}");
    }
}

#[tokio::test]
async fn worker_role_cannot_read_vulnerabilities() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;
    let mut conn = conn_as_role(&pool, "weissman_worker").await;

    let jobs_ok = sqlx::query("SELECT 1 FROM weissman_async_jobs LIMIT 1")
        .fetch_optional(&mut *conn)
        .await;
    assert!(
        jobs_ok.is_ok(),
        "worker must SELECT job-bus: {:?}",
        jobs_ok.err()
    );

    let vuln = sqlx::query("SELECT 1 FROM vulnerabilities LIMIT 1")
        .fetch_optional(&mut *conn)
        .await;
    assert!(
        vuln.is_err(),
        "weissman_worker must not read tenant findings"
    );
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

    let cfg: Vec<String> = sqlx::query_scalar(
        "SELECT unnest(rolconfig) FROM pg_roles WHERE rolname = 'weissman_analytics'",
    )
    .fetch_all(&pool)
    .await
    .expect("analytics rolconfig");
    assert!(
        cfg.iter().any(|c| c == "statement_timeout=15s"),
        "weissman_analytics rolconfig must pin 15s timeout, got {cfg:?}"
    );
}
