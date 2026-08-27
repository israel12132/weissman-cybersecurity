//! Default scan target contract: bound client + empty target uses Client Configuration
//! (then Asset Snapshot); no domain/asset → structured `no_default_scan_target`; spoofed
//! hosts for another org are rejected.
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p fingerprint_engine --test default_scan_target -- --nocapture
//! ```

use fingerprint_engine::auth_jwt::AuthContext;
use fingerprint_engine::client_isolation;
use fingerprint_engine::client_scan_target::{ERROR_CODE_NO_DEFAULT, ERROR_CODE_OUT_OF_SCOPE};
use fingerprint_engine::scan_routing::{route_scan_job, RouteError};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

fn test_db_url() -> String {
    match std::env::var("TEST_DATABASE_URL")
        .ok()
        .or_else(|| std::env::var("DATABASE_URL").ok())
    {
        Some(u) if !u.trim().is_empty() => u,
        _ => {
            assert!(
                !std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
                    .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
                    .unwrap_or(false),
                "default_scan_target requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP default_scan_target: TEST_DATABASE_URL not set");
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
            .connect(url.trim())
            .await
            .expect("connect TEST_DATABASE_URL"),
    )
}

async fn tenant_id(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT id FROM tenants WHERE id > 0 ORDER BY id LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("tenant row")
}

async fn insert_client(pool: &PgPool, tenant_id: i64, domains_json: &str) -> i64 {
    let name = format!("dst-{}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO clients (tenant_id, name, domains) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(tenant_id)
    .bind(&name)
    .bind(domains_json)
    .fetch_one(pool)
    .await
    .expect("insert client")
}

async fn cleanup_client(pool: &PgPool, tenant_id: i64, client_id: i64) {
    let _ = sqlx::query(
        "DELETE FROM weissman_async_jobs WHERE tenant_id = $1 AND payload->>'client_id' = $2",
    )
    .bind(tenant_id)
    .bind(client_id.to_string())
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM asm_graph_nodes WHERE tenant_id = $1 AND client_id = $2")
        .bind(tenant_id)
        .bind(client_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM clients WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(client_id)
        .execute(pool)
        .await;
}

fn scoped_auth(tenant_id: i64, client_id: i64) -> AuthContext {
    AuthContext {
        user_id: 1,
        tenant_id,
        role: "client".into(),
        is_superadmin: false,
        agent_id: None,
        jti: None,
        bind_ip: None,
        bind_tls_fp: None,
        assigned_client_id: Some(client_id),
    }
}

#[tokio::test]
async fn scoped_user_empty_target_uses_example_com() {
    let Some(pool) = pool().await else { return };
    let tenant_id = tenant_id(&pool).await;
    let client_id = insert_client(&pool, tenant_id, r#"["example.com"]"#).await;

    let mut body = json!({ "engine": "leak_hunter" });
    client_isolation::force_json_client_id(&scoped_auth(tenant_id, client_id), &mut body)
        .expect("stamp client_id");
    assert!(body.get("target").is_none());
    assert_eq!(
        body.get("client_id").and_then(Value::as_i64),
        Some(client_id)
    );

    let result = route_scan_job(&body, tenant_id, &pool).await;
    let (kind, payload) = match result {
        Ok(v) => v,
        Err(e) => {
            cleanup_client(&pool, tenant_id, client_id).await;
            panic!("expected job, got {}: {}", e.error_code(), e.detail());
        }
    };

    let target = payload.get("target").and_then(Value::as_str).unwrap_or("");
    assert!(
        target.contains("example.com"),
        "default target should be example.com, got {target:?}"
    );
    assert_eq!(
        payload.get("target_source").and_then(Value::as_str),
        Some("client_primary_domain")
    );
    assert_eq!(kind, "command_center_engine");

    let job_id = fingerprint_engine::async_jobs::enqueue(
        &pool,
        tenant_id,
        kind.as_str(),
        payload.clone(),
        None,
    )
    .await
    .expect("enqueue");
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT payload->>'target' FROM weissman_async_jobs WHERE id = $1 AND tenant_id = $2",
    )
    .bind(job_id)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await
    .expect("read job");
    assert!(
        stored.as_deref().is_some_and(|t| t.contains("example.com")),
        "stored job target {stored:?}"
    );

    cleanup_client(&pool, tenant_id, client_id).await;
}

#[tokio::test]
async fn no_domains_returns_structured_no_default_scan_target() {
    let Some(pool) = pool().await else { return };
    let tenant_id = tenant_id(&pool).await;
    let client_id = insert_client(&pool, tenant_id, "[]").await;

    let err = route_scan_job(
        &json!({ "engine": "leak_hunter", "client_id": client_id }),
        tenant_id,
        &pool,
    )
    .await
    .expect_err("empty client must fail closed");

    match err {
        RouteError::NoDefaultScanTarget { ref detail } => {
            assert!(detail.to_ascii_lowercase().contains("domain"));
        }
        other => {
            cleanup_client(&pool, tenant_id, client_id).await;
            panic!(
                "expected NoDefaultScanTarget, got {} ({})",
                other.error_code(),
                other.detail()
            );
        }
    }
    let body = err.json_body();
    assert_eq!(body["error_code"], json!(ERROR_CODE_NO_DEFAULT));
    assert_eq!(body["code"], json!(ERROR_CODE_NO_DEFAULT));
    assert_eq!(body["ok"], json!(false));
    assert_eq!(body["action"], json!("add_client_domain"));

    cleanup_client(&pool, tenant_id, client_id).await;
}

#[tokio::test]
async fn spoofed_foreign_org_target_is_rejected() {
    let Some(pool) = pool().await else { return };
    let tenant_id = tenant_id(&pool).await;
    let client_id = insert_client(&pool, tenant_id, r#"["example.com"]"#).await;

    let err = route_scan_job(
        &json!({
            "engine": "leak_hunter",
            "client_id": client_id,
            "target": "https://example.net"
        }),
        tenant_id,
        &pool,
    )
    .await
    .expect_err("foreign host must be rejected");

    assert_eq!(err.error_code(), ERROR_CODE_OUT_OF_SCOPE);
    assert!(
        err.detail().contains("example.net"),
        "detail should name the spoofed host: {}",
        err.detail()
    );
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);

    cleanup_client(&pool, tenant_id, client_id).await;
}

#[tokio::test]
async fn object_shaped_domain_is_a_valid_primary() {
    let Some(pool) = pool().await else { return };
    let tenant_id = tenant_id(&pool).await;
    let client_id = insert_client(
        &pool,
        tenant_id,
        r#"[{"domain":"example.com","verified":true,"primary":true}]"#,
    )
    .await;

    let (_, payload) = route_scan_job(
        &json!({ "engine": "osint", "client_id": client_id }),
        tenant_id,
        &pool,
    )
    .await
    .expect("object domain should fill default");
    assert!(payload
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("")
        .contains("example.com"));

    cleanup_client(&pool, tenant_id, client_id).await;
}

#[tokio::test]
async fn verified_asset_fills_when_domains_empty() {
    let Some(pool) = pool().await else { return };
    let tenant_id = tenant_id(&pool).await;
    let client_id = insert_client(&pool, tenant_id, "[]").await;
    let run_id: i64 = sqlx::query_scalar(
        "INSERT INTO report_runs (tenant_id, findings_json, summary) VALUES ($1, '[]', '{}') RETURNING id",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("report_runs");
    sqlx::query(
        r#"INSERT INTO asm_graph_nodes
            (tenant_id, run_id, client_id, node_id, label, node_type, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(tenant_id)
    .bind(run_id)
    .bind(client_id)
    .bind("asm:root:example.com")
    .bind("example.com")
    .bind("root")
    .bind("verified")
    .execute(&pool)
    .await
    .expect("asm node");

    let result = route_scan_job(
        &json!({ "engine": "leak_hunter", "client_id": client_id }),
        tenant_id,
        &pool,
    )
    .await;

    let _ = sqlx::query("DELETE FROM asm_graph_nodes WHERE run_id = $1")
        .bind(run_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM report_runs WHERE id = $1")
        .bind(run_id)
        .execute(&pool)
        .await;
    cleanup_client(&pool, tenant_id, client_id).await;

    let (_, payload) = result.expect("verified asset should become default target");
    assert!(
        payload
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("example.com"),
        "payload {payload}"
    );
    assert_eq!(
        payload.get("target_source").and_then(Value::as_str),
        Some("client_verified_asset")
    );
}
