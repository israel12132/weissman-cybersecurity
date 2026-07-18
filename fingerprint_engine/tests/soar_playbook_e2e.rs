//! SOAR playbook E2E contract: finding → isolate (dry-run) → verify → revert.
//!
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:...@localhost:5432/weissman' \
//! REDIS_URL='redis://127.0.0.1:6379/0' \
//!   cargo test -p fingerprint_engine --test soar_playbook_e2e -- --nocapture
//! ```

use fingerprint_engine::soar::adapters::{self, REGISTERED_ADAPTER_IDS};
use fingerprint_engine::soar::engine::{build_command, execute_armored_action, revert_execution};
use fingerprint_engine::soar::revert::persist_runbook;
use fingerprint_engine::soar::types::{RevertStep, ThreatEvidence};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

fn require_test_database_url() -> String {
    // DB-backed E2E: runs only where a test database is provided — local dev, or a
    // CI job that sets TEST_DATABASE_URL (the engine-wiring job; see ci.yml). The
    // lint/audit job runs `cargo test --workspace` with no database, so skip there
    // instead of hard-failing the whole suite.
    match std::env::var("TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            // In CI (WEISSMAN_REQUIRE_DB_TESTS=1) a missing DB is a hard failure, so a
            // dropped TEST_DATABASE_URL can never masquerade as a green run. Locally it
            // stays a visible skip.
            assert!(
                !std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
                    .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
                    .unwrap_or(false),
                "soar_playbook_e2e requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!("SKIP soar_playbook_e2e: TEST_DATABASE_URL not set");
            String::new()
        }
    }
}

#[test]
fn eight_soar_adapters_registered() {
    assert!(adapters::registered_adapter_count() >= 8);
    for id in [
        "aws_ec2",
        "azure_vm",
        "crowdstrike_falcon",
        "github",
        "pagerduty",
        "opsgenie",
        "slack",
        "servicenow",
    ] {
        assert!(REGISTERED_ADAPTER_IDS.contains(&id), "missing adapter {id}");
    }
}

#[tokio::test]
async fn isolate_dry_run_verify_and_revert_chain() {
    let url = require_test_database_url();
    if url.is_empty() {
        return;
    }

    let pool = match PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url.trim())
        .await
    {
        Ok(p) => p,
        Err(e) => {
            // We only get here when TEST_DATABASE_URL was provided, so a failed
            // connection is a real infra/migration problem, not a skip condition —
            // fail loudly so the DB-enabled CI job can't go green without running.
            panic!("connect TEST_DATABASE_URL failed: {e}");
        }
    };

    let tenant_id: i64 = sqlx::query_scalar("SELECT id FROM tenants ORDER BY id LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("tenant row");

    // Hermetic seed: the SOAR execution row's client_id is a FK to clients(id)
    // (see 20260627150000_soar_action_engine.sql). Seed a real client under this
    // tenant so the dry-run isolate's execution insert resolves — never assume a
    // hard-coded client_id=1 exists. Connected as the superuser test role, so this
    // INSERT is not RLS-gated.
    let client_id: i64 = sqlx::query_scalar(
        "INSERT INTO clients (tenant_id, name) VALUES ($1, $2) RETURNING id",
    )
    .bind(tenant_id)
    .bind("SOAR E2E contract probe client")
    .fetch_one(&pool)
    .await
    .expect("seed probe client");

    let evidence = ThreatEvidence {
        finding_id: Some(1),
        title: "SOAR E2E contract probe".into(),
        severity: "critical".into(),
        source: "soar_e2e".into(),
        target: "i-test123456789".into(),
        cve: None,
        signature_hash: None,
        cvss: Some(9.8),
        epss: Some(0.9),
        kev: true,
        internet_exposed: true,
        trigger_kind: "finding_persisted".into(),
    };

    let cmd = build_command(
        "isolate_host",
        tenant_id,
        Some(client_id),
        None,
        "i-test123456789".into(),
        json!({ "pre_approved": true, "blast_radius_override": true }),
        evidence,
        true,
    );

    let outcome = execute_armored_action(&pool, cmd).await;
    assert_eq!(
        outcome.status, "ok",
        "dry-run isolate should succeed: {}",
        outcome.detail
    );
    let execution_id = outcome
        .execution_id
        .expect("execution_id from dry-run isolate");

    let verify_ok = adapters::verify_probe(
        "tcp_unreachable",
        "192.0.2.1",
        &[443, 22],
        &json!({}),
        "aws_ec2",
    )
    .await
    .expect("verify_probe");
    assert!(verify_ok, "TEST-NET address should appear unreachable");

    let revert_steps = vec![RevertStep {
        provider: "aws_ec2".into(),
        operation: "restore_ec2_security_groups".into(),
        payload: json!({
            "instance_id": "i-test123456789",
            "region": "us-east-1",
        }),
        description: "E2E contract revert step".into(),
    }];
    persist_runbook(
        &pool,
        tenant_id,
        execution_id,
        "isolate_host",
        &revert_steps,
    )
    .await
    .expect("persist revert runbook");

    let revert_detail = revert_execution(&pool, tenant_id, execution_id)
        .await
        .expect("execute revert");
    assert!(
        revert_detail.contains("restore_ec2_security_groups"),
        "revert detail: {revert_detail}"
    );

    let Ok(mut tx) = fingerprint_engine::db::begin_tenant_tx(&pool, tenant_id).await else {
        panic!("tenant tx");
    };
    let status: String =
        sqlx::query_scalar("SELECT status FROM soar_revert_runbooks WHERE execution_id = $1")
            .bind(execution_id)
            .fetch_one(&mut *tx)
            .await
            .expect("revert status");
    let _ = tx.commit().await;
    assert_eq!(status, "reverted");

    let _ = sqlx::query("DELETE FROM soar_revert_runbooks WHERE execution_id = $1")
        .bind(execution_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM soar_action_executions WHERE id = $1")
        .bind(execution_id)
        .execute(&pool)
        .await;
}
