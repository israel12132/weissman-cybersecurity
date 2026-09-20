//! Live-Postgres test for the per-tenant isolation attestation emitter (Step 17).
//!
//! Builds `weissman_db::isolation_attestation::build_isolation_attestation` against the live
//! migrated schema and asserts it reflects the same DB-enforced isolation posture the Step-1
//! contract test proves — so the exportable attestation and the CI gate cannot diverge.
//!
//! Skips cleanly when `TEST_DATABASE_URL` is unset, unless `WEISSMAN_REQUIRE_DB_TESTS=1`
//! (then a dropped URL hard-fails instead of masquerading as green), mirroring the sibling
//! `rls_live_schema_contract` suite.

use sqlx::postgres::PgPoolOptions;
use weissman_db::isolation_attestation::{build_isolation_attestation, ATTESTATION_SCHEMA_VERSION};

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
                "isolation_attestation_live requires TEST_DATABASE_URL, but WEISSMAN_REQUIRE_DB_TESTS is set"
            );
            eprintln!(
                "SKIP isolation_attestation_live: TEST_DATABASE_URL not set (no test Postgres)"
            );
            String::new()
        }
    }
}

async fn connect(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await
        .expect("connect TEST_DATABASE_URL")
}

#[tokio::test]
async fn isolation_attestation_reflects_live_db_enforced_posture() {
    let url = test_database_url();
    if url.is_empty() {
        return;
    }
    let pool = connect(&url).await;

    let att = build_isolation_attestation(&pool)
        .await
        .expect("build isolation attestation against the live schema");

    assert_eq!(att.schema_version, ATTESTATION_SCHEMA_VERSION);

    // The schema must be migrated — refuse to pass vacuously.
    assert!(
        !att.tenant_tables.is_empty(),
        "no tenant_id tables found — schema not migrated?"
    );
    assert!(
        !att.client_tables.is_empty(),
        "no client_id tables found — schema not migrated?"
    );

    // Every tenant table must ENABLE+FORCE RLS with a tenant-GUC policy and no USING(true)
    // (or be an explicit allowlisted global). This mirrors the Step-1 contract test, now
    // sourced from the emitter so the report and the gate share one truth.
    let tenant_offenders: Vec<&str> = att
        .tenant_tables
        .iter()
        .filter(|t| !t.compliant)
        .map(|t| t.table.as_str())
        .collect();
    assert!(
        tenant_offenders.is_empty(),
        "tenant tables failing the live isolation contract: {tenant_offenders:?}"
    );

    // Every client_id table must carry the customer-visibility predicate (or be allowlisted).
    let client_offenders: Vec<&str> = att
        .client_tables
        .iter()
        .filter(|t| !t.compliant)
        .map(|t| t.table.as_str())
        .collect();
    assert!(
        client_offenders.is_empty(),
        "client_id tables missing the customer-visibility predicate: {client_offenders:?}"
    );

    // No non-app role may carry a default tenant GUC (that would let it read across tenants).
    assert_eq!(
        att.tenant_guc_role_default_count, 0,
        "a non-app role has a default tenant GUC set — cross-tenant read risk"
    );

    // The single verdict must agree with the parts.
    assert!(
        att.compliant,
        "attestation.compliant must be true when every part is compliant"
    );

    // active_tenant_ids() must be callable (SECURITY DEFINER); ids are non-negative.
    for id in &att.active_tenant_ids {
        assert!(*id >= 0, "tenant id should be non-negative: {id}");
    }

    eprintln!(
        "isolation attestation OK: {} tenant tables, {} client tables, {} active tenants, compliant={}",
        att.tenant_tables.len(),
        att.client_tables.len(),
        att.active_tenant_ids.len(),
        att.compliant
    );
}
