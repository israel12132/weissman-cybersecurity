//! Live persist contract for alert-fatigue controls.
//!
//! Requires Postgres with migrations applied:
//! ```text
//! TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/weissman' \
//!   cargo test -p fingerprint_engine --test alert_fatigue_persist_live -- --nocapture --ignored
//! ```
//!
//! Optional `WEISSMAN_LIVE_TENANT_ID` / `WEISSMAN_LIVE_CLIENT_ID` seed the admin
//! tenant so Command Center `/finding-clusters` shows the same rows.

use fingerprint_engine::findings_persist::persist_engine_findings;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use std::time::Duration;

fn db_url() -> Option<String> {
    for key in ["TEST_DATABASE_URL", "WEISSMAN_MIGRATE_URL", "DATABASE_URL"] {
        if let Ok(u) = std::env::var(key) {
            if !u.trim().is_empty() {
                return Some(u);
            }
        }
    }
    None
}

fn finding(title: &str, signature: &str, target: &str, severity: &str) -> serde_json::Value {
    json!({
        "title": title,
        "signature": signature,
        "severity": severity,
        "cwe": "CWE-89",
        "cve": "CVE-2021-1234",
        "target_url": target,
        "description": "alert-fatigue live persist contract",
        "evidence": { "proof": "HTTP 500 + SQL error in response body (live probe)" },
    })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn persist_dedup_auto_suppress_and_cross_plane_critical() {
    let url = db_url().expect("TEST_DATABASE_URL / DATABASE_URL");
    fingerprint_engine::db::run_migrations(url.trim())
        .await
        .expect("migrations");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(10))
        .connect(url.trim())
        .await
        .expect("connect");

    ensure_cluster_ingest_schema(&pool).await;
    let (tenant_id, client_id, seeded) = seed_scope(&pool).await;
    reset_scope(&pool, tenant_id, client_id).await;
    eprintln!("alert-fatigue live: tenant={tenant_id} client={client_id} seeded={seeded}");

    // 1) Network engine, volatile URL (ephemeral port + query).
    let n1 = persist_engine_findings(
        &pool,
        tenant_id,
        Some(client_id),
        "asm",
        "https://app.example.com:54321/login?sid=aaa",
        &[finding(
            "SQL Injection in /login",
            "sqli?sid=aaa",
            "https://app.example.com:54321/login?sid=aaa",
            "medium",
        )],
    )
    .await
    .expect("persist asm #1");
    assert!(n1 >= 1, "asm persist #1 inserted={n1}");

    let row1 = fetch_vuln(&pool, tenant_id, client_id, "asm").await;
    let finding_id = row1.get::<String, _>("finding_id");
    let sig_hash = row1.get::<String, _>("signature_hash");
    let status1 = row1.get::<String, _>("status");
    assert_eq!(status1, "OPEN");
    assert!(
        finding_id.starts_with("asm-"),
        "stable finding_id prefix: {finding_id}"
    );

    // 2) Same vuln, stripped URL — hard de-duplication must upsert, not mint a new row.
    let n2 = persist_engine_findings(
        &pool,
        tenant_id,
        Some(client_id),
        "asm",
        "https://app.example.com/login",
        &[finding(
            "SQL Injection in /login",
            "sqli",
            "https://app.example.com/login",
            "medium",
        )],
    )
    .await
    .expect("persist asm #2");
    assert!(n2 >= 1);

    let asm_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2 AND source = 'asm'
              AND finding_id = $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&finding_id)
    .fetch_one(&pool)
    .await
    .expect("count asm");
    assert_eq!(
        asm_count, 1,
        "ephemeral-port rescan must not create a duplicate"
    );

    let seen: i32 = sqlx::query_scalar(
        r#"SELECT seen_count FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2 AND finding_id = $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&finding_id)
    .fetch_one(&pool)
    .await
    .expect("seen_count");
    assert!(seen >= 2, "rescan should bump seen_count, got {seen}");

    // 3) Agent plane on the same identity — cluster severity jumps to critical.
    let n3 = persist_engine_findings(
        &pool,
        tenant_id,
        Some(client_id),
        "process_inventory",
        "https://app.example.com/login",
        &[finding(
            "SQL Injection in /login",
            "sqli",
            "https://app.example.com/login",
            "medium",
        )],
    )
    .await
    .expect("persist agent");
    assert!(n3 >= 1);

    let cluster = sqlx::query(
        r#"SELECT max_severity, native_severity, watermark_severity, corroboration_boost,
                  engine_planes, member_count
             FROM weissman_finding_clusters
            WHERE tenant_id = $1 AND client_id = $2
              AND cluster_key = $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&sig_hash)
    .fetch_one(&pool)
    .await
    .expect("cluster row");
    let max_sev: String = cluster.get("max_severity");
    let native: String = cluster.get("native_severity");
    let watermark: String = cluster.get("watermark_severity");
    let boost: String = cluster.get("corroboration_boost");
    let planes: Vec<String> = cluster.get("engine_planes");
    eprintln!(
        "cluster max={max_sev} native={native} watermark={watermark} boost={boost} planes={planes:?}"
    );
    assert_eq!(max_sev, "critical", "network+agent must jump to critical");
    assert_eq!(watermark, "critical", "watermark must capture the peak");
    assert_eq!(boost, "cross_plane");
    assert!(planes.iter().any(|p| p == "network"));
    assert!(planes.iter().any(|p| p == "agent"));

    // 4) Auto-suppression: install the 3-FP rule, re-persist, status must be FALSE_POSITIVE
    //    and SOAR must be skipped (raw_data.soar_skipped).
    sqlx::query(
        r#"INSERT INTO finding_suppressions
                 (tenant_id, engine, signature_hash, target_glob, reason, fp_count_at_create, created_at)
           VALUES ($1, 'asm', $2, $3, 'auto:3_fp_marks', 3, now())
           ON CONFLICT (tenant_id, engine, signature_hash, COALESCE(target_glob, ''))
           DO NOTHING"#,
    )
    .bind(tenant_id)
    .bind(&sig_hash)
    .bind("https://app.example.com/login")
    .execute(&pool)
    .await
    .expect("insert suppression");
    fingerprint_engine::fp_feedback::invalidate_suppression_cache(tenant_id, "asm");

    persist_engine_findings(
        &pool,
        tenant_id,
        Some(client_id),
        "asm",
        "https://app.example.com:49152/login?sid=zzz",
        &[finding(
            "SQL Injection in /login",
            "sqli?sid=zzz",
            "https://app.example.com:49152/login?sid=zzz",
            "medium",
        )],
    )
    .await
    .expect("persist auto-suppressed");

    let suppressed = fetch_vuln(&pool, tenant_id, client_id, "asm").await;
    let status_fp: String = suppressed.get("status");
    let raw: serde_json::Value = suppressed.get("raw_data");
    assert_eq!(status_fp, "FALSE_POSITIVE");
    assert_eq!(
        raw.get("auto_suppressed").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        raw.get("soar_skipped").and_then(|v| v.as_bool()),
        Some(true)
    );

    let after_fp = sqlx::query(
        r#"SELECT max_severity, watermark_severity, native_severity
             FROM weissman_finding_clusters
            WHERE tenant_id = $1 AND client_id = $2 AND cluster_key = $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&sig_hash)
    .fetch_one(&pool)
    .await
    .expect("cluster after FP");
    let max_after: String = after_fp.get("max_severity");
    let water_after: String = after_fp.get("watermark_severity");
    assert_eq!(
        max_after, "critical",
        "inbox severity must not yo-yo after auto-suppression"
    );
    assert_eq!(water_after, "critical");

    // 5) Route-template: public image vs admin billing must never share a cluster.
    persist_engine_findings(
        &pool,
        tenant_id,
        Some(client_id),
        "asm",
        "https://api.corp/api/v1/public/image/6c084089-0aec",
        &[finding(
            "XSS in public image",
            "xss",
            "https://api.corp/api/v1/public/image/6c084089-0aec",
            "low",
        )],
    )
    .await
    .expect("persist public image");
    persist_engine_findings(
        &pool,
        tenant_id,
        Some(client_id),
        "asm",
        "https://api.corp/api/v1/admin/billing/6c084089-0aec",
        &[finding(
            "XSS in admin billing",
            "xss",
            "https://api.corp/api/v1/admin/billing/6c084089-0aec",
            "critical",
        )],
    )
    .await
    .expect("persist admin billing");

    let public_key = fingerprint_engine::finding_identity::build_cluster_key(
        "https://api.corp/api/v1/public/image/6c084089-0aec",
        "xss",
        "CWE-89",
    );
    let admin_key = fingerprint_engine::finding_identity::build_cluster_key(
        "https://api.corp/api/v1/admin/billing/6c084089-0aec",
        "xss",
        "CWE-89",
    );
    assert_ne!(public_key, admin_key);
    let keys: Vec<String> = sqlx::query_scalar(
        r#"SELECT cluster_key FROM weissman_finding_clusters
            WHERE tenant_id = $1 AND client_id = $2
              AND cluster_key IN ($3, $4)
            ORDER BY cluster_key"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&public_key)
    .bind(&admin_key)
    .fetch_all(&pool)
    .await
    .expect("route-template clusters");
    assert_eq!(
        keys.len(),
        2,
        "public image and admin billing must be distinct clusters, got {keys:?}"
    );

    // High-cardinality escapes: emails and filenames share one identity.
    persist_engine_findings(
        &pool,
        tenant_id,
        Some(client_id),
        "leak_hunter",
        "https://api.corp/inbox/alice@corp.com",
        &[
            finding(
                "Open redirect",
                "open_redirect",
                "https://api.corp/inbox/alice@corp.com",
                "medium",
            ),
            finding(
                "Open redirect",
                "open_redirect",
                "https://api.corp/inbox/bob@corp.com",
                "medium",
            ),
            finding(
                "Open redirect",
                "open_redirect",
                "https://api.corp/inbox/invoice_august_2026.pdf",
                "medium",
            ),
        ],
    )
    .await
    .expect("persist high-card targets");
    let email_ids: Vec<String> = sqlx::query_scalar(
        r#"SELECT DISTINCT finding_id FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2 AND source = 'leak_hunter'"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&pool)
    .await
    .expect("high-card finding_ids");
    assert_eq!(
        email_ids.len(),
        1,
        "email + filename targets must share one finding_id, got {email_ids:?}"
    );

    // VERIFIED_FIXED resets the watermark; a later low regression must not stay Critical.
    let login_key = sig_hash.clone();
    sqlx::query(
        r#"UPDATE weissman_finding_clusters
              SET status = 'VERIFIED_FIXED',
                  watermark_severity = 'info',
                  max_severity = 'info',
                  native_severity = 'info',
                  corroboration_boost = 'none'
            WHERE tenant_id = $1 AND client_id = $2 AND cluster_key = $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&login_key)
    .execute(&pool)
    .await
    .expect("close cluster lifecycle");
    persist_engine_findings(
        &pool,
        tenant_id,
        Some(client_id),
        "asm",
        "https://app.example.com/login",
        &[finding(
            "SQL Injection in /login",
            "sqli",
            "https://app.example.com/login",
            "low",
        )],
    )
    .await
    .expect("persist regression");
    let wm: String = sqlx::query_scalar(
        r#"SELECT watermark_severity FROM weissman_finding_clusters
            WHERE tenant_id = $1 AND client_id = $2 AND cluster_key = $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&login_key)
    .fetch_one(&pool)
    .await
    .expect("regression watermark");
    assert_ne!(
        wm.to_ascii_lowercase(),
        "critical",
        "zombie watermark after VERIFIED_FIXED: {wm}"
    );

    let relopts: Option<Vec<String>> = sqlx::query_scalar(
        "SELECT reloptions FROM pg_class WHERE relname = 'weissman_cluster_ingest'",
    )
    .fetch_optional(&pool)
    .await
    .expect("reloptions");
    let joined = relopts.unwrap_or_default().join(",");
    assert!(
        joined.contains("autovacuum_vacuum_scale_factor=0.05")
            || joined.contains("autovacuum_vacuum_scale_factor"),
        "ingest autovacuum not set: {joined}"
    );

    eprintln!("alert-fatigue live contract OK finding_id={finding_id}");
}

/// Cold-start: after a reboot the in-memory trie is empty. Pre-warming from
/// persisted cluster/finding targets must collapse the next sibling onto the
/// existing `{id}` identity instead of minting `/users/carol` as a new finding.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn cold_start_prewarm_collapses_next_sibling() {
    let url = db_url().expect("TEST_DATABASE_URL / DATABASE_URL");
    fingerprint_engine::db::run_migrations(url.trim())
        .await
        .expect("migrations");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(10))
        .connect(url.trim())
        .await
        .expect("connect");

    ensure_cluster_ingest_schema(&pool).await;
    let (tenant_id, client_id, _) = seed_scope(&pool).await;
    reset_scope(&pool, tenant_id, client_id).await;
    fingerprint_engine::path_templates::invalidate_tenant(tenant_id);

    let alice = "https://api.corp/api/v1/users/alice_prewarm";
    let bob = "https://api.corp/api/v1/users/bob_prewarm";
    let carol = "https://api.corp/api/v1/users/carol_prewarm";
    persist_engine_findings(
        &pool,
        tenant_id,
        Some(client_id),
        "asm",
        alice,
        &[
            finding("XSS in user profile (prewarm)", "xss-prewarm", alice, "low"),
            finding("XSS in user profile (prewarm)", "xss-prewarm", bob, "low"),
        ],
    )
    .await
    .expect("persist alice+bob");

    let before: String = sqlx::query_scalar(
        r#"SELECT finding_id FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2 AND source = 'asm'
              AND title = 'XSS in user profile (prewarm)'
            ORDER BY id LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_one(&pool)
    .await
    .expect("alice/bob finding_id");

    fingerprint_engine::path_templates::invalidate_tenant(tenant_id);
    fingerprint_engine::path_templates::prewarm_all_tenants(&pool).await;

    persist_engine_findings(
        &pool,
        tenant_id,
        Some(client_id),
        "asm",
        carol,
        &[finding(
            "XSS in user profile (prewarm)",
            "xss-prewarm",
            carol,
            "low",
        )],
    )
    .await
    .expect("persist carol after pre-warm");

    let rows: Vec<(String, i32)> = sqlx::query_as(
        r#"SELECT finding_id, seen_count FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2 AND source = 'asm'
              AND title = 'XSS in user profile (prewarm)'"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&pool)
    .await
    .expect("prewarm identities");
    assert_eq!(
        rows.len(),
        1,
        "carol must not mint a new finding_id after trie pre-warm, got {rows:?}"
    );
    assert_eq!(rows[0].0, before);
    assert!(
        rows[0].1 >= 2,
        "carol must upsert the existing identity, seen_count={}",
        rows[0].1
    );
    eprintln!("cold-start prewarm OK finding_id={}", rows[0].0);
}

async fn ensure_cluster_ingest_schema(pool: &sqlx::PgPool) {
    let sql = include_str!(
        "../../crates/weissman-db/migrations/20260827173000_cluster_ingest_watermark.sql"
    );
    sqlx::raw_sql(sql)
        .execute(pool)
        .await
        .expect("apply cluster ingest + watermark schema");
    let av = include_str!(
        "../../crates/weissman-db/migrations/20260827190000_cluster_ingest_autovacuum.sql"
    );
    sqlx::raw_sql(av)
        .execute(pool)
        .await
        .expect("apply cluster ingest autovacuum");
}

async fn seed_scope(pool: &sqlx::PgPool) -> (i64, i64, bool) {
    if let (Ok(t), Ok(c)) = (
        std::env::var("WEISSMAN_LIVE_TENANT_ID"),
        std::env::var("WEISSMAN_LIVE_CLIENT_ID"),
    ) {
        if let (Ok(tid), Ok(cid)) = (t.parse::<i64>(), c.parse::<i64>()) {
            return (tid, cid, false);
        }
    }

    let slug = "__alert_fatigue_live__";
    let tenant_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO tenants (slug, name) VALUES ($1, 'alert fatigue live')
           ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id"#,
    )
    .bind(slug)
    .fetch_one(pool)
    .await
    .expect("seed tenant");

    sqlx::query("DELETE FROM vulnerabilities WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM weissman_finding_clusters WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM finding_suppressions WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM clients WHERE tenant_id = $1 AND name = $2")
        .bind(tenant_id)
        .bind("alert-fatigue-client")
        .execute(pool)
        .await
        .ok();

    let client_id: i64 =
        sqlx::query_scalar(r#"INSERT INTO clients (tenant_id, name) VALUES ($1, $2) RETURNING id"#)
            .bind(tenant_id)
            .bind("alert-fatigue-client")
            .fetch_one(pool)
            .await
            .expect("seed client");
    (tenant_id, client_id, true)
}

async fn reset_scope(pool: &sqlx::PgPool, tenant_id: i64, client_id: i64) {
    let _ =
        sqlx::query("DELETE FROM weissman_cluster_ingest WHERE tenant_id = $1 AND client_id = $2")
            .bind(tenant_id)
            .bind(client_id)
            .execute(pool)
            .await;
    let _ = sqlx::query("DELETE FROM vulnerabilities WHERE tenant_id = $1 AND client_id = $2")
        .bind(tenant_id)
        .bind(client_id)
        .execute(pool)
        .await;
    let _ = sqlx::query(
        "DELETE FROM weissman_finding_clusters WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind(tenant_id)
    .bind(client_id)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM finding_suppressions WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    fingerprint_engine::fp_feedback::invalidate_suppression_cache_tenant(tenant_id);
    fingerprint_engine::path_templates::invalidate_tenant(tenant_id);
}

async fn fetch_vuln(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    engine: &str,
) -> sqlx::postgres::PgRow {
    sqlx::query(
        r#"SELECT finding_id, signature_hash, status, seen_count, raw_data
             FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2 AND source = $3
            ORDER BY id DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(engine)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("fetch vuln for {engine}: {e}"))
}
