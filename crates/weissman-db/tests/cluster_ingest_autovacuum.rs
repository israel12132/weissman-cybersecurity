//! Physical migration must enforce aggressive autovacuum on the cluster ingest
//! outbox. Relied-on-as-runbook notes are not enough — the SET lives in both
//! sqlx trees so every environment (API + worker) inherits it.

const DB_SQL: &str = include_str!("../migrations/20260827190000_cluster_ingest_autovacuum.sql");
const ENGINE_SQL: &str = include_str!(
    "../../../fingerprint_engine/migrations/20260827190000_cluster_ingest_autovacuum.sql"
);

const REQUIRED: &str = "ALTER TABLE weissman_cluster_ingest SET (\n    autovacuum_vacuum_scale_factor = 0.05,\n    autovacuum_vacuum_threshold = 1000";

#[test]
fn cluster_ingest_autovacuum_is_enforced_in_both_sqlx_trees() {
    for (label, sql) in [
        ("crates/weissman-db/migrations", DB_SQL),
        ("fingerprint_engine/migrations", ENGINE_SQL),
    ] {
        assert!(
            sql.contains(REQUIRED),
            "{label}: missing explicit autovacuum SET (scale 0.05 / threshold 1000)\n{sql}"
        );
        assert!(
            sql.contains("autovacuum_vacuum_scale_factor = 0.05"),
            "{label}: missing autovacuum_vacuum_scale_factor = 0.05"
        );
        assert!(
            sql.contains("autovacuum_vacuum_threshold = 1000"),
            "{label}: missing autovacuum_vacuum_threshold = 1000"
        );
    }
    assert_eq!(
        DB_SQL, ENGINE_SQL,
        "cluster-ingest autovacuum migration drifted between sqlx trees"
    );
}
