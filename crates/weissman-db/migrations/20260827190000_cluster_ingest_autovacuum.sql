-- Aggressive autovacuum on the cluster-ingest outbox.
-- High INSERT + processed_at UPDATE rate otherwise leaves dead tuples that
-- bloat ix_cluster_ingest_pending and turn SKIP LOCKED claims into an I/O stall.
ALTER TABLE weissman_cluster_ingest SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_scale_factor = 0.05,
    autovacuum_analyze_threshold = 1000,
    autovacuum_vacuum_cost_delay = 2
);
