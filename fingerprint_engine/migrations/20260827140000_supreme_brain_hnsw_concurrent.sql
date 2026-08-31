-- weissman:no-transaction
--
-- Rebuild HNSW (m=16, ef_construction=64) without AccessExclusiveLock.
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction — the sqlx
-- pre-runner (crates/weissman-db/src/no_tx_migrations.rs) executes this
-- file statement-by-statement on a bare connection.
--
-- Order is mandatory: build the new index first, drop the old name only
-- after the replacement is live. Re-runs are idempotent.

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_supreme_council_mem_embedding_hnsw_m16
    ON supreme_council_memory
    USING hnsw (embedding_vec vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_pwp_embedding_hnsw_m16
    ON pentest_winning_paths
    USING hnsw (target_embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64)
    WHERE target_embedding IS NOT NULL;

DROP INDEX CONCURRENTLY IF EXISTS ix_supreme_council_mem_embedding_hnsw;
DROP INDEX CONCURRENTLY IF EXISTS ix_pwp_embedding_hnsw;
