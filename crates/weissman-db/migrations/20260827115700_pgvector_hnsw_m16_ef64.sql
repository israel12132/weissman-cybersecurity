-- weissman:no-transaction
--
-- ⚠ DO NOT REMOVE THE FIRST-LINE DIRECTIVE ABOVE.
-- CREATE/DROP INDEX CONCURRENTLY cannot run inside SQLx's BEGIN/COMMIT wrapper.
--
-- Rebuild pgvector HNSW indexes on Supreme Council memory and pentest winning-path
-- tables with explicit build parameters:
--   m               = 16   (graph degree — recall vs. index size)
--   ef_construction = 64   (build-time candidate list — recall vs. build time)
--
-- These are pgvector's documented balanced defaults; older CREATE INDEX statements
-- omitted WITH (...), so operators could not audit the live reloptions. Rebuilding
-- once with the clause frozen in SQL makes the recall/latency contract inspectable
-- and identical on every volume, including those created before this file existed.
--
-- Idempotent: DROP CONCURRENTLY IF EXISTS then CREATE CONCURRENTLY IF NOT EXISTS.
-- On a fresh database the target tables are created by earlier regular migrations,
-- so the no-tx pre-runner defers this file (undefined_table) and the post-pass
-- builds the indexes after sqlx::migrate!() finishes.

DROP INDEX CONCURRENTLY IF EXISTS ix_supreme_council_mem_embedding_hnsw;

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_supreme_council_mem_embedding_hnsw
    ON supreme_council_memory
 USING hnsw (embedding_vec vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);

DROP INDEX CONCURRENTLY IF EXISTS ix_pwp_embedding_hnsw;

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_pwp_embedding_hnsw
    ON pentest_winning_paths
 USING hnsw (target_embedding vector_cosine_ops)
  WITH (m = 16, ef_construction = 64)
 WHERE target_embedding IS NOT NULL;
