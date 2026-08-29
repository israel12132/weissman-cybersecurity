-- weissman:no-transaction
--
-- ⚠ DO NOT REMOVE THE FIRST-LINE DIRECTIVE ABOVE.
-- Parsed by weissman_db::run_migrations BEFORE sqlx::migrate!(). This file runs
-- OUTSIDE a transaction. Postgres rejects CREATE/DROP INDEX CONCURRENTLY inside
-- any transaction block, and SQLx wraps every untagged file in BEGIN/COMMIT.
--
-- ─── Why this exists ──────────────────────────────────────────────────────
-- The previous Ultra-Guard draft rebuilt ix_supreme_council_mem_embedding_hnsw
-- with DROP INDEX + CREATE INDEX (m=32, ef_construction=128) inside the
-- transactional 20260827160000 file. That takes AccessExclusiveLock for the
-- entire HNSW build. On a live supreme_council_memory with millions of 1536-d
-- vectors the lock lasts minutes to hours: Ask Weissman ANN, council writes,
-- and worker RAG all block, then 504/503.
--
-- Contract: build the new index under a NEW name while the old index keeps
-- serving queries, then DROP the legacy name. Both statements are CONCURRENTLY
-- (brief ACCESS SHARE only).
--
-- Idempotency: DROP IF EXISTS of the new name first clears an INVALID leftover
-- from a killed CREATE CONCURRENTLY. CREATE IF NOT EXISTS then rebuilds.
-- DROP of the legacy name is a no-op when it is already gone.

DROP INDEX CONCURRENTLY IF EXISTS ix_supreme_council_mem_embedding_hnsw_m32;

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_supreme_council_mem_embedding_hnsw_m32
    ON supreme_council_memory
 USING hnsw (embedding_vec vector_cosine_ops)
  WITH (m = 32, ef_construction = 128);

DROP INDEX CONCURRENTLY IF EXISTS ix_supreme_council_mem_embedding_hnsw;
