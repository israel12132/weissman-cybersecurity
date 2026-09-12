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
-- (brief ShareUpdateExclusiveLock, not AccessExclusiveLock).
--
-- ─── INVALID leftover trap ────────────────────────────────────────────────
-- If CREATE INDEX CONCURRENTLY is killed (OOM, timeout, crash) Postgres keeps
-- the catalog row with pg_index.indisvalid = false. CREATE INDEX CONCURRENTLY
-- IF NOT EXISTS then *skips* that name, this file would DROP the live legacy
-- index and record success — RAG boots with no usable HNSW (crash-loop / 503).
-- DROP INDEX CONCURRENTLY IF EXISTS of the new name FIRST removes both VALID
-- and INVALID leftovers. CREATE has no IF NOT EXISTS so an INVALID name can
-- never be skipped. pgvector ops class is vector_cosine_ops (not cosine_ops).

DROP INDEX CONCURRENTLY IF EXISTS ix_supreme_council_mem_embedding_hnsw_m32;

CREATE INDEX CONCURRENTLY ix_supreme_council_mem_embedding_hnsw_m32
    ON supreme_council_memory
 USING hnsw (embedding_vec vector_cosine_ops)
  WITH (m = 32, ef_construction = 128);

DROP INDEX CONCURRENTLY IF EXISTS ix_supreme_council_mem_embedding_hnsw;
