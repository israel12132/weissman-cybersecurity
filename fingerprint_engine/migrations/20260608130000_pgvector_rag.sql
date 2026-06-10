-- ─── pgvector RAG: Supreme Council retrieval ─────────────────────────────────
--
-- The Supreme Council writes a memory row for every successful OAST/canary hit
-- (`council::run_supreme_council_debate` → `supreme_council_memory`). Until now,
-- the `embedding` column was JSONB[] — useful for export, useless for retrieval.
--
-- This migration:
--   1. enables pgvector (idempotent — provided by pgvector/pgvector:pg16 image)
--   2. adds a NEW typed `embedding_vec` column of type vector(1536) — matches the
--      output of OpenAI `text-embedding-3-small` (1536 dims) and Ollama
--      `nomic-embed-text` (768) with zero-padding handled in code
--   3. creates an IVFFlat ANN index for sub-millisecond top-K cosine queries
--   4. back-fills `embedding_vec` from the legacy JSONB array if present
--
-- Retrieval path (council.rs):
--   SELECT brief_excerpt, strategy_summary, orchestrator_instruction
--     FROM supreme_council_memory
--    WHERE tenant_id = $1 AND embedding_vec IS NOT NULL
--    ORDER BY embedding_vec <-> $2::vector LIMIT 5;
--
-- `<->` is pgvector's L2 distance. For cosine we'd use `<=>` — IVFFlat below is
-- configured for cosine because OpenAI embeddings are L2-normalised already,
-- making cosine and dot-product order-equivalent.

CREATE EXTENSION IF NOT EXISTS vector;

-- Add the typed column (idempotent).
ALTER TABLE supreme_council_memory
    ADD COLUMN IF NOT EXISTS embedding_vec vector(1536);

-- Backfill from the legacy JSONB column (best-effort: drops to NULL on any row
-- whose stored array isn't exactly 1536 floats). Safe to re-run.
DO $$
DECLARE
    r RECORD;
    arr float[];
    txt text;
BEGIN
    FOR r IN
        SELECT id FROM supreme_council_memory
         WHERE embedding_vec IS NULL
           AND embedding IS NOT NULL
           AND jsonb_typeof(embedding) = 'array'
           AND jsonb_array_length(embedding) = 1536
    LOOP
        BEGIN
            SELECT array_agg((value)::float8)
              INTO arr
              FROM jsonb_array_elements_text(
                       (SELECT embedding FROM supreme_council_memory WHERE id = r.id)
                   ) AS value;
            -- Render the array as "[v1,v2,...]" so pgvector parses it via its text form.
            txt := '[' || array_to_string(arr, ',') || ']';
            UPDATE supreme_council_memory
               SET embedding_vec = txt::vector
             WHERE id = r.id;
        EXCEPTION WHEN OTHERS THEN
            -- skip malformed legacy rows; they'll be re-embedded by the worker
            CONTINUE;
        END;
    END LOOP;
END $$;

-- ANN index. We use HNSW (Hierarchical Navigable Small World) rather than IVFFlat
-- because (a) HNSW has no cold-start problem — recall stays good from row #1
-- onward, whereas IVFFlat with `probes=1` (the default) effectively skips queries
-- against tables smaller than `lists`; and (b) HNSW recall stays consistent as
-- the table grows without REINDEX. Trade-off: builds are slightly slower and the
-- index is ~2x larger — both acceptable for the council memory table which never
-- exceeds the high-thousands of rows per tenant.
DROP INDEX IF EXISTS ix_supreme_council_mem_embedding_cos;  -- legacy IVFFlat if present
CREATE INDEX IF NOT EXISTS ix_supreme_council_mem_embedding_hnsw
    ON supreme_council_memory
 USING hnsw (embedding_vec vector_cosine_ops);

-- ─── Council RAG hits log (so we can measure retrieval quality) ───────────────
CREATE TABLE IF NOT EXISTS supreme_council_rag_hits (
    id              BIGSERIAL   PRIMARY KEY,
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    memory_id       BIGINT      REFERENCES supreme_council_memory(id) ON DELETE SET NULL,
    distance        REAL        NOT NULL,
    rank            INTEGER     NOT NULL,
    brief_excerpt   TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_rag_hits_tenant ON supreme_council_rag_hits(tenant_id, created_at DESC);

ALTER TABLE supreme_council_rag_hits ENABLE ROW LEVEL SECURITY;
ALTER TABLE supreme_council_rag_hits FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS supreme_council_rag_hits_tenant ON supreme_council_rag_hits;
CREATE POLICY supreme_council_rag_hits_tenant ON supreme_council_rag_hits
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT ON supreme_council_rag_hits TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE supreme_council_rag_hits_id_seq TO weissman_app;
