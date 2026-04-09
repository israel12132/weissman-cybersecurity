-- Weissman Supreme Council: long-term semantic memory for OAST/canary-validated strategies.
-- Embeddings stored as JSONB numeric arrays; similarity search runs in the application (cosine).

CREATE TABLE supreme_council_memory (
    id                       BIGSERIAL PRIMARY KEY,
    tenant_id                BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_fingerprint       TEXT NOT NULL,
    brief_excerpt            TEXT NOT NULL,
    orchestrator_instruction JSONB NOT NULL DEFAULT '{}'::jsonb,
    strategy_summary         TEXT NOT NULL,
    embedding                JSONB NOT NULL DEFAULT '[]'::jsonb,
    oast_token               TEXT NOT NULL DEFAULT '',
    source                   TEXT NOT NULL DEFAULT 'oast_success',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_supreme_council_mem_tenant ON supreme_council_memory(tenant_id);
CREATE INDEX ix_supreme_council_mem_tenant_fp ON supreme_council_memory(tenant_id, target_fingerprint);
CREATE INDEX ix_supreme_council_mem_created ON supreme_council_memory(tenant_id, created_at DESC);

ALTER TABLE supreme_council_memory ENABLE ROW LEVEL SECURITY;
ALTER TABLE supreme_council_memory FORCE ROW LEVEL SECURITY;
CREATE POLICY supreme_council_memory_tenant ON supreme_council_memory FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON supreme_council_memory TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE supreme_council_memory_id_seq TO weissman_app;
