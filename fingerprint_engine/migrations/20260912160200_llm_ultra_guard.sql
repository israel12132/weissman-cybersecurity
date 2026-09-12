-- LLM Ultra-Guard (Part 4): prompt-injection brake, jailbreak cognition, RAG integrity.
-- Live-only tables; RLS on app.current_tenant_id. weissman_auth (BYPASSRLS) is denied
-- access to council/intel vectors. weissman_ro stays SELECT-only on the NL allow-list
-- (never these tables).

-- ── Events / quarantine ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS llm_guard_events (
    id                  BIGSERIAL   PRIMARY KEY,
    tenant_id           BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT,
    user_id             BIGINT,
    engine_id           TEXT        NOT NULL,
    source              TEXT        NOT NULL DEFAULT 'inspect',
    verdict             TEXT        NOT NULL,
    score               REAL        NOT NULL,
    injection_score     REAL        NOT NULL DEFAULT 0,
    jailbreak_score     REAL        NOT NULL DEFAULT 0,
    latency_us          BIGINT      NOT NULL DEFAULT 0,
    fingerprint         TEXT        NOT NULL,
    simhash             BIGINT      NOT NULL DEFAULT 0,
    techniques          TEXT[]      NOT NULL DEFAULT '{}',
    cwes                TEXT[]      NOT NULL DEFAULT '{}',
    flags               INTEGER     NOT NULL DEFAULT 0,
    prompt_excerpt      TEXT        NOT NULL DEFAULT '',
    detail              JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_llm_guard_events_tenant_created
    ON llm_guard_events (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_llm_guard_events_fp
    ON llm_guard_events (tenant_id, fingerprint);

ALTER TABLE llm_guard_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE llm_guard_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS llm_guard_events_tenant ON llm_guard_events;
CREATE POLICY llm_guard_events_tenant ON llm_guard_events FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT ON llm_guard_events TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE llm_guard_events_id_seq TO weissman_app;

CREATE TABLE IF NOT EXISTS llm_guard_quarantine (
    id              BIGSERIAL   PRIMARY KEY,
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_id        BIGINT      REFERENCES llm_guard_events(id) ON DELETE CASCADE,
    prompt_hash     TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending',
    council_decision TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_llm_guard_quarantine_tenant
    ON llm_guard_quarantine (tenant_id, created_at DESC);

ALTER TABLE llm_guard_quarantine ENABLE ROW LEVEL SECURITY;
ALTER TABLE llm_guard_quarantine FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS llm_guard_quarantine_tenant ON llm_guard_quarantine;
CREATE POLICY llm_guard_quarantine_tenant ON llm_guard_quarantine FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE ON llm_guard_quarantine TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE llm_guard_quarantine_id_seq TO weissman_app;

CREATE TABLE IF NOT EXISTS rag_vector_integrity (
    id                  BIGSERIAL   PRIMARY KEY,
    tenant_id           BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    memory_id           BIGINT,
    table_name          TEXT        NOT NULL DEFAULT 'supreme_council_memory',
    sha256              TEXT        NOT NULL,
    l2_norm             REAL        NOT NULL,
    outlier             BOOLEAN     NOT NULL DEFAULT false,
    source_attribution  TEXT        NOT NULL DEFAULT '',
    flags               INTEGER     NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_rag_vector_integrity_tenant
    ON rag_vector_integrity (tenant_id, created_at DESC);

ALTER TABLE rag_vector_integrity ENABLE ROW LEVEL SECURITY;
ALTER TABLE rag_vector_integrity FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rag_vector_integrity_tenant ON rag_vector_integrity;
CREATE POLICY rag_vector_integrity_tenant ON rag_vector_integrity FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT ON rag_vector_integrity TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE rag_vector_integrity_id_seq TO weissman_app;

-- ── Council memory integrity columns ─────────────────────────────────────────
-- HNSW rebuild (m=32, ef_construction=128) is NOT here. DROP INDEX / CREATE INDEX
-- on a populated supreme_council_memory takes AccessExclusiveLock for the whole
-- build (minutes to hours at millions of vectors) and stalls Ask Weissman +
-- worker RAG. Online rebuild lives in
-- 20260828120000_supreme_council_hnsw_concurrent.sql (weissman:no-transaction,
-- CREATE INDEX CONCURRENTLY then DROP INDEX CONCURRENTLY of the legacy name).
ALTER TABLE supreme_council_memory
    ADD COLUMN IF NOT EXISTS embedding_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS embedding_norm   REAL,
    ADD COLUMN IF NOT EXISTS source_link      TEXT,
    ADD COLUMN IF NOT EXISTS verified_at      TIMESTAMPTZ;

-- ── Role hardening: auth plane never reads RAG / guard intel ────────────────
REVOKE ALL ON TABLE supreme_council_memory FROM weissman_auth;
REVOKE ALL ON TABLE supreme_council_rag_hits FROM weissman_auth;
REVOKE ALL ON TABLE llm_guard_events FROM weissman_auth;
REVOKE ALL ON TABLE llm_guard_quarantine FROM weissman_auth;
REVOKE ALL ON TABLE rag_vector_integrity FROM weissman_auth;
REVOKE ALL ON TABLE llm_guard_events FROM weissman_ro;
REVOKE ALL ON TABLE llm_guard_quarantine FROM weissman_ro;
REVOKE ALL ON TABLE rag_vector_integrity FROM weissman_ro;
REVOKE ALL ON TABLE supreme_council_memory FROM weissman_ro;

-- Read-only Ask Weissman role: hard timeouts + read-only transactions.
ALTER ROLE weissman_ro SET statement_timeout = '15s';
ALTER ROLE weissman_ro SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE weissman_ro SET default_transaction_read_only = on;
ALTER ROLE weissman_ro SET client_encoding = 'UTF8';

-- App role must never bypass RLS.
ALTER ROLE weissman_app SET row_security = on;

-- Planner stats for RLS-heavy tables.
ALTER TABLE llm_guard_events ALTER COLUMN tenant_id SET STATISTICS 500;
ALTER TABLE supreme_council_memory ALTER COLUMN tenant_id SET STATISTICS 500;
