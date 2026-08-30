-- Living System Memory, forge drafts, and sandbox PoC scripts for the Sovereign Operator.
-- FORCE RLS. Live-only: rows are written from worker findings, sandbox verdicts, and owner tools.

CREATE TABLE IF NOT EXISTS weissman_sovereign_memory (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT,
    kind            TEXT NOT NULL,
    engine_id       TEXT NOT NULL DEFAULT '',
    target          TEXT NOT NULL DEFAULT '',
    body            JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence        TEXT NOT NULL DEFAULT '',
    verified        BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_sovereign_memory_tenant_kind
    ON weissman_sovereign_memory (tenant_id, kind, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_sovereign_memory_target
    ON weissman_sovereign_memory (tenant_id, target, created_at DESC);

ALTER TABLE weissman_sovereign_memory ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_sovereign_memory FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_sovereign_memory_tenant ON weissman_sovereign_memory;
CREATE POLICY weissman_sovereign_memory_tenant ON weissman_sovereign_memory
    FOR ALL
    USING      (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_sovereign_memory TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE weissman_sovereign_memory_id_seq TO weissman_app;

CREATE TABLE IF NOT EXISTS weissman_sovereign_forge (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_user_id       BIGINT,
    engine_id           TEXT NOT NULL,
    title               TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'draft',
    rust_source         TEXT NOT NULL DEFAULT '',
    worktree_path       TEXT NOT NULL DEFAULT '',
    compile_log         TEXT NOT NULL DEFAULT '',
    live_finding        JSONB NOT NULL DEFAULT '{}'::jsonb,
    proposal_cycle_id   UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_sovereign_forge_tenant_status
    ON weissman_sovereign_forge (tenant_id, status, updated_at DESC);

ALTER TABLE weissman_sovereign_forge ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_sovereign_forge FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_sovereign_forge_tenant ON weissman_sovereign_forge;
CREATE POLICY weissman_sovereign_forge_tenant ON weissman_sovereign_forge
    FOR ALL
    USING      (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_sovereign_forge TO weissman_app;

CREATE TABLE IF NOT EXISTS weissman_sovereign_scripts (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT,
    target          TEXT NOT NULL,
    method          TEXT NOT NULL DEFAULT 'GET',
    payload         TEXT NOT NULL DEFAULT '',
    marker          TEXT NOT NULL DEFAULT '',
    verdict         JSONB NOT NULL DEFAULT '{}'::jsonb,
    verified        BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_sovereign_scripts_tenant
    ON weissman_sovereign_scripts (tenant_id, created_at DESC);

ALTER TABLE weissman_sovereign_scripts ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_sovereign_scripts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_sovereign_scripts_tenant ON weissman_sovereign_scripts;
CREATE POLICY weissman_sovereign_scripts_tenant ON weissman_sovereign_scripts
    FOR ALL
    USING      (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_sovereign_scripts TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE weissman_sovereign_scripts_id_seq TO weissman_app;
