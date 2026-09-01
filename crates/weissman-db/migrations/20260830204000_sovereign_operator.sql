-- Sovereign Operator (owner-only right-hand): durable engine log tape,
-- chat sessions / thought cards, and tool-call audit. FORCE RLS.

CREATE TABLE IF NOT EXISTS weissman_sovereign_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_user_id   BIGINT NOT NULL,
    title           TEXT NOT NULL DEFAULT 'Sovereign',
    shift           TEXT NOT NULL DEFAULT 'red',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_sovereign_sessions_tenant_updated
    ON weissman_sovereign_sessions (tenant_id, updated_at DESC);

ALTER TABLE weissman_sovereign_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_sovereign_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_sovereign_sessions_tenant ON weissman_sovereign_sessions;
CREATE POLICY weissman_sovereign_sessions_tenant ON weissman_sovereign_sessions
    FOR ALL
    USING      (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_sovereign_sessions TO weissman_app;

CREATE TABLE IF NOT EXISTS weissman_sovereign_messages (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    session_id      UUID NOT NULL REFERENCES weissman_sovereign_sessions(id) ON DELETE CASCADE,
    role            TEXT NOT NULL,
    content         TEXT NOT NULL DEFAULT '',
    thought_kind    TEXT,
    tool_name       TEXT,
    tool_payload    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_sovereign_messages_session
    ON weissman_sovereign_messages (tenant_id, session_id, id);

ALTER TABLE weissman_sovereign_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_sovereign_messages FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_sovereign_messages_tenant ON weissman_sovereign_messages;
CREATE POLICY weissman_sovereign_messages_tenant ON weissman_sovereign_messages
    FOR ALL
    USING      (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_sovereign_messages TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE weissman_sovereign_messages_id_seq TO weissman_app;

CREATE TABLE IF NOT EXISTS weissman_sovereign_engine_logs (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT,
    job_id          TEXT,
    engine_id       TEXT NOT NULL,
    phase           TEXT NOT NULL,
    target          TEXT NOT NULL DEFAULT '',
    detail          TEXT NOT NULL DEFAULT '',
    failure_class   TEXT,
    finding_count   INTEGER,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_sovereign_engine_logs_tenant_id
    ON weissman_sovereign_engine_logs (tenant_id, id);
CREATE INDEX IF NOT EXISTS ix_sovereign_engine_logs_engine
    ON weissman_sovereign_engine_logs (tenant_id, engine_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_sovereign_engine_logs_job
    ON weissman_sovereign_engine_logs (tenant_id, job_id);

ALTER TABLE weissman_sovereign_engine_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_sovereign_engine_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_sovereign_engine_logs_tenant ON weissman_sovereign_engine_logs;
CREATE POLICY weissman_sovereign_engine_logs_tenant ON weissman_sovereign_engine_logs
    FOR ALL
    USING      (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_sovereign_engine_logs TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE weissman_sovereign_engine_logs_id_seq TO weissman_app;
