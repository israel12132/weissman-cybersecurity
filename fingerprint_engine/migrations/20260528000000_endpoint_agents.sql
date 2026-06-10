-- Endpoint-agent registry + enrollment tokens.

CREATE TABLE IF NOT EXISTS endpoint_agents (
    id               BIGSERIAL PRIMARY KEY,
    agent_uuid       UUID NOT NULL UNIQUE,
    tenant_id        BIGINT NOT NULL,
    client_id        BIGINT NOT NULL,
    hostname         TEXT NOT NULL DEFAULT '',
    device_name      TEXT NOT NULL DEFAULT '',
    os               TEXT NOT NULL DEFAULT '',
    arch             TEXT NOT NULL DEFAULT '',
    agent_version    TEXT NOT NULL DEFAULT '',
    capabilities     JSONB NOT NULL DEFAULT '[]',
    enrolled_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    status           TEXT NOT NULL DEFAULT 'enrolled',  -- enrolled | online | offline | revoked
    revoked_at       TIMESTAMPTZ,
    notes            TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_endpoint_agents_tenant_client
    ON endpoint_agents (tenant_id, client_id);

CREATE INDEX IF NOT EXISTS idx_endpoint_agents_last_seen
    ON endpoint_agents (last_seen_at);

-- Bootstrap (one-time) enrollment tokens. A token is created from the dashboard, the admin
-- pastes it into the install script, the agent presents it once to /api/agents/enroll, and the
-- server marks it `consumed`.
CREATE TABLE IF NOT EXISTS endpoint_agent_enrollment_tokens (
    id                 BIGSERIAL PRIMARY KEY,
    token_hash         TEXT NOT NULL UNIQUE,   -- sha256 of the token (stored hashed)
    tenant_id          BIGINT NOT NULL,
    client_id          BIGINT NOT NULL,
    created_by_user_id BIGINT,
    expires_at         TIMESTAMPTZ NOT NULL,
    consumed_at        TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_tokens_tenant
    ON endpoint_agent_enrollment_tokens (tenant_id, client_id);

-- Pending tasks awaiting an online agent.
CREATE TABLE IF NOT EXISTS endpoint_agent_tasks (
    id            BIGSERIAL PRIMARY KEY,
    task_uuid     UUID NOT NULL UNIQUE,
    tenant_id     BIGINT NOT NULL,
    client_id     BIGINT NOT NULL,
    agent_id      BIGINT,                       -- nullable until claimed by an agent
    engine        TEXT NOT NULL,
    target        TEXT,
    params        JSONB NOT NULL DEFAULT '{}',
    status        TEXT NOT NULL DEFAULT 'pending',   -- pending | running | done | failed | expired
    findings_count INTEGER NOT NULL DEFAULT 0,
    error         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ NOT NULL DEFAULT now() + interval '15 minutes'
);

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_tasks_status
    ON endpoint_agent_tasks (tenant_id, client_id, status);

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_tasks_agent
    ON endpoint_agent_tasks (agent_id);

-- Row-level security (mirrors other tables in the schema).
ALTER TABLE endpoint_agents               ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_agent_enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_agent_tasks          ENABLE ROW LEVEL SECURITY;

CREATE POLICY endpoint_agents_tenant_isolation
    ON endpoint_agents
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

CREATE POLICY endpoint_agent_tokens_tenant_isolation
    ON endpoint_agent_enrollment_tokens
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

CREATE POLICY endpoint_agent_tasks_tenant_isolation
    ON endpoint_agent_tasks
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint);
