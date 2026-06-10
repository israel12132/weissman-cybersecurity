-- Engagements: formal Red Team / consulting executions per client (ROE, window, notes).
-- This is a governance primitive (contracts/ROE live outside), but the platform must track:
-- who ran what, when, and under which ROE mode.

CREATE TABLE IF NOT EXISTS engagements (
    id                   BIGSERIAL PRIMARY KEY,
    tenant_id             BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id             BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'active', -- active | paused | closed
    start_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    end_at                TIMESTAMPTZ,
    roe_mode              TEXT NOT NULL DEFAULT 'safe_proofs', -- safe_proofs | weaponized_god_mode
    notes                 TEXT NOT NULL DEFAULT '',
    scope_snapshot        JSONB NOT NULL DEFAULT '{}'::jsonb,  -- domains/ip_ranges/tech at creation time
    created_by_user_id    BIGINT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_engagements_tenant_client_created
    ON engagements (tenant_id, client_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_engagements_status
    ON engagements (tenant_id, status, created_at DESC);

ALTER TABLE engagements ENABLE ROW LEVEL SECURITY;

CREATE POLICY engagements_tenant_isolation
    ON engagements
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

