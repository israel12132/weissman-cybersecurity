-- Multi-stage correlation incidents: an attacker progressing through ordered kill-chain stages
-- (recon -> access -> priv-esc -> exfil) on one target within a time window, persisted as a single
-- high-confidence incident. Tenant-isolated under forced RLS.

CREATE TABLE IF NOT EXISTS weissman_correlation_incidents (
    id            BIGSERIAL    PRIMARY KEY,
    tenant_id     BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id     BIGINT,
    rule_id       TEXT         NOT NULL,
    rule_name     TEXT         NOT NULL,
    severity      TEXT         NOT NULL,
    target        TEXT         NOT NULL,
    started_ts    BIGINT       NOT NULL,
    ended_ts      BIGINT       NOT NULL,
    span_secs     BIGINT       NOT NULL,
    incident_key  TEXT         NOT NULL,
    stages        JSONB        NOT NULL DEFAULT '[]'::jsonb,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, incident_key)
);

CREATE INDEX IF NOT EXISTS ix_corr_incidents_tenant_client
    ON weissman_correlation_incidents (tenant_id, client_id, created_at DESC);

ALTER TABLE weissman_correlation_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_correlation_incidents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_correlation_incidents_tenant ON weissman_correlation_incidents;
CREATE POLICY weissman_correlation_incidents_tenant ON weissman_correlation_incidents
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_correlation_incidents TO weissman_app;
