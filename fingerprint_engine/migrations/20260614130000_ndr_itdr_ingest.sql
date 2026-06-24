-- Live data sources for the NDR (network beaconing/exfil) and ITDR (identity threat) detectors.
-- Flow samples and auth events are ingested via the API, stored tenant-isolated under forced RLS,
-- and read back by the unified threat-analysis composition. No detector input is fabricated.

CREATE TABLE IF NOT EXISTS ndr_flow_samples (
    id          BIGSERIAL    PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id   BIGINT,
    ts          BIGINT       NOT NULL,
    dst         TEXT         NOT NULL,
    bytes_out   BIGINT       NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_ndr_flow_tenant_client_ts
    ON ndr_flow_samples (tenant_id, client_id, ts DESC);

ALTER TABLE ndr_flow_samples ENABLE ROW LEVEL SECURITY;
ALTER TABLE ndr_flow_samples FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ndr_flow_samples_tenant ON ndr_flow_samples;
CREATE POLICY ndr_flow_samples_tenant ON ndr_flow_samples
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON ndr_flow_samples TO weissman_app;

CREATE TABLE IF NOT EXISTS itdr_auth_events (
    id            BIGSERIAL    PRIMARY KEY,
    tenant_id     BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id     BIGINT,
    ts            BIGINT       NOT NULL,
    username      TEXT         NOT NULL,
    ip            TEXT         NOT NULL,
    country       TEXT         NOT NULL DEFAULT '',
    success       BOOLEAN      NOT NULL DEFAULT FALSE,
    mfa_prompted  BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_itdr_auth_tenant_client_ts
    ON itdr_auth_events (tenant_id, client_id, ts DESC);

ALTER TABLE itdr_auth_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE itdr_auth_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS itdr_auth_events_tenant ON itdr_auth_events;
CREATE POLICY itdr_auth_events_tenant ON itdr_auth_events
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON itdr_auth_events TO weissman_app;
