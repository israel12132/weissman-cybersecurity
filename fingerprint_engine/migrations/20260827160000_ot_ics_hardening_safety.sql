-- OT/ICS hardening: safety events, protocol baselines (Z-score), asset address ranges.
-- RLS FORCE on every table. weissman_app writes findings; weissman_ro SELECT for Ask-Weissman.

CREATE TABLE IF NOT EXISTS ot_ics_safety_events (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT REFERENCES clients(id) ON DELETE CASCADE,
    host                TEXT NOT NULL,
    protocol            TEXT NOT NULL,
    event_kind          TEXT NOT NULL,
    severity            TEXT NOT NULL DEFAULT 'info',
    z_score             DOUBLE PRECISION,
    detail              JSONB NOT NULL DEFAULT '{}'::jsonb,
    binary_signature    TEXT NOT NULL DEFAULT '',
    soar_action         TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_ot_ics_safety_tenant_time
    ON ot_ics_safety_events (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_ot_ics_safety_client
    ON ot_ics_safety_events (tenant_id, client_id, created_at DESC);

ALTER TABLE ot_ics_safety_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ot_ics_safety_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ot_ics_safety_events_tenant ON ot_ics_safety_events;
CREATE POLICY ot_ics_safety_events_tenant ON ot_ics_safety_events FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON ot_ics_safety_events TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE ot_ics_safety_events_id_seq TO weissman_app;

CREATE TABLE IF NOT EXISTS ot_ics_protocol_baselines (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    host                TEXT NOT NULL,
    protocol            TEXT NOT NULL,
    metric              TEXT NOT NULL DEFAULT 'packet_rate',
    mean_rate           DOUBLE PRECISION NOT NULL DEFAULT 0,
    stddev_rate         DOUBLE PRECISION NOT NULL DEFAULT 0,
    sample_count        BIGINT NOT NULL DEFAULT 0,
    window_start        TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, client_id, host, protocol, metric)
);

CREATE INDEX IF NOT EXISTS ix_ot_ics_baselines_client
    ON ot_ics_protocol_baselines (tenant_id, client_id);

ALTER TABLE ot_ics_protocol_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE ot_ics_protocol_baselines FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ot_ics_protocol_baselines_tenant ON ot_ics_protocol_baselines;
CREATE POLICY ot_ics_protocol_baselines_tenant ON ot_ics_protocol_baselines FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON ot_ics_protocol_baselines TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE ot_ics_protocol_baselines_id_seq TO weissman_app;

CREATE TABLE IF NOT EXISTS ot_ics_asset_ranges (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    host                TEXT NOT NULL,
    protocol            TEXT NOT NULL,
    unit_id             INT,
    address_start       INT NOT NULL DEFAULT 0,
    address_end         INT NOT NULL DEFAULT 65535,
    allow_write         BOOLEAN NOT NULL DEFAULT FALSE,
    is_gateway          BOOLEAN NOT NULL DEFAULT FALSE,
    note                TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_ot_ics_asset_ranges_client
    ON ot_ics_asset_ranges (tenant_id, client_id, host);

ALTER TABLE ot_ics_asset_ranges ENABLE ROW LEVEL SECURITY;
ALTER TABLE ot_ics_asset_ranges FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ot_ics_asset_ranges_tenant ON ot_ics_asset_ranges;
CREATE POLICY ot_ics_asset_ranges_tenant ON ot_ics_asset_ranges FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON ot_ics_asset_ranges TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE ot_ics_asset_ranges_id_seq TO weissman_app;

-- Ask-Weissman (weissman_ro) may read OT inventory + safety events, never write.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON ot_ics_fingerprints TO weissman_ro;
        GRANT SELECT ON ot_ics_safety_events TO weissman_ro;
        GRANT SELECT ON ot_ics_protocol_baselines TO weissman_ro;
        GRANT SELECT ON ot_ics_asset_ranges TO weissman_ro;
    END IF;
END $$;
