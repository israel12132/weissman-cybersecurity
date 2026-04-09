-- Phase 7: OT/ICS fingerprints, edge swarm registry, RLS.

CREATE TABLE IF NOT EXISTS ot_ics_fingerprints (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    host            TEXT NOT NULL,
    port            INT NOT NULL,
    protocol        TEXT NOT NULL,
    vendor_hint     TEXT NOT NULL DEFAULT '',
    confidence      REAL NOT NULL DEFAULT 0,
    raw_excerpt_hex TEXT NOT NULL DEFAULT '',
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_ot_ics_client ON ot_ics_fingerprints (client_id);
CREATE INDEX IF NOT EXISTS ix_ot_ics_tenant ON ot_ics_fingerprints (tenant_id);

ALTER TABLE ot_ics_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE ot_ics_fingerprints FORCE ROW LEVEL SECURITY;
CREATE POLICY ot_ics_fingerprints_tenant ON ot_ics_fingerprints FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);
GRANT SELECT, INSERT, UPDATE, DELETE ON ot_ics_fingerprints TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE ot_ics_fingerprints_id_seq TO weissman_app;

CREATE TABLE IF NOT EXISTS edge_swarm_nodes (
    id               BIGSERIAL PRIMARY KEY,
    tenant_id        BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    region_code      TEXT NOT NULL,
    pop_label        TEXT NOT NULL,
    latitude         DOUBLE PRECISION,
    longitude        DOUBLE PRECISION,
    wasm_revision    TEXT NOT NULL DEFAULT '',
    provider         TEXT NOT NULL DEFAULT '',
    last_heartbeat   TIMESTAMPTZ,
    active_jobs      INT NOT NULL DEFAULT 0,
    metadata         JSONB NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_edge_swarm_tenant ON edge_swarm_nodes (tenant_id);

ALTER TABLE edge_swarm_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE edge_swarm_nodes FORCE ROW LEVEL SECURITY;
CREATE POLICY edge_swarm_nodes_tenant ON edge_swarm_nodes FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);
GRANT SELECT, INSERT, UPDATE, DELETE ON edge_swarm_nodes TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE edge_swarm_nodes_id_seq TO weissman_app;
