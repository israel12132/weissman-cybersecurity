-- Phase 2: Deception cloud deploy state machine + durable swarm event log.

CREATE TABLE deception_cloud_deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    client_id BIGINT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'deploying', 'active', 'failed')),
    request_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    result_json JSONB,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_deception_cloud_deployments_tenant ON deception_cloud_deployments (tenant_id, created_at DESC);
CREATE INDEX ix_deception_cloud_deployments_client ON deception_cloud_deployments (client_id);

ALTER TABLE deception_cloud_deployments ENABLE ROW LEVEL SECURITY;
ALTER TABLE deception_cloud_deployments FORCE ROW LEVEL SECURITY;
CREATE POLICY deception_cloud_deployments_tenant ON deception_cloud_deployments FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

CREATE TABLE swarm_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    client_id BIGINT,
    agent TEXT NOT NULL,
    event TEXT NOT NULL,
    detail_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    ts_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_swarm_events_tenant_client ON swarm_events (tenant_id, client_id, id DESC);

ALTER TABLE swarm_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE swarm_events FORCE ROW LEVEL SECURITY;
CREATE POLICY swarm_events_tenant ON swarm_events FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

COMMENT ON TABLE deception_cloud_deployments IS 'Async cloud honeytoken injection; state machine pending→deploying→active|failed.';
COMMENT ON TABLE swarm_events IS 'Durable Swarm Mind events (WebSocket remains live mirror).';

GRANT SELECT, INSERT, UPDATE, DELETE ON deception_cloud_deployments TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON swarm_events TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE swarm_events_id_seq TO weissman_app;
