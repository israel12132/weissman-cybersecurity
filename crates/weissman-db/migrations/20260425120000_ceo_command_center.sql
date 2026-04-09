-- CEO Command Center: live war-room events, HPC routing policy (honest worker-pool model).

CREATE TABLE ceo_war_room_events (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    session_id      TEXT NOT NULL DEFAULT '',
    async_job_id    UUID,
    phase           TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'info',
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_ceo_war_room_tenant_id ON ceo_war_room_events(tenant_id, id DESC);
CREATE INDEX ix_ceo_war_room_session ON ceo_war_room_events(tenant_id, session_id, id DESC);

ALTER TABLE ceo_war_room_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ceo_war_room_events FORCE ROW LEVEL SECURITY;
CREATE POLICY ceo_war_room_events_tenant ON ceo_war_room_events FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON ceo_war_room_events TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE ceo_war_room_events_id_seq TO weissman_app;

CREATE TABLE ceo_hpc_policy (
    tenant_id                       BIGINT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    research_core_share_percent     SMALLINT NOT NULL DEFAULT 50
        CHECK (research_core_share_percent >= 0 AND research_core_share_percent <= 100),
    research_cpu_affinity           TEXT NOT NULL DEFAULT '',
    client_scan_cpu_affinity        TEXT NOT NULL DEFAULT '',
    routing_note                    TEXT NOT NULL DEFAULT '',
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE ceo_hpc_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE ceo_hpc_policy FORCE ROW LEVEL SECURITY;
CREATE POLICY ceo_hpc_policy_tenant ON ceo_hpc_policy FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON ceo_hpc_policy TO weissman_app;
