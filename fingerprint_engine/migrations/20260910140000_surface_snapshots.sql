-- First-mover surface snapshots: persist live DNS/HTTP inventory per client so
-- the next scan can emit only what changed (new hosts, dangling CNAME, A flips).
-- RLS FORCE. weissman_app writes; weissman_ro SELECT for Ask-Weissman.

CREATE TABLE IF NOT EXISTS surface_snapshots (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    run_id          BIGINT REFERENCES report_runs(id) ON DELETE SET NULL,
    snapshot_json   JSONB NOT NULL DEFAULT '{}'::jsonb,
    asset_count     INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_surface_snapshots_client_time
    ON surface_snapshots (tenant_id, client_id, created_at DESC);

ALTER TABLE surface_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE surface_snapshots FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS surface_snapshots_tenant ON surface_snapshots;
CREATE POLICY surface_snapshots_tenant ON surface_snapshots FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON surface_snapshots TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE surface_snapshots_id_seq TO weissman_app;
