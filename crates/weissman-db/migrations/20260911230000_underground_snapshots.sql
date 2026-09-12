-- Adversary underground snapshots: persist public criminal-index hits per client
-- so the next hunt emits only what is new (HIBP / ransomware.live / ThreatFox / …).
-- RLS FORCE. weissman_app writes; weissman_ro SELECT for Ask-Weissman.

CREATE TABLE IF NOT EXISTS underground_snapshots (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    run_id          BIGINT REFERENCES report_runs(id) ON DELETE SET NULL,
    snapshot_json   JSONB NOT NULL DEFAULT '{}'::jsonb,
    hit_count       INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_underground_snapshots_client_time
    ON underground_snapshots (tenant_id, client_id, created_at DESC);

ALTER TABLE underground_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE underground_snapshots FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS underground_snapshots_tenant ON underground_snapshots;
CREATE POLICY underground_snapshots_tenant ON underground_snapshots FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON underground_snapshots TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE underground_snapshots_id_seq TO weissman_app;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON underground_snapshots TO weissman_ro;
    END IF;
END $$;
