-- Recurring scan schedules (tenant-scoped, optional client target).

CREATE TABLE IF NOT EXISTS weissman_scan_schedules (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT REFERENCES clients(id) ON DELETE SET NULL,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    schedule_type   TEXT NOT NULL DEFAULT 'daily',
    cron            TEXT NOT NULL,
    engines         JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_run_at     TIMESTAMPTZ,
    next_run_at     TIMESTAMPTZ,
    run_count       BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_weissman_scan_schedules_tenant_enabled
    ON weissman_scan_schedules (tenant_id, enabled, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_weissman_scan_schedules_tenant_client
    ON weissman_scan_schedules (tenant_id, client_id);

ALTER TABLE weissman_scan_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_scan_schedules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_scan_schedules_tenant_isolation ON weissman_scan_schedules;
CREATE POLICY weissman_scan_schedules_tenant_isolation ON weissman_scan_schedules
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_scan_schedules TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE weissman_scan_schedules_id_seq TO weissman_app;
