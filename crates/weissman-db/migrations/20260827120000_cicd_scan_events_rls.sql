-- Tenant-scope CI/CD scan findings. The original table (phase6) stored webhook
-- results with no tenant_id and no RLS — every replica could read every customer's
-- pipeline findings. Follow-on only: never edit the applied phase6 file.

ALTER TABLE cicd_scan_events
    ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'cicd_scan_events_tenant_id_fkey'
    ) THEN
        ALTER TABLE cicd_scan_events
            ADD CONSTRAINT cicd_scan_events_tenant_id_fkey
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_cicd_scan_events_tenant_created
    ON cicd_scan_events (tenant_id, created_at DESC);

ALTER TABLE cicd_scan_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE cicd_scan_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cicd_scan_events_tenant ON cicd_scan_events;
CREATE POLICY cicd_scan_events_tenant ON cicd_scan_events FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT ON cicd_scan_events TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE cicd_scan_events_id_seq TO weissman_app;
