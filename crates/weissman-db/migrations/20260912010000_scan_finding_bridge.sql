-- Scan → finding mapping for proven-finding Cortex export.
-- Live-only: rows are written at persist time from real engine scans.
-- RLS FORCE. weissman_app writes. weissman_ro can read the Command Center board.

CREATE TABLE IF NOT EXISTS scan_finding_bridge (
    tenant_id               BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_pk              BIGINT NOT NULL,
    finding_id              TEXT NOT NULL,
    report_run_id          BIGINT,
    engine_id               TEXT NOT NULL,
    scan_target             TEXT NOT NULL DEFAULT '',
    proof_kind              TEXT,
    proof_hash              TEXT,
    cortex_status            TEXT NOT NULL DEFAULT 'mapped',
    cortex_external_ref    TEXT,
    cortex_pushed_at        TIMESTAMPTZ,
    xdr_had_matching_alert  BOOLEAN,
    mapped_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, finding_pk)
);

CREATE INDEX IF NOT EXISTS ix_scan_finding_bridge_engine
    ON scan_finding_bridge (tenant_id, engine_id, mapped_at DESC);

CREATE INDEX IF NOT EXISTS ix_scan_finding_bridge_cortex
    ON scan_finding_bridge (tenant_id, cortex_status);

ALTER TABLE scan_finding_bridge ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_finding_bridge FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scan_finding_bridge_tenant ON scan_finding_bridge;
CREATE POLICY scan_finding_bridge_tenant ON scan_finding_bridge FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON scan_finding_bridge TO weissman_app;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON scan_finding_bridge TO weissman_ro;
    END IF;
END $$;
