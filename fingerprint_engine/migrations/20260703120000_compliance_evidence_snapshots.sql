-- DB-backed compliance evidence pack snapshots (auditor handoff + tamper-evident SHA-256).

CREATE TABLE IF NOT EXISTS compliance_evidence_pack_snapshots (
    id               BIGSERIAL PRIMARY KEY,
    tenant_id        BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id        BIGINT NOT NULL,
    framework_filter TEXT,
    pack_json        JSONB NOT NULL,
    pack_sha256      CHAR(64) NOT NULL,
    generated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_compliance_snapshots_client
    ON compliance_evidence_pack_snapshots (tenant_id, client_id, generated_at DESC);

ALTER TABLE compliance_evidence_pack_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_evidence_pack_snapshots FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS compliance_snapshots_tenant ON compliance_evidence_pack_snapshots;
CREATE POLICY compliance_snapshots_tenant ON compliance_evidence_pack_snapshots FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::bigint);

GRANT SELECT, INSERT ON compliance_evidence_pack_snapshots TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE compliance_evidence_pack_snapshots_id_seq TO weissman_app;

COMMENT ON TABLE compliance_evidence_pack_snapshots IS
    'Immutable compliance evidence pack snapshots — SHA-256 of canonical JSON for auditor export.';
