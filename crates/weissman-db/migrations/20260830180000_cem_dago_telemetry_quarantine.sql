-- CEM-DAGO telemetry integrity quarantine.
-- Corrupt / schema-drifted MessagePack bodies are never dropped: they land here
-- as raw hex so SOC can inspect Telemetry Integrity Violations under RLS.

CREATE TABLE IF NOT EXISTS cem_dago_telemetry_quarantine (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL,
    scan_id         TEXT NOT NULL,
    kind            TEXT NOT NULL,
    field_key       TEXT NOT NULL DEFAULT '',
    codec_byte      INTEGER,
    raw_hex         TEXT NOT NULL,
    decode_error    TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_cem_dago_quarantine_tenant_created
    ON cem_dago_telemetry_quarantine (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_cem_dago_quarantine_scan
    ON cem_dago_telemetry_quarantine (tenant_id, client_id, scan_id);

ALTER TABLE cem_dago_telemetry_quarantine ENABLE ROW LEVEL SECURITY;
ALTER TABLE cem_dago_telemetry_quarantine FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cem_dago_telemetry_quarantine_tenant ON cem_dago_telemetry_quarantine;
CREATE POLICY cem_dago_telemetry_quarantine_tenant ON cem_dago_telemetry_quarantine
    FOR ALL
    USING      (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT ON cem_dago_telemetry_quarantine TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE cem_dago_telemetry_quarantine_id_seq TO weissman_app;
