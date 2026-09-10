-- System-global CEM-DAGO telemetry quarantine.
-- Tenant-scoped cem_dago_telemetry_quarantine is FORCE RLS
-- (tenant_id = app_current_tenant_id()). A corrupt MessagePack body cannot
-- supply a tenant; inserting it under RLS raises OR-01 / WITH CHECK and would
-- drop the blob. This table has NO RLS, NO FK to tenants, and is granted only
-- to weissman_app (never weissman_ro) so the worker can retain the raw hex
-- when tenant identity is missing or the tenant persist fails.

CREATE TABLE IF NOT EXISTS cem_dago_telemetry_quarantine_global (
    id                  BIGSERIAL PRIMARY KEY,
    claimed_tenant_id   BIGINT,
    client_id           BIGINT NOT NULL DEFAULT 0,
    scan_id             TEXT NOT NULL DEFAULT '',
    kind                TEXT NOT NULL,
    field_key           TEXT NOT NULL DEFAULT '',
    codec_byte          INTEGER,
    raw_hex             TEXT NOT NULL,
    decode_error        TEXT NOT NULL,
    fallback_reason     TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_cem_dago_quarantine_global_created
    ON cem_dago_telemetry_quarantine_global (created_at DESC);

REVOKE ALL ON TABLE cem_dago_telemetry_quarantine_global FROM PUBLIC;
REVOKE ALL ON SEQUENCE cem_dago_telemetry_quarantine_global_id_seq FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        REVOKE ALL ON TABLE cem_dago_telemetry_quarantine_global FROM weissman_ro;
        REVOKE ALL ON SEQUENCE cem_dago_telemetry_quarantine_global_id_seq FROM weissman_ro;
    END IF;
END $$;

GRANT INSERT, SELECT ON cem_dago_telemetry_quarantine_global TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE cem_dago_telemetry_quarantine_global_id_seq TO weissman_app;
