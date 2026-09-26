-- ITSM connectors — outbound ticket creation into ServiceNow / Jira from a finding.
-- The connector credential (API token / basic-auth secret) is encrypted at rest with the
-- AES-256-GCM vault (wzv1: prefix, crate::ceo::vault) BEFORE it reaches this table; the
-- auth_ref column never holds plaintext and is never returned to any API client.
-- RLS FORCE on both tables; tenant policy via public.app_current_tenant_id()
-- (never a raw GUC ::bigint cast). Byte-identical copy in crates/weissman-db/migrations.

CREATE TABLE IF NOT EXISTS itsm_connectors (
    id                BIGSERIAL PRIMARY KEY,
    tenant_id         BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind              TEXT NOT NULL CHECK (kind IN ('servicenow', 'jira')),
    name              TEXT NOT NULL DEFAULT '',
    base_url          TEXT NOT NULL,
    auth_ref          TEXT NOT NULL DEFAULT '',
    project_or_table  TEXT NOT NULL DEFAULT '',
    default_fields    JSONB NOT NULL DEFAULT '{}'::jsonb,
    active            BOOLEAN NOT NULL DEFAULT TRUE,
    created_by        BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_itsm_connectors_tenant
    ON itsm_connectors (tenant_id)
    WHERE active;

ALTER TABLE itsm_connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE itsm_connectors FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS itsm_connectors_tenant ON itsm_connectors;
CREATE POLICY itsm_connectors_tenant ON itsm_connectors FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON itsm_connectors TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE itsm_connectors_id_seq TO weissman_app;

-- Ticket ledger — one row per external ticket opened from a finding. Records the vendor
-- id / key / url so a finding's remediation trail is queryable without re-hitting the vendor.
CREATE TABLE IF NOT EXISTS itsm_tickets (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_id  BIGINT NOT NULL REFERENCES itsm_connectors(id) ON DELETE CASCADE,
    finding_id    BIGINT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    external_id   TEXT NOT NULL DEFAULT '',
    external_key  TEXT NOT NULL DEFAULT '',
    external_url  TEXT NOT NULL DEFAULT '',
    created_by    BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_itsm_tickets_tenant_finding
    ON itsm_tickets (tenant_id, finding_id);

ALTER TABLE itsm_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE itsm_tickets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS itsm_tickets_tenant ON itsm_tickets;
CREATE POLICY itsm_tickets_tenant ON itsm_tickets FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON itsm_tickets TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE itsm_tickets_id_seq TO weissman_app;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON itsm_connectors TO weissman_ro;
        GRANT SELECT ON itsm_tickets TO weissman_ro;
    END IF;
END $$;

COMMENT ON TABLE itsm_connectors IS
    'Outbound ITSM connectors (ServiceNow / Jira); auth_ref holds the AES-256-GCM (wzv1:) encrypted credential, never plaintext, never returned by the API.';
COMMENT ON TABLE itsm_tickets IS
    'Ledger of external ITSM tickets opened from findings (external id/key/url).';
