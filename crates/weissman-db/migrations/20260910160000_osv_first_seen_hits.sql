-- First-seen OSV/NVD hits: persist live SBOM↔OSV matches so we do not re-alert,
-- and so nvd_status (absent_cve / unpublished / listed / skipped_no_key) is auditable.
-- RLS FORCE. weissman_app writes. No weissman_ro GRANT (operator-only).

CREATE TABLE IF NOT EXISTS osv_first_seen_hits (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    package_name    TEXT NOT NULL,
    version_spec    TEXT NOT NULL DEFAULT '',
    ecosystem       TEXT NOT NULL DEFAULT '',
    osv_id          TEXT NOT NULL,
    cve_id          TEXT,
    nvd_status      TEXT NOT NULL,
    evidence_json   JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, client_id, osv_id, package_name, version_spec)
);

CREATE INDEX IF NOT EXISTS ix_osv_first_seen_client_time
    ON osv_first_seen_hits (tenant_id, client_id, first_seen_at DESC);

ALTER TABLE osv_first_seen_hits ENABLE ROW LEVEL SECURITY;
ALTER TABLE osv_first_seen_hits FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS osv_first_seen_hits_tenant ON osv_first_seen_hits;
CREATE POLICY osv_first_seen_hits_tenant ON osv_first_seen_hits FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON osv_first_seen_hits TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE osv_first_seen_hits_id_seq TO weissman_app;
