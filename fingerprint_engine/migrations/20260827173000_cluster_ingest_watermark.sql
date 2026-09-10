-- Out-of-band cluster ingest (hot persist TX must not lock weissman_finding_clusters)
-- plus high-watermark severity so inbox / SOAR / audit never yo-yo downward.

ALTER TABLE weissman_finding_clusters
    ADD COLUMN IF NOT EXISTS watermark_severity TEXT NOT NULL DEFAULT 'info';

UPDATE weissman_finding_clusters
   SET watermark_severity = COALESCE(NULLIF(max_severity, ''), 'info')
 WHERE watermark_severity = 'info'
    OR watermark_severity IS NULL;

-- Append-only queue. No FK to vulnerabilities: that would re-introduce the
-- vuln-row ↔ cluster-row lock inversion this table exists to break.
CREATE TABLE IF NOT EXISTS weissman_cluster_ingest (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    vuln_id         BIGINT NOT NULL,
    cluster_key     TEXT NOT NULL,
    target          TEXT NOT NULL DEFAULT '',
    engine          TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT '',
    title           TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT 'info',
    cwe             TEXT NOT NULL DEFAULT '',
    vuln_signature  TEXT NOT NULL DEFAULT '',
    cve             TEXT,
    cvss            DOUBLE PRECISION,
    epss            REAL,
    kev_listed      BOOLEAN NOT NULL DEFAULT FALSE,
    is_new_member   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_cluster_ingest_pending
    ON weissman_cluster_ingest (tenant_id, id)
    WHERE processed_at IS NULL;

ALTER TABLE weissman_cluster_ingest ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_cluster_ingest FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_cluster_ingest_tenant ON weissman_cluster_ingest;
CREATE POLICY weissman_cluster_ingest_tenant ON weissman_cluster_ingest
    FOR ALL
    USING (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    )
    WITH CHECK (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_cluster_ingest TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE weissman_cluster_ingest_id_seq TO weissman_app;
