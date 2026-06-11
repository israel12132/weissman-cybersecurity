-- Evidence Vault: immutable evidence artifacts (files) attached to a client and optionally an engagement/finding.
-- MVP stores encrypted-at-rest evidence elsewhere; this table is for operator-uploaded artifacts (screenshots, logs, exports).

CREATE TABLE IF NOT EXISTS evidence_items (
    id                 BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    engagement_id       BIGINT REFERENCES engagements(id) ON DELETE SET NULL,
    vulnerability_id    BIGINT REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    filename            TEXT NOT NULL,
    content_type        TEXT NOT NULL DEFAULT 'application/octet-stream',
    size_bytes          BIGINT NOT NULL,
    sha256_hex          TEXT NOT NULL,
    label               TEXT NOT NULL DEFAULT '',
    notes               TEXT NOT NULL DEFAULT '',
    blob                BYTEA NOT NULL,
    created_by_user_id  BIGINT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evidence_items_tenant_client_created
    ON evidence_items (tenant_id, client_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_evidence_items_tenant_engagement_created
    ON evidence_items (tenant_id, engagement_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_evidence_items_tenant_vuln_created
    ON evidence_items (tenant_id, vulnerability_id, created_at DESC);

ALTER TABLE evidence_items ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS evidence_items_tenant_isolation ON evidence_items;
CREATE POLICY evidence_items_tenant_isolation
    ON evidence_items
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

