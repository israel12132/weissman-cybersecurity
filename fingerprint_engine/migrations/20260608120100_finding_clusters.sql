-- ─── Findings correlation & deduplication ─────────────────────────────────────
--
-- Goal: collapse multiple engine signals on the same vulnerability into ONE
-- "cluster" the analyst triages once. Engines may detect the same issue from
-- different angles (e.g. asm + leak_hunter + bola_idor all flag the same IDOR);
-- without clustering the user gets 3 tickets for the same problem.
--
-- Cluster identity = sha256(target_lower | vuln_signature | cwe_normalized).
-- One row per cluster; vulnerabilities point to it via cluster_id.
--
-- Aggregated fields are denormalised for fast read (no GROUP BY on the hot path):
--   * member_count, engines, sources
--   * max_severity (priority for the inbox), max_cvss, max_epss, kev_listed
--   * first_seen_at / last_seen_at / status (open|acknowledged|fixed|fp)

CREATE TABLE IF NOT EXISTS weissman_finding_clusters (
    id                  BIGSERIAL   PRIMARY KEY,
    tenant_id           BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT      NOT NULL REFERENCES clients(id)  ON DELETE CASCADE,

    -- Cluster identity (immutable for the life of the cluster).
    cluster_key         TEXT        NOT NULL,                 -- sha256 hex
    target              TEXT        NOT NULL DEFAULT '',
    cwe                 TEXT        NOT NULL DEFAULT '',
    vuln_signature      TEXT        NOT NULL DEFAULT '',
    title               TEXT        NOT NULL DEFAULT '',

    -- Aggregated state (re-computed on every member upsert).
    member_count        INTEGER     NOT NULL DEFAULT 0,
    engines             TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    sources             TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    cves                TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    max_severity        TEXT        NOT NULL DEFAULT 'info',
    max_cvss            REAL,
    max_epss            REAL,
    kev_listed          BOOLEAN     NOT NULL DEFAULT FALSE,

    status              TEXT        NOT NULL DEFAULT 'OPEN',
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_finding_clusters_key
    ON weissman_finding_clusters (tenant_id, client_id, cluster_key);

CREATE INDEX IF NOT EXISTS ix_finding_clusters_tenant_sev
    ON weissman_finding_clusters (tenant_id, max_severity, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS ix_finding_clusters_kev
    ON weissman_finding_clusters (tenant_id, kev_listed) WHERE kev_listed = TRUE;

-- Forced RLS — clusters carry tenant_id like everything else.
ALTER TABLE weissman_finding_clusters ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_finding_clusters FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_finding_clusters_tenant ON weissman_finding_clusters;
CREATE POLICY weissman_finding_clusters_tenant ON weissman_finding_clusters
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_finding_clusters TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE weissman_finding_clusters_id_seq TO weissman_app;

-- ─── Add cluster_id FK on vulnerabilities ─────────────────────────────────────
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS cluster_id BIGINT REFERENCES weissman_finding_clusters(id)
        ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS ix_vuln_cluster ON vulnerabilities(cluster_id);
