-- Cluster corroboration: native vs effective severity, detection planes, boost reason.
-- Cross-plane (network + agent) corroboration raises max_severity to critical at persist time.

ALTER TABLE weissman_finding_clusters
    ADD COLUMN IF NOT EXISTS native_severity TEXT NOT NULL DEFAULT 'info',
    ADD COLUMN IF NOT EXISTS corroboration_boost TEXT NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS engine_planes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

UPDATE weissman_finding_clusters
   SET native_severity = COALESCE(NULLIF(max_severity, ''), 'info')
 WHERE native_severity = 'info' OR native_severity IS NULL;

CREATE INDEX IF NOT EXISTS ix_finding_clusters_boost
    ON weissman_finding_clusters (tenant_id, corroboration_boost)
    WHERE corroboration_boost <> 'none';
