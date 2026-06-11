-- ─── Attack-path inference: graph-node entry/exit flags ──────────────────────
--
-- `attack_path::compute_top_paths` runs BFS from "internet_exposed" nodes
-- towards "crown_jewel" nodes, weighted by associated finding CVSS+EPSS.
-- Both flags live directly on `risk_graph_nodes` so the BFS query plan stays
-- in one table.
--
-- The existing `risk_graph_nodes.metadata` column is `TEXT '{}'::text` (not
-- JSONB), so we add real boolean columns for predictable indexing.

ALTER TABLE risk_graph_nodes
    ADD COLUMN IF NOT EXISTS internet_exposed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS crown_jewel      BOOLEAN NOT NULL DEFAULT FALSE,
    -- Optional ER-style "blast radius" weighting for the crown jewel: a database
    -- of HR data carries more weight than the marketing site. Default 1.0.
    ADD COLUMN IF NOT EXISTS asset_value      REAL    NOT NULL DEFAULT 1.0;

CREATE INDEX IF NOT EXISTS ix_risk_nodes_entry
    ON risk_graph_nodes(tenant_id, client_id) WHERE internet_exposed = TRUE;
CREATE INDEX IF NOT EXISTS ix_risk_nodes_jewel
    ON risk_graph_nodes(tenant_id, client_id) WHERE crown_jewel = TRUE;

-- ─── Optional: link a finding to the node it affects ────────────────────────
-- Used by the BFS to weight an edge by the worst finding present on the
-- adjacent node (CVSS + EPSS + KEV multiplier).
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS risk_node_id BIGINT REFERENCES risk_graph_nodes(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS ix_vuln_risk_node ON vulnerabilities(risk_node_id);

-- ─── Snapshot table for the most recent attack-path computation per client ──
-- (Cheap precompute → cockpit can render the matrix without re-doing BFS on
-- every page view.)
CREATE TABLE IF NOT EXISTS attack_path_snapshots (
    id              BIGSERIAL   PRIMARY KEY,
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT      NOT NULL REFERENCES clients(id)  ON DELETE CASCADE,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    entry_count     INTEGER     NOT NULL DEFAULT 0,
    jewel_count     INTEGER     NOT NULL DEFAULT 0,
    path_count      INTEGER     NOT NULL DEFAULT 0,
    max_risk        REAL        NOT NULL DEFAULT 0,
    -- Top-N paths serialised as JSON (small — top 50 paths max).
    paths_json      JSONB       NOT NULL DEFAULT '[]'::jsonb,
    -- Choke points: nodes that appear in many paths. The cockpit highlights
    -- these — fixing one issue here breaks many paths at once.
    choke_points    JSONB       NOT NULL DEFAULT '[]'::jsonb
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_attack_path_latest
    ON attack_path_snapshots(tenant_id, client_id, computed_at);
CREATE INDEX IF NOT EXISTS ix_attack_path_recent
    ON attack_path_snapshots(tenant_id, client_id, computed_at DESC);

ALTER TABLE attack_path_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_path_snapshots FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS attack_path_snapshots_tenant ON attack_path_snapshots;
CREATE POLICY attack_path_snapshots_tenant ON attack_path_snapshots
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON attack_path_snapshots TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE attack_path_snapshots_id_seq TO weissman_app;
