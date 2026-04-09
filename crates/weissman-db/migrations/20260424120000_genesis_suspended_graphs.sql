-- Genesis eternal DFS: hibernate / resume when RAM exceeds soft limit (state offload).

CREATE TABLE genesis_suspended_graphs (
    id                 BIGSERIAL PRIMARY KEY,
    tenant_id          BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    graph_snapshot     JSONB NOT NULL DEFAULT '{}'::jsonb,
    dfs_stack          JSONB NOT NULL DEFAULT '[]'::jsonb,
    visited_nodes      JSONB NOT NULL DEFAULT '[]'::jsonb,
    seeds_json         JSONB NOT NULL DEFAULT '[]'::jsonb,
    max_depth          BIGINT NOT NULL DEFAULT 0,
    root_index         BIGINT NOT NULL DEFAULT 0,
    paths_found_json   JSONB NOT NULL DEFAULT '[]'::jsonb,
    ram_budget_bytes   BIGINT NOT NULL DEFAULT 0,
    status             TEXT NOT NULL DEFAULT 'suspended'
        CHECK (status IN ('suspended', 'resumed', 'completed', 'failed')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_genesis_suspended_tenant ON genesis_suspended_graphs(tenant_id);
CREATE INDEX ix_genesis_suspended_status ON genesis_suspended_graphs(tenant_id, status);

ALTER TABLE genesis_suspended_graphs ENABLE ROW LEVEL SECURITY;
ALTER TABLE genesis_suspended_graphs FORCE ROW LEVEL SECURITY;
CREATE POLICY genesis_suspended_graphs_tenant ON genesis_suspended_graphs FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON genesis_suspended_graphs TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE genesis_suspended_graphs_id_seq TO weissman_app;
