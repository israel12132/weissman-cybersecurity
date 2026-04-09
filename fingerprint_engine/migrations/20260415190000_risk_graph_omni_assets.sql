-- Omni risk graph: stable graph_key upserts (no full-table delete), blast-radius fields, cloud/K8s inventory.

-- Remove duplicate edges so a uniqueness constraint can be enforced (idempotent).
DELETE FROM risk_graph_edges a
    USING risk_graph_edges b
WHERE a.id > b.id
  AND a.tenant_id = b.tenant_id
  AND a.client_id = b.client_id
  AND a.from_node_id = b.from_node_id
  AND a.to_node_id = b.to_node_id
  AND a.edge_type = b.edge_type;

ALTER TABLE risk_graph_nodes
    ADD COLUMN IF NOT EXISTS graph_key TEXT,
    ADD COLUMN IF NOT EXISTS risk_score INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS is_choke_point BOOLEAN NOT NULL DEFAULT false;

UPDATE risk_graph_nodes
SET graph_key = node_type || ':' || COALESCE(NULLIF(TRIM(external_id), ''), 'id:' || id::text)
WHERE graph_key IS NULL;

ALTER TABLE risk_graph_nodes ALTER COLUMN graph_key SET NOT NULL;

ALTER TABLE risk_graph_nodes DROP CONSTRAINT IF EXISTS uq_risk_graph_nodes_graph_key;
ALTER TABLE risk_graph_nodes ADD CONSTRAINT uq_risk_graph_nodes_graph_key UNIQUE (tenant_id, client_id, graph_key);

ALTER TABLE risk_graph_edges DROP CONSTRAINT IF EXISTS uq_risk_graph_edges_dedupe;
ALTER TABLE risk_graph_edges ADD CONSTRAINT uq_risk_graph_edges_dedupe UNIQUE (tenant_id, client_id, from_node_id, to_node_id, edge_type);

-- AWS inventory (populated by cloud connectors / future scanners).
CREATE TABLE IF NOT EXISTS aws_assets (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    asset_arn       TEXT NOT NULL,
    region          TEXT,
    service_name    TEXT,
    resource_type   TEXT,
    metadata        TEXT NOT NULL DEFAULT '{}',
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_aws_assets_arn UNIQUE (tenant_id, client_id, asset_arn)
);

CREATE INDEX IF NOT EXISTS ix_aws_assets_client ON aws_assets(client_id);
CREATE INDEX IF NOT EXISTS ix_aws_assets_tenant ON aws_assets(tenant_id);

-- Kubernetes cluster / workload inventory (stub for CNAPP graph linkage).
CREATE TABLE IF NOT EXISTS k8s_assets (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    cluster_uid     TEXT NOT NULL,
    cluster_name    TEXT,
    namespace       TEXT NOT NULL DEFAULT '',
    kind            TEXT NOT NULL DEFAULT 'Cluster',
    name            TEXT NOT NULL DEFAULT '',
    metadata        TEXT NOT NULL DEFAULT '{}',
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_k8s_assets_logical UNIQUE (tenant_id, client_id, cluster_uid, namespace, kind, name)
);

CREATE INDEX IF NOT EXISTS ix_k8s_assets_client ON k8s_assets(client_id);
CREATE INDEX IF NOT EXISTS ix_k8s_assets_tenant ON k8s_assets(tenant_id);

ALTER TABLE aws_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_assets FORCE ROW LEVEL SECURITY;
CREATE POLICY aws_assets_tenant ON aws_assets FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE k8s_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE k8s_assets FORCE ROW LEVEL SECURITY;
CREATE POLICY k8s_assets_tenant ON k8s_assets FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);
