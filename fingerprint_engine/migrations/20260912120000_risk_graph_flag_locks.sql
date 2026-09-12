-- Operator locks for risk-graph flags.
-- AUTO_TAG_* must not re-apply internet_exposed / crown_jewel after an
-- operator PATCH sets them explicitly (including an explicit false).

ALTER TABLE risk_graph_nodes
    ADD COLUMN IF NOT EXISTS internet_exposed_locked BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS crown_jewel_locked     BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS ix_risk_nodes_unlocked_internet
    ON risk_graph_nodes (tenant_id, client_id)
    WHERE internet_exposed_locked IS NOT TRUE;

CREATE INDEX IF NOT EXISTS ix_risk_nodes_unlocked_jewel
    ON risk_graph_nodes (tenant_id, client_id)
    WHERE crown_jewel_locked IS NOT TRUE;
