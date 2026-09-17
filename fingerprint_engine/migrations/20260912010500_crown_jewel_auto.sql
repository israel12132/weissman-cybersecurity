-- Provenance for crown-jewel auto-tag: operator-cleared jewels stay off.
-- Auto-tag sets crown_jewel_auto=TRUE. A later UPDATE that only clears
-- crown_jewel leaves this flag set, so recompute will not re-enable it.

ALTER TABLE risk_graph_nodes
    ADD COLUMN IF NOT EXISTS crown_jewel_auto BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS ix_risk_nodes_jewel_auto
    ON risk_graph_nodes(tenant_id, client_id)
    WHERE crown_jewel_auto = TRUE;
