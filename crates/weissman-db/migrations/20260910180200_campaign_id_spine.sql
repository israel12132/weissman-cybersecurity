-- P0 Campaign Fabric spine: thread one tenant-scoped campaign_id across
-- attack-path snapshots, Council HITL, and SOAR runs. Correlation only —
-- never widens scan scope or auto-discloses findings.

ALTER TABLE attack_path_snapshots
    ADD COLUMN IF NOT EXISTS campaign_id UUID;

CREATE INDEX IF NOT EXISTS ix_attack_path_snapshots_campaign
    ON attack_path_snapshots (tenant_id, campaign_id, computed_at DESC)
    WHERE campaign_id IS NOT NULL;

COMMENT ON COLUMN attack_path_snapshots.campaign_id IS
    'Optional Campaign Fabric correlation. Graph remains client-scoped; this tags the snapshot for Scan→Path→Emulation.';

ALTER TABLE council_hitl_queue
    ADD COLUMN IF NOT EXISTS campaign_id UUID;

CREATE INDEX IF NOT EXISTS ix_council_hitl_campaign
    ON council_hitl_queue (tenant_id, campaign_id)
    WHERE campaign_id IS NOT NULL;

COMMENT ON COLUMN council_hitl_queue.campaign_id IS
    'When set, Council proposals are Campaign-scoped. P0 never auto-fires mapped engines; HITL still required.';

ALTER TABLE weissman_playbook_runs
    ADD COLUMN IF NOT EXISTS campaign_id UUID;

CREATE INDEX IF NOT EXISTS ix_playbook_runs_campaign
    ON weissman_playbook_runs (tenant_id, campaign_id, triggered_at DESC)
    WHERE campaign_id IS NOT NULL;

COMMENT ON COLUMN weissman_playbook_runs.campaign_id IS
    'In-product SOAR correlation to weissman_campaigns. Not an external disclosure channel.';
