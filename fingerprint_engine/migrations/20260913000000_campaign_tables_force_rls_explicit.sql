-- Adversary-campaign tables: restate FORCE RLS explicitly (idempotent).
--
-- weissman_campaigns / weissman_campaign_steps / weissman_campaign_world_states /
-- weissman_campaign_audit (created in 20260910180000_adversary_campaign_fabric.sql) and
-- weissman_campaign_detection_gaps (20260910200000_apt_emulation_profiles.sql) already
-- ENABLE + FORCE RLS and carry a tenant policy, but they apply it inside a dynamic
-- `DO $$ ... $$` loop that the static rls_policy_contract test cannot see. Restating FORCE
-- per table makes the tenant-isolation contract verifiable in the migration text. FORCE on an
-- already-forced table is a no-op, so this is safe to (re-)run on any database.

ALTER TABLE weissman_campaigns FORCE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaign_steps FORCE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaign_world_states FORCE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaign_audit FORCE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaign_detection_gaps FORCE ROW LEVEL SECURITY;
