-- P2 APT emulation profiles: detection/control-gap artifacts linked to
-- adversary campaigns. Profile snapshots live on weissman_campaigns.profile_stub.
-- Privilege facts still unlock only when proof_status = proven (P1).
-- No shells, no destructive payloads, no auto external disclosure.

ALTER TABLE weissman_campaigns
    ADD COLUMN IF NOT EXISTS profile_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS ix_weissman_campaigns_profile
    ON weissman_campaigns (tenant_id, profile_id)
    WHERE profile_id <> '';

COMMENT ON COLUMN weissman_campaigns.profile_id IS
    'P2 APT emulation profile id (e.g. ransomware-affiliate). Empty = generic P0 goal-only campaign.';

CREATE TABLE IF NOT EXISTS weissman_campaign_detection_gaps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id    UUID NOT NULL REFERENCES weissman_campaigns(id) ON DELETE CASCADE,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    step_id         UUID REFERENCES weissman_campaign_steps(id) ON DELETE SET NULL,
    technique_id    TEXT NOT NULL DEFAULT '',
    engine_id       TEXT NOT NULL DEFAULT '',
    mitre           TEXT NOT NULL DEFAULT '',
    gap_kind        TEXT NOT NULL,
    control_surface TEXT NOT NULL DEFAULT 'unknown',
    summary         TEXT NOT NULL DEFAULT '',
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT weissman_campaign_detection_gaps_kind_chk CHECK (
        gap_kind IN (
            'proof_failed',
            'job_failed',
            'control_blocked',
            'roe_blocked'
        )
    ),
    CONSTRAINT weissman_campaign_detection_gaps_surface_chk CHECK (
        control_surface IN (
            'waf',
            'edr',
            'mfa',
            'proof_gate',
            'ot_roe',
            'unknown'
        )
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_weissman_campaign_detection_gaps_step_kind
    ON weissman_campaign_detection_gaps (campaign_id, step_id, gap_kind)
    WHERE step_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_weissman_campaign_detection_gaps_campaign
    ON weissman_campaign_detection_gaps (campaign_id, created_at DESC);

COMMENT ON TABLE weissman_campaign_detection_gaps IS
    'Purple-team detection/control gaps: a stage would succeed in theory but proof failed or a control blocked. Linked to campaign. Never invents findings.';

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['weissman_campaign_detection_gaps']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant', t);
        EXECUTE format(
            'CREATE POLICY %I ON %I FOR ALL
               USING (
                 tenant_id = public.app_current_tenant_id()
                 AND public.weissman_client_row_visible(client_id)
               )
               WITH CHECK (
                 tenant_id = public.app_current_tenant_id()
                 AND public.weissman_client_row_visible(client_id)
               )',
            t || '_tenant', t
        );
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO weissman_app',
            t
        );
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_worker') THEN
            EXECUTE format(
                'GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO weissman_worker',
                t
            );
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
            EXECUTE format('GRANT SELECT ON %I TO weissman_ro', t);
        END IF;
    END LOOP;
END $$;
