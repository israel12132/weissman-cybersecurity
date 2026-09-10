-- P1 Proof layer: safe exploitability validation. Findings and campaign steps
-- move observed → validated_safe_proof → proven (or failed_proof / not_applicable).
-- Evidence artifacts are tenant+client scoped. Never widens scan scope. No shells.

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS proof_status TEXT NOT NULL DEFAULT 'observed';

ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_proof_status_chk;
ALTER TABLE vulnerabilities ADD CONSTRAINT vulnerabilities_proof_status_chk CHECK (
    proof_status IN (
        'observed',
        'validated_safe_proof',
        'proven',
        'failed_proof',
        'not_applicable'
    )
);

CREATE INDEX IF NOT EXISTS ix_vuln_proof_status
    ON vulnerabilities (tenant_id, client_id, proof_status)
    WHERE proof_status IN ('validated_safe_proof', 'proven');

COMMENT ON COLUMN vulnerabilities.proof_status IS
    'P1 safe-proof state. Default observed. Proven is evidence-backed exploitability, never invented.';

ALTER TABLE weissman_campaign_steps
    ADD COLUMN IF NOT EXISTS proof_status TEXT NOT NULL DEFAULT 'observed';

ALTER TABLE weissman_campaign_steps DROP CONSTRAINT IF EXISTS weissman_campaign_steps_proof_status_chk;
ALTER TABLE weissman_campaign_steps ADD CONSTRAINT weissman_campaign_steps_proof_status_chk CHECK (
    proof_status IN (
        'observed',
        'validated_safe_proof',
        'proven',
        'failed_proof',
        'not_applicable'
    )
);

ALTER TABLE weissman_campaign_steps
    ADD COLUMN IF NOT EXISTS proof_evidence JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN weissman_campaign_steps.proof_status IS
    'P1 proof gate. Privilege/lateral/impact WorldState facts unlock only when proven.';

ALTER TABLE weissman_campaign_world_states
    ADD COLUMN IF NOT EXISTS proven_facts JSONB NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN weissman_campaign_world_states.proven_facts IS
    'Subset of facts that passed the P1 proof gate. Observation facts may exist without these.';

CREATE TABLE IF NOT EXISTS weissman_proof_artifacts (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    finding_id          TEXT,
    finding_row_id      BIGINT,
    campaign_id         UUID REFERENCES weissman_campaigns(id) ON DELETE CASCADE,
    campaign_step_id    UUID REFERENCES weissman_campaign_steps(id) ON DELETE SET NULL,
    adapter             TEXT NOT NULL,
    kind                TEXT NOT NULL,
    evidence            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT weissman_proof_artifacts_kind_chk CHECK (
        kind IN (
            'request_response_diff',
            'oast_hit',
            'screenshot_ref',
            'cloud_confirmation',
            'sql_error_indicator',
            'xss_reflection',
            'open_redirect',
            'authz_differential',
            'engine_output'
        )
    ),
    CONSTRAINT weissman_proof_artifacts_adapter_chk CHECK (adapter ~ '^[a-z0-9_]+$')
);

CREATE INDEX IF NOT EXISTS ix_weissman_proof_artifacts_finding
    ON weissman_proof_artifacts (tenant_id, finding_row_id, created_at DESC)
    WHERE finding_row_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_weissman_proof_artifacts_campaign
    ON weissman_proof_artifacts (campaign_id, created_at DESC)
    WHERE campaign_id IS NOT NULL;

COMMENT ON TABLE weissman_proof_artifacts IS
    'P1 safe-proof evidence: diffs, OAST hit ids, screenshot refs, cloud confirmations. In-product only.';

ALTER TABLE weissman_proof_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_proof_artifacts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_proof_artifacts_tenant ON weissman_proof_artifacts;
CREATE POLICY weissman_proof_artifacts_tenant ON weissman_proof_artifacts FOR ALL
    USING (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    )
    WITH CHECK (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_proof_artifacts TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE weissman_proof_artifacts_id_seq TO weissman_app;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_worker') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_proof_artifacts TO weissman_worker;
        GRANT USAGE, SELECT ON SEQUENCE weissman_proof_artifacts_id_seq TO weissman_worker;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON weissman_proof_artifacts TO weissman_ro;
    END IF;
END $$;
