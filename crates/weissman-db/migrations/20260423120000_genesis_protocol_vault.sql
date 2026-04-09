-- Genesis Protocol: preemptive attack-chain research, council-validated "vaccines" (patch + detection), knowledge match on onboarding.

CREATE TABLE genesis_vaccine_vault (
    id                      BIGSERIAL PRIMARY KEY,
    tenant_id               BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tech_fingerprint        TEXT NOT NULL DEFAULT '',
    component_ref           TEXT NOT NULL DEFAULT '',
    attack_chain_json       JSONB NOT NULL DEFAULT '{}'::jsonb,
    remediation_patch       TEXT NOT NULL DEFAULT '',
    detection_signature     TEXT NOT NULL DEFAULT '',
    severity                TEXT NOT NULL DEFAULT 'medium',
    preemptive_validated    BOOLEAN NOT NULL DEFAULT false,
    simulation_feedback     JSONB NOT NULL DEFAULT '[]'::jsonb,
    council_transcript      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_genesis_vault_tenant ON genesis_vaccine_vault(tenant_id);
CREATE INDEX ix_genesis_vault_tenant_fp ON genesis_vaccine_vault(tenant_id, tech_fingerprint);
CREATE INDEX ix_genesis_vault_validated ON genesis_vaccine_vault(tenant_id, preemptive_validated);

ALTER TABLE genesis_vaccine_vault ENABLE ROW LEVEL SECURITY;
ALTER TABLE genesis_vaccine_vault FORCE ROW LEVEL SECURITY;
CREATE POLICY genesis_vaccine_vault_tenant ON genesis_vaccine_vault FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON genesis_vaccine_vault TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE genesis_vaccine_vault_id_seq TO weissman_app;
