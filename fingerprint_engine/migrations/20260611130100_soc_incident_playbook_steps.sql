-- IR playbook step completion per incident (finding-backed INC-* cases).

CREATE TABLE IF NOT EXISTS soc_incident_playbook_steps (
    tenant_id   BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id  BIGINT      NOT NULL,
    step_id     INTEGER     NOT NULL,
    done        BOOLEAN     NOT NULL DEFAULT TRUE,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, finding_id, step_id)
);

CREATE INDEX IF NOT EXISTS ix_soc_ir_playbook_finding
    ON soc_incident_playbook_steps (tenant_id, finding_id);

ALTER TABLE soc_incident_playbook_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE soc_incident_playbook_steps FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS soc_incident_playbook_steps_tenant ON soc_incident_playbook_steps;
CREATE POLICY soc_incident_playbook_steps_tenant ON soc_incident_playbook_steps
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON soc_incident_playbook_steps TO weissman_app;
