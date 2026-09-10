-- Privilege-escalation / credential-access control coverage (all 500 PAC rows,
-- including na and not_observed). FORCE RLS. Bulk UPSERT target for the engine.
-- Unique (tenant_id, host_id, control_id) so one atomic UNNEST write replaces
-- the previous scan for that host without 500 sequential INSERTs.

CREATE TABLE IF NOT EXISTS privilege_escalation_control_results (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id     BIGINT REFERENCES clients(id) ON DELETE CASCADE,
    host_id       TEXT NOT NULL,
    control_id    SMALLINT NOT NULL CHECK (control_id BETWEEN 1 AND 500),
    status        TEXT NOT NULL CHECK (status IN ('pass', 'fail', 'na', 'not_observed')),
    domain        TEXT NOT NULL,
    mitre         TEXT NOT NULL DEFAULT '',
    title         TEXT NOT NULL DEFAULT '',
    evidence      TEXT NOT NULL DEFAULT '',
    job_id        TEXT,
    evaluated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_pac_controls_tenant_host_id
    ON privilege_escalation_control_results (tenant_id, host_id, control_id);

CREATE INDEX IF NOT EXISTS ix_pac_controls_tenant_eval
    ON privilege_escalation_control_results (tenant_id, evaluated_at DESC);

ALTER TABLE privilege_escalation_control_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE privilege_escalation_control_results FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS privilege_escalation_control_results_tenant
    ON privilege_escalation_control_results;
CREATE POLICY privilege_escalation_control_results_tenant
    ON privilege_escalation_control_results
    FOR ALL
    USING      (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON privilege_escalation_control_results TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE privilege_escalation_control_results_id_seq TO weissman_app;
