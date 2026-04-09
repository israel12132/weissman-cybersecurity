-- Row-Level Security: tenant_id must match session GUC app.current_tenant_id
-- Orchestrator / API: BEGIN; SELECT set_config('app.current_tenant_id', '<id>', true); ... COMMIT;
-- Platform tables dynamic_payloads / ephemeral_payloads: no RLS (shared intel)

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
-- Tenant row visible when session is scoped to that tenant (API requests after JWT resolution).
CREATE POLICY tenants_tenant_scope ON tenants FOR SELECT
    USING (id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_tenant ON users FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients FORCE ROW LEVEL SECURITY;
CREATE POLICY clients_tenant ON clients FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE report_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY report_runs_tenant ON report_runs FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities FORCE ROW LEVEL SECURITY;
CREATE POLICY vulnerabilities_tenant ON vulnerabilities FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE system_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_configs FORCE ROW LEVEL SECURITY;
CREATE POLICY system_configs_tenant ON system_configs FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE asm_graph_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE asm_graph_nodes FORCE ROW LEVEL SECURITY;
CREATE POLICY asm_graph_nodes_tenant ON asm_graph_nodes FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE asm_graph_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE asm_graph_edges FORCE ROW LEVEL SECURITY;
CREATE POLICY asm_graph_edges_tenant ON asm_graph_edges FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE semantic_fuzz_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE semantic_fuzz_log FORCE ROW LEVEL SECURITY;
CREATE POLICY semantic_fuzz_log_tenant ON semantic_fuzz_log FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE poe_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE poe_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY poe_jobs_tenant ON poe_jobs FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE attack_chain ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_chain FORCE ROW LEVEL SECURITY;
CREATE POLICY attack_chain_tenant ON attack_chain FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE identity_contexts ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_contexts FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_contexts_tenant ON identity_contexts FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE privilege_escalation_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE privilege_escalation_events FORCE ROW LEVEL SECURITY;
CREATE POLICY priv_esc_tenant ON privilege_escalation_events FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE risk_graph_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_graph_nodes FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_graph_nodes_tenant ON risk_graph_nodes FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE risk_graph_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_graph_edges FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_graph_edges_tenant ON risk_graph_edges FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE runtime_traces ENABLE ROW LEVEL SECURITY;
ALTER TABLE runtime_traces FORCE ROW LEVEL SECURITY;
CREATE POLICY runtime_traces_tenant ON runtime_traces FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE heal_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE heal_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY heal_requests_tenant ON heal_requests FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE deception_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE deception_assets FORCE ROW LEVEL SECURITY;
CREATE POLICY deception_assets_tenant ON deception_assets FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE deception_triggers ENABLE ROW LEVEL SECURITY;
ALTER TABLE deception_triggers FORCE ROW LEVEL SECURITY;
CREATE POLICY deception_triggers_tenant ON deception_triggers FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE pipeline_run_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE pipeline_run_state FORCE ROW LEVEL SECURITY;
CREATE POLICY pipeline_run_state_tenant ON pipeline_run_state FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_logs_tenant ON audit_logs FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE tenant_idps ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_idps FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_idps_tenant ON tenant_idps FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

-- Bootstrap: allow first-time tenant listing for login resolution (optional superuser in compose)
-- Application sets GUC before every pooled query.
