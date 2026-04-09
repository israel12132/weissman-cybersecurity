-- Mirror weissman-db migration for standalone fingerprint_engine migrate runs.

CREATE TABLE generative_fuzz_winning_payloads (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT REFERENCES clients(id) ON DELETE SET NULL,
    run_id          BIGINT REFERENCES report_runs(id) ON DELETE SET NULL,
    target_url      TEXT NOT NULL,
    payload         TEXT NOT NULL,
    llm_user_prompt TEXT NOT NULL,
    anomaly_type    TEXT NOT NULL DEFAULT '',
    baseline_vs_anomaly TEXT NOT NULL DEFAULT '',
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_gen_fuzz_win_tenant ON generative_fuzz_winning_payloads(tenant_id);
CREATE INDEX ix_gen_fuzz_win_run ON generative_fuzz_winning_payloads(run_id);
CREATE INDEX ix_gen_fuzz_win_client ON generative_fuzz_winning_payloads(client_id);
CREATE INDEX ix_gen_fuzz_win_discovered ON generative_fuzz_winning_payloads(discovered_at DESC);

ALTER TABLE generative_fuzz_winning_payloads ENABLE ROW LEVEL SECURITY;
ALTER TABLE generative_fuzz_winning_payloads FORCE ROW LEVEL SECURITY;
CREATE POLICY generative_fuzz_wins_tenant ON generative_fuzz_winning_payloads FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON generative_fuzz_winning_payloads TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE generative_fuzz_winning_payloads_id_seq TO weissman_app;
