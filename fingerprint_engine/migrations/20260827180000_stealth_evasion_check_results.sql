-- Intelligence-grade stealth evasion check results (COPY ingest + FORCE RLS).

CREATE TABLE IF NOT EXISTS stealth_evasion_check_results (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    check_id        SMALLINT NOT NULL CHECK (check_id BETWEEN 1 AND 500),
    domain          SMALLINT NOT NULL CHECK (domain BETWEEN 1 AND 10),
    status          TEXT NOT NULL,
    severity        TEXT NOT NULL,
    mitre           TEXT NOT NULL DEFAULT '',
    title           TEXT NOT NULL,
    evidence_json   JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_stealth_evasion_check_results_client
    ON stealth_evasion_check_results (tenant_id, client_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_stealth_evasion_check_results_domain
    ON stealth_evasion_check_results (tenant_id, domain, status);

ALTER TABLE stealth_evasion_check_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE stealth_evasion_check_results FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS stealth_evasion_check_results_tenant ON stealth_evasion_check_results;
CREATE POLICY stealth_evasion_check_results_tenant ON stealth_evasion_check_results FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON stealth_evasion_check_results TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE stealth_evasion_check_results_id_seq TO weissman_app;
