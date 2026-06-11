-- ─── Read-only role for the NL → SQL conversational layer ──────────────────
--
-- This role can ONLY do SELECT. It is what `nl_query::execute_plan` connects
-- as. Even if an attacker breaks out of our QueryPlan validator and injects
-- raw SQL, Postgres will reject any non-SELECT.
--
-- The role inherits RLS, so policies still scope queries to the calling tenant.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        -- Lab default only. Production MUST rotate immediately:
        --   ALTER ROLE weissman_ro PASSWORD '<DB_RO_PASSWORD from PRODUCTION.env>';
        -- and set WEISSMAN_READ_ONLY_DATABASE_URL to match.
        CREATE ROLE weissman_ro NOINHERIT LOGIN PASSWORD 'weissman_ro_dev';
    END IF;
END $$;

-- Tightest possible grant — read on the tables we expose, nothing else. Never
-- grant USAGE on sequences; never grant on auth schema.
GRANT CONNECT ON DATABASE weissman TO weissman_ro;
GRANT USAGE  ON SCHEMA public   TO weissman_ro;
-- Whitelist: only the tables that AskWeissman can query.
GRANT SELECT ON
    vulnerabilities,
    weissman_finding_clusters,
    clients,
    risk_graph_nodes,
    risk_graph_edges,
    attack_path_snapshots,
    client_financial_risk_snapshots,
    agent_anomalies,
    endpoint_agents,
    weissman_async_jobs,
    epss_intel,
    kev_intel,
    audit_logs
TO weissman_ro;

-- Block default-future grants — explicit-allow only.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM weissman_ro;

-- Tight per-session limits to defend against runaway queries.
ALTER ROLE weissman_ro SET statement_timeout         = '15s';
ALTER ROLE weissman_ro SET lock_timeout              = '5s';
ALTER ROLE weissman_ro SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE weissman_ro SET work_mem                  = '32MB';

-- ─── Audit table for /api/ask queries (immutable) ──────────────────────────
CREATE TABLE IF NOT EXISTS nl_query_audit (
    id                  BIGSERIAL   PRIMARY KEY,
    tenant_id           BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id             BIGINT,
    asked_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    question            TEXT        NOT NULL,
    plan_json           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    compiled_sql        TEXT        NOT NULL DEFAULT '',
    rows_returned       INTEGER     NOT NULL DEFAULT 0,
    elapsed_ms          INTEGER     NOT NULL DEFAULT 0,
    error               TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_nlqa_recent ON nl_query_audit(tenant_id, asked_at DESC);

ALTER TABLE nl_query_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE nl_query_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS nl_query_audit_tenant ON nl_query_audit;
CREATE POLICY nl_query_audit_tenant ON nl_query_audit FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT ON nl_query_audit TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE nl_query_audit_id_seq TO weissman_app;
