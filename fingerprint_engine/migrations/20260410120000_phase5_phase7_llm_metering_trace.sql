-- Phase 5: per-tenant LLM token metering (billing / abuse).
-- Phase 7: trace_id on durable async jobs for distributed correlation.

CREATE TABLE IF NOT EXISTS tenant_llm_usage (
    id bigserial PRIMARY KEY,
    tenant_id bigint NOT NULL REFERENCES tenants (id),
    prompt_tokens integer NOT NULL DEFAULT 0,
    completion_tokens integer NOT NULL DEFAULT 0,
    total_tokens integer NOT NULL DEFAULT 0,
    model text NOT NULL DEFAULT '',
    operation text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_tenant_llm_usage_tenant_created
    ON tenant_llm_usage (tenant_id, created_at DESC);

ALTER TABLE tenant_llm_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_llm_usage FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_llm_usage_tenant ON tenant_llm_usage FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_llm_usage TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_llm_usage TO weissman_auth;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO weissman_app;

ALTER TABLE weissman_async_jobs
    ADD COLUMN IF NOT EXISTS trace_id text;

CREATE INDEX IF NOT EXISTS ix_weissman_async_jobs_trace_id
    ON weissman_async_jobs (trace_id)
    WHERE trace_id IS NOT NULL;

COMMENT ON COLUMN weissman_async_jobs.trace_id IS 'Request/trace id from HTTP edge; propagated for worker and audit correlation.';
COMMENT ON TABLE tenant_llm_usage IS 'Append-only LLM token usage per tenant (RLS-scoped).';
