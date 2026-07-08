-- Defense-in-depth RLS for the job-bus tables.
--
-- weissman_async_jobs / weissman_job_events / weissman_job_forensic_dlq all carry a
-- tenant_id but were previously left without RLS because the worker dequeues ACROSS
-- tenants (it never sets app.current_tenant_id before reserve/claim). Enabling plain
-- per-tenant RLS would break the worker.
--
-- The policy below preserves the worker path while closing the API leak:
--   * No tenant GUC set (worker: no begin_tenant_tx)  -> unrestricted (dequeue across tenants).
--   * Tenant GUC set (any handler using begin_tenant_tx) -> rows filtered to that tenant, so an
--     API handler that scopes to a tenant can never read/return another tenant's job payloads.
--
-- NULLIF(...,'') handles both "GUC unset" (NULL) and "GUC set to empty string".

ALTER TABLE weissman_async_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_async_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS async_jobs_tenant_or_worker ON weissman_async_jobs;
CREATE POLICY async_jobs_tenant_or_worker ON weissman_async_jobs FOR ALL
    USING (
        NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
        OR tenant_id = current_setting('app.current_tenant_id', true)::bigint
    )
    WITH CHECK (
        NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
        OR tenant_id = current_setting('app.current_tenant_id', true)::bigint
    );

ALTER TABLE weissman_job_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_job_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS job_events_tenant_or_worker ON weissman_job_events;
CREATE POLICY job_events_tenant_or_worker ON weissman_job_events FOR ALL
    USING (
        NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
        OR tenant_id = current_setting('app.current_tenant_id', true)::bigint
    )
    WITH CHECK (
        NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
        OR tenant_id = current_setting('app.current_tenant_id', true)::bigint
    );

ALTER TABLE weissman_job_forensic_dlq ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_job_forensic_dlq FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS job_forensic_dlq_tenant_or_worker ON weissman_job_forensic_dlq;
CREATE POLICY job_forensic_dlq_tenant_or_worker ON weissman_job_forensic_dlq FOR ALL
    USING (
        NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
        OR tenant_id = current_setting('app.current_tenant_id', true)::bigint
    )
    WITH CHECK (
        NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
        OR tenant_id = current_setting('app.current_tenant_id', true)::bigint
    );
