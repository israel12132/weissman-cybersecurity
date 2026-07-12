-- Tenant-isolation hardening — closes gaps found in the RLS audit.
--
-- 1. compliance_evidence_pack_snapshots: its policy referenced current_setting('app.tenant_id'),
--    a GUC that is set NOWHERE (the whole system uses 'app.current_tenant_id', set by begin_tenant_tx).
--    Effect: the predicate is NULL for every legitimate request (fails closed), and because app.* GUCs
--    are freely settable per session, a crafted `set_config('app.tenant_id', <victim>)` bypasses it.
--    Repoint the policy at the real tenant GUC so isolation tracks the request context.
DROP POLICY IF EXISTS compliance_snapshots_tenant ON compliance_evidence_pack_snapshots;
CREATE POLICY compliance_snapshots_tenant ON compliance_evidence_pack_snapshots FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

-- 2. weissman_async_jobs is intentionally RLS-free (the worker dequeues across tenants). But it was also
--    granted SELECT to weissman_ro — the read-only role behind the AskWeissman NL→SQL layer. With no RLS,
--    an analyst for tenant A could ask a question that runs `SELECT * FROM weissman_async_jobs` and read
--    every tenant's job rows and payload JSONB. Revoke that cross-tenant read; the worker (weissman_app)
--    is unaffected, so cross-tenant dequeue keeps working.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        REVOKE SELECT ON weissman_async_jobs FROM weissman_ro;
    END IF;
END $$;

-- 3. FORCE ROW LEVEL SECURITY on three tables that had ENABLE + a correct tenant policy but were never
--    FORCE'd — matching the fixes already shipped for endpoint_agents / agent_auth. Without FORCE, the
--    table owner (postgres, which runs migrations and any owner-connected job) bypasses the policy.
--    The runtime role weissman_app is NOBYPASSRLS and not the owner, so this is pure defense-in-depth
--    with no effect on the normal request path.
ALTER TABLE engagements           FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence_items        FORCE ROW LEVEL SECURITY;
ALTER TABLE roe_override_requests FORCE ROW LEVEL SECURITY;

-- NOT changed here (documented, deliberate):
--   * weissman_job_events / weissman_job_forensic_dlq — no RLS, but they are NOT granted to weissman_ro,
--     so there is no analyst cross-tenant path. The job-bus worker writes them across tenants via
--     weissman_app; enabling FORCE RLS would break those writes. Left as-is pending a dedicated
--     BYPASSRLS worker role.
--   * security_events — documented intentional security-telemetry plane (see its table comment).
