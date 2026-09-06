-- Fail-closed tenant RLS on the job-bus.
--
-- 20260708120000 used "GUC unset OR tenant_id = GUC" so the worker could claim
-- across tenants as weissman_app. That left every tenant's scan payloads, targets
-- and short-lived tokens readable to any weissman_app session that omitted the GUC
-- (injection, missing begin_tenant_tx, compromised replica).
--
-- Cross-tenant claim now belongs to weissman_worker (BYPASSRLS, job-bus GRANTs
-- only — 20260829120050). weissman_app must set a real tenant GUC; empty/unset
-- GUC yields zero rows (app_current_tenant_id() is NULL).

DROP POLICY IF EXISTS async_jobs_tenant_or_worker ON weissman_async_jobs;
DROP POLICY IF EXISTS async_jobs_tenant_strict ON weissman_async_jobs;
CREATE POLICY async_jobs_tenant_strict ON weissman_async_jobs FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS job_events_tenant_or_worker ON weissman_job_events;
DROP POLICY IF EXISTS job_events_tenant_strict ON weissman_job_events;
CREATE POLICY job_events_tenant_strict ON weissman_job_events FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS job_forensic_dlq_tenant_or_worker ON weissman_job_forensic_dlq;
DROP POLICY IF EXISTS job_forensic_dlq_tenant_strict ON weissman_job_forensic_dlq;
CREATE POLICY job_forensic_dlq_tenant_strict ON weissman_job_forensic_dlq FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

COMMENT ON TABLE weissman_async_jobs IS
  'Durable job queue. RLS ENABLED + FORCED, fail-closed: tenant_id = app_current_tenant_id(). '
  'weissman_app never sees other tenants. Cross-tenant claim uses weissman_worker (BYPASSRLS).';

COMMENT ON TABLE weissman_job_events IS
  'Append-only job event log. RLS ENABLED + FORCED, fail-closed tenant policy. '
  'Worker appends via weissman_worker; API appends with begin_tenant_tx.';

COMMENT ON TABLE weissman_job_forensic_dlq IS
  'Forensic DLQ bundles. RLS ENABLED + FORCED, fail-closed tenant policy. '
  'Worker writes via weissman_worker.';
