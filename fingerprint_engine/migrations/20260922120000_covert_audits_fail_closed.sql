-- Tighten c2_covert_channel_audits / dns_covert_query_audits from fail-OPEN to fail-CLOSED RLS.
--
-- THE PROBLEM
-- Both tables hold per-tenant customer assessment findings ("Live C2/covert-channel
-- assessment findings ... tenant isolation. Directive 361", see 20260912120100). They were
-- created with the fail-OPEN policy form copied from the job-bus / security_events tables:
--
--     USING (NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
--            OR tenant_id = public.app_current_tenant_id())
--
-- That `IS NULL OR` branch makes every row visible to weissman_app whenever the tenant GUC is
-- unset. It exists deliberately on the job-bus tables (the worker dequeues across tenants with
-- no GUC, and weissman_app holds no grant on them) and on security_events (the worker/migration
-- runner write auth events without a tenant context). NEITHER rationale applies here:
--   * Every writer of these two tables runs inside begin_tenant_tx with the tenant GUC set
--     (advanced_c2_covert_exfil_engine.rs persist path).
--   * There is no unscoped reader — the analyst NL->SQL role (weissman_ro) is not granted SELECT
--     on either table (RO_SELECT_TABLES), and no worker aggregates them.
-- So the only effect of the fail-open branch is a latent cross-tenant DATA LEAK: a future (or
-- forgotten) weissman_app read without begin_tenant_tx would return every tenant's covert-channel
-- findings instead of zero rows. Today that is masked only by the single-tenant deployment.
--
-- THE FIX
-- Adopt the standard fail-CLOSED form used by ~90 other tenant tables. When the GUC is unset,
-- public.app_current_tenant_id() IS NULL (see 20260811000000), so `tenant_id = NULL` matches no
-- rows: a missing begin_tenant_tx now yields zero rows (a safe functional bug) instead of a leak.
-- Writers are unaffected: begin_tenant_tx sets the GUC to the real tenant id, so WITH CHECK holds.

DROP POLICY IF EXISTS c2_covert_audits_tenant ON c2_covert_channel_audits;
CREATE POLICY c2_covert_audits_tenant ON c2_covert_channel_audits
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS dns_covert_audits_tenant ON dns_covert_query_audits;
CREATE POLICY dns_covert_audits_tenant ON dns_covert_query_audits
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

-- Fail loudly if either policy did not end up fail-closed, rather than leave a table that
-- looks protected but still carries the IS NULL escape hatch.
DO $$
DECLARE
    bad_count int;
BEGIN
    SELECT count(*) INTO bad_count
    FROM pg_policy p
    JOIN pg_class c ON c.oid = p.polrelid
    WHERE c.relname IN ('c2_covert_channel_audits', 'dns_covert_query_audits')
      AND pg_get_expr(p.polqual, p.polrelid) ILIKE '%IS NULL%';
    IF bad_count > 0 THEN
        RAISE EXCEPTION 'covert-audit RLS still fail-open (% policy expression(s) contain IS NULL)', bad_count;
    END IF;
END $$;
