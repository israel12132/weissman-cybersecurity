-- security_events was the ONE tenant table with no row-level security.
--
-- 91 tables in this schema carry a tenant_id. 90 of them have RLS enabled AND forced.
-- security_events had relrowsecurity = false, relforcerowsecurity = false, zero policies, and
-- weissman_app holding SELECT/INSERT/UPDATE/DELETE. It holds authentication and BYPASSRLS audit
-- events — client IPs, event types, and free-form details — which is precisely the data a tenant
-- must never see for another tenant.
--
-- No leak has occurred yet only because the deployment has a single tenant. The exposure begins
-- with customer number two.
--
-- This policy matches the convention used by the other 90 tables: when the tenant GUC is unset the
-- row is visible, because the worker and the migration runner legitimately operate without a
-- tenant context. That is also why RLS ALONE DOES NOT CLOSE THIS. The three code paths that read
-- this table did so on a plain pool with no GUC set, so they would still have seen every tenant's
-- rows after this migration. Those queries are scoped in the same change; this migration is the
-- defense-in-depth half, and it makes any FUTURE tenant-scoped reader fail closed instead of
-- silently reading the whole table.
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS security_events_tenant_or_worker ON public.security_events;
CREATE POLICY security_events_tenant_or_worker ON public.security_events
  USING (
    NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
    OR tenant_id = public.app_current_tenant_id()
  )
  WITH CHECK (
    NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
    OR tenant_id = public.app_current_tenant_id()
  );

-- Fail loudly rather than leave the table half-protected: a migration that "succeeded" while RLS
-- stayed off is exactly the shape of failure this table already demonstrated.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relname = 'security_events'
       AND c.relrowsecurity
       AND c.relforcerowsecurity
  ) THEN
    RAISE EXCEPTION 'security_events RLS was not applied — refusing to complete the migration';
  END IF;
END $$;
