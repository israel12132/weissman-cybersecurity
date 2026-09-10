-- cicd_scan_events RLS must use public.app_current_tenant_id(), never a raw GUC cast.
--
-- 20260827120000 enabled FORCE RLS with:
--     tenant_id = current_setting('app.current_tenant_id', true)::bigint
-- That is the exact form that took production down for four days (2026-08-06 → 2026-08-10):
-- the worker sets app.current_tenant_id to the empty string inside begin_worker_tx, and
-- Postgres may evaluate the ::bigint eagerly, raising
--     invalid input syntax for type bigint: ""
-- even when a NULLIF OR-guard is present. Do not edit 20260827120000 — it is already
-- applied. This follow-on restates the policy with the cast-safe helper from
-- 20260811000000_rls_tenant_guc_cast_safety.
--
-- Semantics stay fail-closed for this table (customer CI findings, not the job bus):
--   GUC = '7'        → rows of tenant 7
--   GUC = '' / unset → tenant_id = NULL → no rows
-- Worker/queue code that needs to touch this table must open a tenant-scoped tx.

DROP POLICY IF EXISTS cicd_scan_events_tenant ON cicd_scan_events;
CREATE POLICY cicd_scan_events_tenant ON cicd_scan_events FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

-- Fail the migration rather than leave the outage-shaped cast in place.
DO $$
DECLARE
    leftover int;
BEGIN
    SELECT count(*)
      INTO leftover
      FROM pg_policy p
      JOIN pg_class c ON c.oid = p.polrelid
     WHERE c.relname = 'cicd_scan_events'
       AND (
            coalesce(pg_get_expr(p.polqual, p.polrelid), '')
                LIKE '%current_setting(''app.current_tenant_id''::text, true))::bigint%'
         OR coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')
                LIKE '%current_setting(''app.current_tenant_id''::text, true))::bigint%'
       );
    IF leftover > 0 THEN
        RAISE EXCEPTION
            'cicd_scan_events still casts the raw tenant GUC — refusing to complete';
    END IF;
END $$;
