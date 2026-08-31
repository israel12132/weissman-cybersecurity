-- OT/ICS RLS must use public.app_current_tenant_id(), never a raw GUC cast.
--
-- 20260827160000 (as first landed on main) enabled FORCE RLS with:
--     tenant_id = current_setting('app.current_tenant_id', true)::bigint
-- That is the form that took production down for four days (2026-08-06 → 2026-08-10):
-- the worker sets app.current_tenant_id to the empty string inside begin_worker_tx, and
-- Postgres may evaluate the ::bigint eagerly, raising
--     invalid input syntax for type bigint: ""
-- The 160000 file in this tree is restated with the helper; this follow-on repairs
-- databases that already applied the original 160000.
--
-- Semantics stay fail-closed (customer OT findings, not the job bus):
--   GUC = '7'        → rows of tenant 7
--   GUC = '' / unset → tenant_id = NULL → no rows

DROP POLICY IF EXISTS ot_ics_safety_events_tenant ON ot_ics_safety_events;
CREATE POLICY ot_ics_safety_events_tenant ON ot_ics_safety_events FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS ot_ics_protocol_baselines_tenant ON ot_ics_protocol_baselines;
CREATE POLICY ot_ics_protocol_baselines_tenant ON ot_ics_protocol_baselines FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS ot_ics_asset_ranges_tenant ON ot_ics_asset_ranges;
CREATE POLICY ot_ics_asset_ranges_tenant ON ot_ics_asset_ranges FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DO $$
DECLARE
    leftover int;
BEGIN
    SELECT count(*)
      INTO leftover
      FROM pg_policy p
      JOIN pg_class c ON c.oid = p.polrelid
     WHERE c.relname IN (
            'ot_ics_safety_events',
            'ot_ics_protocol_baselines',
            'ot_ics_asset_ranges'
       )
       AND (
            coalesce(pg_get_expr(p.polqual, p.polrelid), '')
                LIKE '%current_setting(''app.current_tenant_id''::text, true))::bigint%'
         OR coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')
                LIKE '%current_setting(''app.current_tenant_id''::text, true))::bigint%'
       );
    IF leftover > 0 THEN
        RAISE EXCEPTION
            'OT/ICS tenant policies still cast the raw tenant GUC — refusing to complete';
    END IF;
END $$;
