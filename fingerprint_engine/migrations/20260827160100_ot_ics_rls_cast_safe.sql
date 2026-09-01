-- OT/ICS RLS must use public.app_current_tenant_id(), never a raw GUC cast.
--
-- 20260827160000 enabled FORCE RLS with:
--     tenant_id = current_setting('app.current_tenant_id', true)::bigint
-- That is the exact form that took production down for four days (2026-08-06 → 2026-08-10).
-- Do not edit 20260827160000 — it may already be applied. This follow-on restates
-- the three tenant policies with the cast-safe helper from
-- 20260811000000_rls_tenant_guc_cast_safety.
--
-- Semantics stay fail-closed (OT safety events / baselines / asset ranges are
-- customer data): GUC = '7' → tenant 7; GUC = '' / unset → no rows.

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
            'ot_ics RLS still casts the raw tenant GUC — refusing to complete';
    END IF;
END $$;
