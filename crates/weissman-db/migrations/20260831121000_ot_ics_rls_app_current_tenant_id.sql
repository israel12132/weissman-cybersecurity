-- Restate OT/ICS RLS policies with public.app_current_tenant_id().
-- 20260827160000 used current_setting(...)::bigint, which raises
-- `invalid input syntax for type bigint: ""` when the worker GUC is empty.
-- Frozen 27160000 body is not rewritten (checksum already on main).

DROP POLICY IF EXISTS ot_ics_safety_events_tenant ON ot_ics_safety_events;
CREATE POLICY ot_ics_safety_events_tenant ON ot_ics_safety_events FOR ALL
    USING      (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS ot_ics_protocol_baselines_tenant ON ot_ics_protocol_baselines;
CREATE POLICY ot_ics_protocol_baselines_tenant ON ot_ics_protocol_baselines FOR ALL
    USING      (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS ot_ics_asset_ranges_tenant ON ot_ics_asset_ranges;
CREATE POLICY ot_ics_asset_ranges_tenant ON ot_ics_asset_ranges FOR ALL
    USING      (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());
