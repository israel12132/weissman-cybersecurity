-- RLS cast-safety + static-FORCE backfill.
--
-- Two pre-existing contract regressions are closed here without editing any
-- already-applied migration (they run under sqlx Migrator::new().run(), which
-- verifies checksums — editing a shipped file breaks boot):
--
-- 1. CAST SAFETY. Eight post-2026-08-11 migrations reintroduced the outage-shaped
--    tenant predicate that casts the raw app.current_tenant_id GUC to bigint.
--    The worker sets app.current_tenant_id to '' inside begin_worker_tx, and
--    Postgres can evaluate ::bigint eagerly, raising
--        invalid input syntax for type bigint: ""
--    which took production down for four days (2026-08-06 -> 2026-08-10). The
--    cast-safe helper public.app_current_tenant_id() (20260811000000) maps an
--    empty/unset GUC to NULL -> no rows (fail-closed), never an error. This
--    follow-on restates every affected policy with the helper, exactly as
--    20260827120600 did for cicd_scan_events. Semantics are preserved verbatim,
--    including the weissman_client_row_visible(client_id) customer-isolation
--    guard on ioc_sightings and ueba_entity_risk.
--
-- 2. STATIC FORCE VISIBILITY. The weissman_campaign* tables FORCE RLS through a
--    DO/EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t) loop, which
--    the static RLS contract test cannot see. The ALTER ... FORCE statements
--    below are idempotent no-ops at runtime (RLS is already forced) and exist so
--    the contract is statically auditable.

-- ── 1. Cast-safety restatements ──────────────────────────────────────────────

-- 20260827160000_ot_ics_hardening_safety.sql
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

-- 20260910140000_surface_snapshots.sql
DROP POLICY IF EXISTS surface_snapshots_tenant ON surface_snapshots;
CREATE POLICY surface_snapshots_tenant ON surface_snapshots FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

-- 20260910160000_osv_first_seen_hits.sql
DROP POLICY IF EXISTS osv_first_seen_hits_tenant ON osv_first_seen_hits;
CREATE POLICY osv_first_seen_hits_tenant ON osv_first_seen_hits FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

-- 20260911230000_underground_snapshots.sql
DROP POLICY IF EXISTS underground_snapshots_tenant ON underground_snapshots;
CREATE POLICY underground_snapshots_tenant ON underground_snapshots FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

-- 20260912010000_scan_finding_bridge.sql
DROP POLICY IF EXISTS scan_finding_bridge_tenant ON scan_finding_bridge;
CREATE POLICY scan_finding_bridge_tenant ON scan_finding_bridge FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

-- 20260912120200_honey_routing_gateway.sql
DROP POLICY IF EXISTS honey_route_sessions_tenant ON honey_route_sessions;
CREATE POLICY honey_route_sessions_tenant ON honey_route_sessions FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS honey_route_payloads_tenant ON honey_route_payloads;
CREATE POLICY honey_route_payloads_tenant ON honey_route_payloads FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS honey_route_vhost_bindings_tenant ON honey_route_vhost_bindings;
CREATE POLICY honey_route_vhost_bindings_tenant ON honey_route_vhost_bindings FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS honey_route_fair_overrides_tenant ON honey_route_fair_overrides;
CREATE POLICY honey_route_fair_overrides_tenant ON honey_route_fair_overrides FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

-- 20260912160200_llm_ultra_guard.sql
DROP POLICY IF EXISTS llm_guard_events_tenant ON llm_guard_events;
CREATE POLICY llm_guard_events_tenant ON llm_guard_events FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS llm_guard_quarantine_tenant ON llm_guard_quarantine;
CREATE POLICY llm_guard_quarantine_tenant ON llm_guard_quarantine FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS rag_vector_integrity_tenant ON rag_vector_integrity;
CREATE POLICY rag_vector_integrity_tenant ON rag_vector_integrity FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

-- 20260913120000_ioc_feeds_ueba_expansion.sql
-- ioc_sightings and ueba_entity_risk keep the customer-isolation guard
-- weissman_client_row_visible(client_id) alongside the tenant predicate.
DROP POLICY IF EXISTS ioc_sightings_tenant ON ioc_sightings;
CREATE POLICY ioc_sightings_tenant ON ioc_sightings FOR ALL
    USING (tenant_id = public.app_current_tenant_id()
           AND public.weissman_client_row_visible(client_id))
    WITH CHECK (tenant_id = public.app_current_tenant_id()
           AND public.weissman_client_row_visible(client_id));

DROP POLICY IF EXISTS ioc_watchlist_tenant ON ioc_watchlist;
CREATE POLICY ioc_watchlist_tenant ON ioc_watchlist FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS ueba_peer_baselines_tenant ON ueba_peer_baselines;
CREATE POLICY ueba_peer_baselines_tenant ON ueba_peer_baselines FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DROP POLICY IF EXISTS ueba_entity_risk_tenant ON ueba_entity_risk;
CREATE POLICY ueba_entity_risk_tenant ON ueba_entity_risk FOR ALL
    USING (tenant_id = public.app_current_tenant_id()
           AND public.weissman_client_row_visible(client_id))
    WITH CHECK (tenant_id = public.app_current_tenant_id()
           AND public.weissman_client_row_visible(client_id));

-- ── 2. Static FORCE visibility for dynamically-forced campaign tables ─────────
ALTER TABLE weissman_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaigns FORCE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaign_world_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaign_world_states FORCE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaign_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaign_steps FORCE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaign_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaign_audit FORCE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaign_detection_gaps ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaign_detection_gaps FORCE ROW LEVEL SECURITY;
