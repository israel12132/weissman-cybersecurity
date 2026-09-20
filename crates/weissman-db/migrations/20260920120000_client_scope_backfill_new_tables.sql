-- Backfill customer (client) isolation onto tenant tables created AFTER the
-- one-time sweeps in 20260826120000_client_scope_isolation.sql and
-- 20260826180000_client_scope_insert_only_policies.sql.
--
-- WHY: those migrations AND-ed `weissman_client_row_visible(client_id)` onto
-- every then-existing policy of every `client_id` table, walling customer A from
-- customer B *inside* a tenant (MSSP portal isolation). But they ran once. Every
-- `client_id` table added since (c2_covert_channel_audits, finding_candidates,
-- ot_ics_*, surface_snapshots, vulnerability_lifecycle_events, honey_route_*,
-- the sovereign_* tables, …) shipped with only the tenant predicate, so a
-- portal-scoped customer (app.current_client_id set) could read a *sibling
-- customer's* rows in those tables — tenant RLS does not catch this because both
-- customers live in the same tenant.
--
-- This re-runs the exact idempotent generic sweep from
-- 20260826180000 (its third DO-block): it AND-s the client-visibility predicate
-- onto the existing policy of every `public` base table that has a `client_id`
-- column and does not yet carry the predicate. It guards each side separately
-- (`IF r.qual IS NOT NULL` / `IF r.with_check IS NOT NULL`) so INSERT-only
-- policies — which allow only WITH CHECK — are handled correctly (Postgres:
-- "only WITH CHECK expression allowed for INSERT"). It is a no-op for tables that
-- already carry the predicate and for tables with no policy (e.g. the
-- intentionally-global cem_dago_telemetry_quarantine_global). tenant_idps is
-- excluded: its client_id is an OAuth client id, not a customer id.
--
-- The companion contract test crates/weissman-db/tests/rls_live_schema_contract.rs
-- introspects the LIVE schema and FAILS CI if any future `client_id` table ships
-- without this predicate, so this manual backfill never needs to be repeated by
-- hand — a new gap turns the build red instead.

DO $$
DECLARE
    r RECORD;
    vis text;
    new_qual text;
    new_check text;
BEGIN
    FOR r IN
        SELECT n.nspname AS schema_name,
               c.relname AS table_name,
               p.polname AS policy_name,
               pg_get_expr(p.polqual, p.polrelid) AS qual,
               pg_get_expr(p.polwithcheck, p.polrelid) AS with_check,
               col.data_type
        FROM pg_policy p
        JOIN pg_class c ON c.oid = p.polrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN information_schema.columns col
          ON col.table_schema = n.nspname
         AND col.table_name = c.relname
         AND col.column_name = 'client_id'
        WHERE n.nspname = 'public'
          AND c.relkind = 'r'
          AND c.relname <> 'tenant_idps'
    LOOP
        CONTINUE WHEN position('weissman_client_row_visible' IN coalesce(r.qual, '') || coalesce(r.with_check, '')) > 0;
        IF r.data_type IN ('bigint', 'integer', 'smallint', 'numeric') THEN
            vis := 'public.weissman_client_row_visible(client_id)';
        ELSE
            vis := 'public.weissman_client_row_visible_text(client_id::text)';
        END IF;
        IF r.qual IS NOT NULL THEN
            new_qual := '(' || r.qual || ') AND ' || vis;
            EXECUTE format(
                'ALTER POLICY %I ON %I.%I USING (%s)',
                r.policy_name, r.schema_name, r.table_name, new_qual
            );
        END IF;
        IF r.with_check IS NOT NULL THEN
            new_check := '(' || r.with_check || ') AND ' || vis;
            EXECUTE format(
                'ALTER POLICY %I ON %I.%I WITH CHECK (%s)',
                r.policy_name, r.schema_name, r.table_name, new_check
            );
        END IF;
    END LOOP;
END $$;
