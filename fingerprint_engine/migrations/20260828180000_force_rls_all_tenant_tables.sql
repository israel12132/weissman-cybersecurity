-- Catch-all FORCE ROW LEVEL SECURITY on every table that already has RLS
-- enabled. Does NOT ENABLE RLS on tables that currently have none: enabling
-- RLS on a table without a tenant-or-worker policy would break empty-GUC
-- worker paths. FORCE is required so table owners and the query planner
-- cannot skip USING quals (join uniqueness / timing side-channels).

ALTER TABLE IF EXISTS public.tenants FORCE ROW LEVEL SECURITY;

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT n.nspname AS schema_name, c.relname AS table_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'r'
          AND c.relrowsecurity
          AND NOT c.relforcerowsecurity
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    LOOP
        EXECUTE format(
            'ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY',
            r.schema_name,
            r.table_name
        );
    END LOOP;

    -- Database default: row_security stays on. Non-BYPASSRLS roles cannot
    -- disable it; this pins the default so a leftover ALTER DATABASE … SET
    -- row_security = off cannot silently strip policies.
    EXECUTE format(
        'ALTER DATABASE %I SET row_security = on',
        current_database()
    );
END
$$;
