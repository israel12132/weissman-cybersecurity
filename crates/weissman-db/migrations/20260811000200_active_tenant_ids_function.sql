-- A safe way for cross-tenant background workers to enumerate tenants.
--
-- `tenants` is FORCE ROW LEVEL SECURITY with `USING (id = <current tenant>)`, so
--
--     SELECT id FROM tenants WHERE active = true
--
-- returns *only the current tenant* on an RLS-subject pool — and zero rows once the GUC is unset,
-- which is exactly what 20260811000100 makes the normal state. Most background workers already
-- avoid this by running that query on the `weissman_auth` (BYPASSRLS) pool, but three did not:
--
--     fingerprint_engine/src/self_improve.rs        — enumerates ALL tenants on the app pool
--     fingerprint_engine/src/sovereign_self_scan.rs — first active tenant on the app pool
--     fingerprint_engine/src/predictive_analyzer.rs — first active tenant on the app pool
--
-- Those three silently degraded to "whatever tenant the connection happened to be scoped to", and
-- with the GUC correctly unset would have degraded again to "no tenants at all" — a self-improve
-- loop that iterates an empty list and a self-scan that errors `no active tenant`, both without a
-- single failing test. Handing them the `weissman_auth` pool would work but hands a BYPASSRLS
-- connection to code that only needs a list of integers.
--
-- This function is the minimum grant that satisfies the need: SECURITY DEFINER so it sees past
-- RLS, but it returns *only ids* — never names, slugs, or any other tenant column — and it is the
-- single greppable place where cross-tenant enumeration is allowed.
--
-- `search_path` is pinned (empty + explicit schema qualification) so a caller cannot shadow
-- `tenants` with a temp table and make a SECURITY DEFINER function read attacker-controlled rows.

CREATE OR REPLACE FUNCTION public.active_tenant_ids()
    RETURNS SETOF bigint
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = ''
    AS $fn$
    SELECT id FROM public.tenants WHERE active = true ORDER BY id
$fn$;

COMMENT ON FUNCTION public.active_tenant_ids() IS
    'Ids of active tenants, bypassing RLS on public.tenants. For cross-tenant background workers '
    'only; returns ids exclusively. Prefer this over querying tenants on a BYPASSRLS pool.';

-- The function is owned by the migration role (the tenants owner), which is what makes SECURITY
-- DEFINER see past RLS. Restrict who may invoke it: PUBLIC does not need cross-tenant enumeration.
REVOKE ALL ON FUNCTION public.active_tenant_ids() FROM PUBLIC;

DO $$
DECLARE
    r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['weissman_app', 'weissman_auth'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION public.active_tenant_ids() TO %I', r);
        END IF;
    END LOOP;
END $$;
