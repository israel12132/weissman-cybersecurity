-- Login workspace picker: slug + display name of active tenants, past RLS.
--
-- The login screen asked for the tenant slug as free text. A user had to already know the exact
-- string (`default`) to get in, and a typo is indistinguishable from a bad password: `api_login`
-- resolves the slug first and fails closed with "Invalid email or password" when no tenant matches.
-- The field is a select now, which needs the list of choices *before* any JWT exists.
--
-- `public.active_tenant_ids()` (migration 20260811000200) cannot back it: that function returns ids
-- exclusively, deliberately. Reading `public.tenants` directly cannot back it either — the table is
-- FORCE ROW LEVEL SECURITY with `USING (id = <current tenant>)`, so for a request that has no
-- authenticated tenant yet the app pool sees zero rows. The picker would render empty and the API
-- would report success, which is the same silent failure 20260811000200 was written to end.
--
-- Hence a second SECURITY DEFINER function, deliberately narrow: slug and name for active tenants,
-- nothing else. No ids, no counts, no timestamps, no user data. Whether an anonymous caller is
-- allowed to see the output at all is an application decision, not a database one — see
-- WEISSMAN_PUBLIC_TENANT_DIRECTORY in fingerprint_engine/src/tenant_directory.rs, which withholds
-- the list on multi-tenant production instances where the slugs are a customer list. EXECUTE is
-- kept off PUBLIC so the database is never the component that leaks it.
--
-- `search_path` is pinned (empty + explicit schema qualification) so a caller cannot shadow
-- `tenants` with a temp table and make a SECURITY DEFINER function read attacker-controlled rows.

CREATE OR REPLACE FUNCTION public.login_tenant_directory()
    RETURNS TABLE (slug text, name text)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = ''
    AS $fn$
    SELECT t.slug, t.name FROM public.tenants t WHERE t.active = true ORDER BY t.slug
$fn$;

COMMENT ON FUNCTION public.login_tenant_directory() IS
    'Slug + display name of active tenants, bypassing RLS on public.tenants. Sole purpose: the '
    'pre-authentication workspace picker on the login screen. Returns no ids and no other columns; '
    'whether anonymous callers may read it is gated by WEISSMAN_PUBLIC_TENANT_DIRECTORY in the API '
    'layer. Background sweeps must keep using public.active_tenant_ids().';

-- The function is owned by the migration role (the tenants owner), which is what makes SECURITY
-- DEFINER see past RLS. Restrict who may invoke it: PUBLIC does not need the tenant list.
REVOKE ALL ON FUNCTION public.login_tenant_directory() FROM PUBLIC;

DO $$
DECLARE
    r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['weissman_app', 'weissman_auth'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION public.login_tenant_directory() TO %I', r);
        END IF;
    END LOOP;
END $$;
