-- PgBouncer auth_query support for the hermetic multi-role split.
--
-- The runtime pools log in as five different roles (weissman_app/auth/worker/analytics/ro). SCRAM
-- cannot be proxied and a static userlist would have to be regenerated on every password rotation
-- (auth_rotation.rs), so transaction pooling requires PgBouncer auth_query: the pooler connects as a
-- dedicated low-privilege role and calls this function to fetch the SCRAM verifier for whichever
-- role the client presents. Because it reads live pg_authid, app-role password rotations are
-- transparent to the pooler.
--
-- Operator steps (credentials never live in git):
--   CREATE ROLE weissman_pgbouncer LOGIN PASSWORD '<strong>'
--     NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
-- then on the pooler: AUTH_USER=weissman_pgbouncer,
--   AUTH_QUERY=SELECT rolname, rolpassword FROM public.pgbouncer_get_auth($1)
--
-- Owned by the migration role (WEISSMAN_MIGRATE_URL, superuser) so SECURITY DEFINER can read
-- pg_authid.rolpassword. The IN (...) whitelist ensures only the intended runtime roles are ever
-- returned — never postgres/superuser verifiers.
CREATE OR REPLACE FUNCTION public.pgbouncer_get_auth(p_rolname text)
RETURNS TABLE (rolname text, rolpassword text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT a.rolname::text, a.rolpassword::text
    FROM pg_authid a
    WHERE a.rolname = p_rolname
      AND a.rolcanlogin
      AND a.rolname IN (
          'weissman_app',
          'weissman_auth',
          'weissman_worker',
          'weissman_analytics',
          'weissman_ro'
      );
$$;

REVOKE ALL ON FUNCTION public.pgbouncer_get_auth(text) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_pgbouncer') THEN
        GRANT EXECUTE ON FUNCTION public.pgbouncer_get_auth(text) TO weissman_pgbouncer;
    END IF;
END
$$;
