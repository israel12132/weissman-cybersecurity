-- Application role subject to RLS (not superuser). Migrations run as DB owner; app uses this role at runtime.
-- Rotate password in production via: ALTER ROLE weissman_app PASSWORD '...';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_app') THEN
        CREATE ROLE weissman_app LOGIN PASSWORD 'weissman_dev_secret' NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS;
    END IF;
END
$$;
