-- Production Postgres role grants (run as superuser after migrations).
--
-- Password rotation is AUTOMATIC on boot: weissman_db::auth_rotation::
-- sync_role_passwords_from_env_on_boot aligns weissman_app / weissman_auth / weissman_ro /
-- weissman_worker / weissman_analytics with the passwords in the matching DSNs using
-- WEISSMAN_MIGRATE_URL (superuser). You no longer
-- need to hand-run ALTER ROLE ... PASSWORD; just set strong values in .env.
--
-- weissman_app is the RLS-scoped application role. This file grants ONLY what that role
-- needs. It deliberately does NOT grant anything to weissman_auth or weissman_ro: those
-- roles' privileges are owned end-to-end by the sqlx migrations (e.g. the auth-hardening
-- migrations REVOKE direct SELECT on public.users from the BYPASSRLS weissman_auth role,
-- and the NL->SQL migration whitelists exactly the tables weissman_ro may read). Widening
-- them here would silently undo that hardening — so we don't.

GRANT CONNECT ON DATABASE weissman TO weissman_app, weissman_auth, weissman_worker, weissman_analytics;
GRANT USAGE ON SCHEMA public TO weissman_app, weissman_auth, weissman_worker, weissman_analytics;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO weissman_app;

-- Default privileges for future migrations (weissman_app only — see note above).
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO weissman_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO weissman_app;
