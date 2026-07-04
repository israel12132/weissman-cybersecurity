-- Production Postgres role grants + password rotation (run as superuser after migrations).
-- NEVER leave weissman_dev_secret / weissman_auth_dev in production DATABASE_URL.

-- 1) Rotate passwords (generate: openssl rand -base64 32)
-- ALTER ROLE weissman_app PASSWORD 'STRONG_APP_PASSWORD';
-- ALTER ROLE weissman_auth PASSWORD 'STRONG_AUTH_PASSWORD';
-- ALTER ROLE weissman_ro PASSWORD 'STRONG_RO_PASSWORD';

GRANT CONNECT ON DATABASE weissman TO weissman_app, weissman_auth;
GRANT USAGE ON SCHEMA public TO weissman_app, weissman_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO weissman_app;

-- weissman_auth: login lookups only (BYPASSRLS via migration 20250328120004)
GRANT SELECT ON ALL TABLES IN SCHEMA public TO weissman_auth;

-- Default privileges for future migrations
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO weissman_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO weissman_app;
