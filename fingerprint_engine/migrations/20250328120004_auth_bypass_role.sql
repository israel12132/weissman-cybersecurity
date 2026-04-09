-- Narrow BYPASSRLS role: use only for password / OIDC / SAML resolution (explicit WHERE tenant_slug / email in code).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_auth') THEN
        CREATE ROLE weissman_auth LOGIN PASSWORD 'weissman_auth_dev' NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT BYPASSRLS;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO weissman_auth;
GRANT SELECT ON tenants, users, tenant_idps TO weissman_auth;
GRANT INSERT, UPDATE ON users TO weissman_auth;
