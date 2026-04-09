-- weissman_auth is used for auth_pool: bootstrap INSERT users, spawn_orchestrator SELECT system_configs,
-- payload_sync_worker INSERT system_configs + dynamic_payloads. Prior grants omitted sequences and system_configs.
-- weissman_app: re-apply blanket grants so existing volumes / partial runs get table + sequence access.

-- ---- weissman_auth (BYPASSRLS; narrow table list was too small for actual call sites) ----
GRANT SELECT ON system_configs TO weissman_auth;
GRANT INSERT, UPDATE, DELETE ON system_configs TO weissman_auth;

-- SERIAL/BIGSERIAL nextval for INSERT INTO users (ensure_admin_user, master bootstrap, OIDC/SAML JIT)
GRANT USAGE, SELECT, UPDATE ON SEQUENCE users_id_seq TO weissman_auth;

-- payload_sync_worker uses auth_pool for global intel rows + per-tenant config keys
GRANT SELECT, INSERT, UPDATE, DELETE ON dynamic_payloads TO weissman_auth;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE dynamic_payloads_id_seq TO weissman_auth;

-- ---- weissman_app (RLS): repair any DB that missed ALL TABLES / ALL SEQUENCES grants ----
GRANT USAGE ON SCHEMA public TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO weissman_app;

-- Future objects created by the superuser during migrations (typical in Docker / WEISSMAN_MIGRATE_URL)
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO weissman_app;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO weissman_app;
