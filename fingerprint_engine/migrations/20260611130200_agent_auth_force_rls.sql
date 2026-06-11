-- Force RLS on endpoint-agent enrollment tokens and auth session tables still missing it.
-- Auth-plane queries use weissman_auth (BYPASSRLS); policies are defense-in-depth for weissman_app.

ALTER TABLE endpoint_agent_enrollment_tokens FORCE ROW LEVEL SECURITY;

ALTER TABLE user_refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_refresh_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_refresh_tokens_tenant ON user_refresh_tokens;
CREATE POLICY user_refresh_tokens_tenant ON user_refresh_tokens
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE weissman_revoked_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_revoked_tokens FORCE ROW LEVEL SECURITY;
