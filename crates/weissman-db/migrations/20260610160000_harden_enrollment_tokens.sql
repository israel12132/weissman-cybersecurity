-- Re-enable RLS on endpoint_agent_enrollment_tokens (disabled in 20260602180000_relax_agent_token_rls.sql).
-- Unauthenticated POST /api/agents/enroll consumes tokens via SECURITY DEFINER RPC (hash lookup only).

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_tokens_active_hash
    ON endpoint_agent_enrollment_tokens (token_hash)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

ALTER TABLE endpoint_agent_enrollment_tokens
    DROP CONSTRAINT IF EXISTS endpoint_agent_enrollment_tokens_expires_after_created;
ALTER TABLE endpoint_agent_enrollment_tokens
    ADD CONSTRAINT endpoint_agent_enrollment_tokens_expires_after_created
    CHECK (expires_at > created_at);

ALTER TABLE endpoint_agent_enrollment_tokens
    DROP CONSTRAINT IF EXISTS endpoint_agent_enrollment_tokens_max_lifetime;
ALTER TABLE endpoint_agent_enrollment_tokens
    ADD CONSTRAINT endpoint_agent_enrollment_tokens_max_lifetime
    CHECK (expires_at <= created_at + interval '7 days');

ALTER TABLE endpoint_agent_enrollment_tokens ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS endpoint_agent_tokens_tenant_isolation ON endpoint_agent_enrollment_tokens;
DROP POLICY IF EXISTS endpoint_agent_tokens_tenant_scope ON endpoint_agent_enrollment_tokens;

CREATE POLICY endpoint_agent_tokens_tenant_scope
    ON endpoint_agent_enrollment_tokens
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

CREATE OR REPLACE FUNCTION public.consume_endpoint_agent_enrollment_token(p_token_hash TEXT)
    RETURNS TABLE (out_tenant_id BIGINT, out_client_id BIGINT)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public
AS
$$
BEGIN
    IF p_token_hash IS NULL OR length(trim(p_token_hash)) <> 64 THEN
        RETURN;
    END IF;

    RETURN QUERY
    UPDATE endpoint_agent_enrollment_tokens AS t
       SET consumed_at = now()
     WHERE t.token_hash = trim(p_token_hash)
       AND t.consumed_at IS NULL
       AND t.revoked_at IS NULL
       AND t.expires_at > now()
    RETURNING t.tenant_id, t.client_id;
END;
$$;

REVOKE ALL ON FUNCTION public.consume_endpoint_agent_enrollment_token(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.consume_endpoint_agent_enrollment_token(TEXT) TO weissman_app;

COMMENT ON FUNCTION public.consume_endpoint_agent_enrollment_token IS
    'Atomically consume a one-time enrollment token by SHA-256 hash for POST /api/agents/enroll.';
