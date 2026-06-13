-- Harden endpoint_agent_enrollment_tokens: scoped client validation, expiry bounds, DB enroll rate limiting.
-- Unauthenticated POST /api/agents/enroll still uses SECURITY DEFINER consume_endpoint_agent_enrollment_token.

-- Drop orphan rows before FK (client must belong to token tenant).
DELETE FROM endpoint_agent_enrollment_tokens AS t
 WHERE NOT EXISTS (
       SELECT 1
         FROM clients AS c
        WHERE c.id = t.client_id
          AND c.tenant_id = t.tenant_id
 );

ALTER TABLE endpoint_agent_enrollment_tokens
    DROP CONSTRAINT IF EXISTS endpoint_agent_enrollment_tokens_client_fk;
ALTER TABLE endpoint_agent_enrollment_tokens
    ADD CONSTRAINT endpoint_agent_enrollment_tokens_client_fk
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE;

ALTER TABLE endpoint_agent_enrollment_tokens
    DROP CONSTRAINT IF EXISTS endpoint_agent_enrollment_tokens_min_validity;
ALTER TABLE endpoint_agent_enrollment_tokens
    ADD CONSTRAINT endpoint_agent_enrollment_tokens_min_validity
    CHECK (expires_at >= created_at + interval '5 minutes');

CREATE OR REPLACE FUNCTION validate_endpoint_agent_enrollment_token_scope()
    RETURNS trigger
    LANGUAGE plpgsql
AS
$$
BEGIN
    IF NEW.expires_at <= NEW.created_at THEN
        RAISE EXCEPTION 'enrollment token expires_at must be after created_at';
    END IF;
    IF NEW.expires_at > NEW.created_at + interval '7 days' THEN
        RAISE EXCEPTION 'enrollment token lifetime exceeds 7 days';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM clients AS c
         WHERE c.id = NEW.client_id
           AND c.tenant_id = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'client_id % not in tenant_id %', NEW.client_id, NEW.tenant_id;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_endpoint_agent_enrollment_token_scope ON endpoint_agent_enrollment_tokens;
CREATE TRIGGER trg_endpoint_agent_enrollment_token_scope
    BEFORE INSERT OR UPDATE ON endpoint_agent_enrollment_tokens
    FOR EACH ROW
    EXECUTE PROCEDURE validate_endpoint_agent_enrollment_token_scope();

CREATE TABLE IF NOT EXISTS endpoint_agent_enroll_attempts (
    id           BIGSERIAL PRIMARY KEY,
    token_hash   TEXT NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_enroll_attempts_hash_time
    ON endpoint_agent_enroll_attempts (token_hash, attempted_at DESC);

COMMENT ON TABLE endpoint_agent_enroll_attempts IS
    'Per-token-hash enroll attempt log for DB rate limiting (15 min window).';

DROP FUNCTION IF EXISTS public.consume_endpoint_agent_enrollment_token(TEXT);

CREATE OR REPLACE FUNCTION public.consume_endpoint_agent_enrollment_token(
    p_token_hash TEXT,
    p_rate_key TEXT DEFAULT NULL
)
    RETURNS TABLE (out_tenant_id BIGINT, out_client_id BIGINT)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public
AS
$$
DECLARE
    v_hash TEXT;
    v_rate_key TEXT;
    v_attempts BIGINT;
    v_max_attempts CONSTANT INT := 30;
    v_window CONSTANT INTERVAL := interval '15 minutes';
BEGIN
    v_hash := trim(p_token_hash);
    IF v_hash IS NULL OR length(v_hash) <> 64 THEN
        RETURN;
    END IF;

    v_rate_key := COALESCE(NULLIF(trim(p_rate_key), ''), v_hash);

    SELECT count(*)::bigint
      INTO v_attempts
      FROM endpoint_agent_enroll_attempts AS a
     WHERE a.token_hash = v_rate_key
       AND a.attempted_at > now() - v_window;

    INSERT INTO endpoint_agent_enroll_attempts (token_hash)
    VALUES (v_rate_key);

    IF v_attempts >= v_max_attempts THEN
        RETURN;
    END IF;

    RETURN QUERY
    UPDATE endpoint_agent_enrollment_tokens AS t
       SET consumed_at = now()
     WHERE t.token_hash = v_hash
       AND t.consumed_at IS NULL
       AND t.revoked_at IS NULL
       AND t.expires_at > now()
       AND EXISTS (
           SELECT 1
             FROM clients AS c
            WHERE c.id = t.client_id
              AND c.tenant_id = t.tenant_id
       )
    RETURNING t.tenant_id, t.client_id;
END;
$$;

REVOKE ALL ON FUNCTION public.consume_endpoint_agent_enrollment_token(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.consume_endpoint_agent_enrollment_token(TEXT, TEXT) TO weissman_app;

GRANT SELECT, INSERT ON endpoint_agent_enroll_attempts TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE endpoint_agent_enroll_attempts_id_seq TO weissman_app;

COMMENT ON FUNCTION public.consume_endpoint_agent_enrollment_token IS
    'Atomically consume a one-time enrollment token by SHA-256 hash for POST /api/agents/enroll; optional rate key for per-hash throttling.';
