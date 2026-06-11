-- JWT jti revocation on logout + link refresh rows to access jti for session tracking.

CREATE TABLE IF NOT EXISTS weissman_revoked_tokens (
    jti         TEXT PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_weissman_revoked_tokens_expires
    ON weissman_revoked_tokens (expires_at);

COMMENT ON TABLE weissman_revoked_tokens IS
    'Revoked access JWT jti values; checked at verify time until expires_at.';

ALTER TABLE user_refresh_tokens
    ADD COLUMN IF NOT EXISTS access_jti TEXT;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_auth') THEN
    GRANT SELECT, INSERT, DELETE ON weissman_revoked_tokens TO weissman_auth;
    GRANT UPDATE (access_jti, revoked_at) ON user_refresh_tokens TO weissman_auth;
  END IF;
END $$;
