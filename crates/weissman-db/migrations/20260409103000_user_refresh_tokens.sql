-- Opaque refresh tokens (SHA-256 at rest), rotatable; used with short-lived JWT access cookies.

CREATE TABLE IF NOT EXISTS user_refresh_tokens (
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id    BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash   BYTEA NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ,
    replaced_by  BIGINT REFERENCES user_refresh_tokens(id) ON DELETE SET NULL,
    CONSTRAINT uq_user_refresh_token_hash UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS ix_user_refresh_tokens_lookup
    ON user_refresh_tokens (user_id, tenant_id)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE user_refresh_tokens IS
    'Rotatable opaque refresh tokens; verify only via constant-time hash lookup. Access JWTs stay short-lived.';

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_auth') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON user_refresh_tokens TO weissman_auth;
    GRANT USAGE, SELECT ON SEQUENCE user_refresh_tokens_id_seq TO weissman_auth;
  END IF;
END $$;
