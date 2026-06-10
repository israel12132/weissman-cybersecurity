-- Self-serve signup + email verification.
--
-- Public `POST /api/auth/signup` writes a pending_signups row + emits a verification
-- email containing a hashed token. The user clicks the link → `GET /api/auth/verify`
-- promotes the row into a real tenant + user. Pending rows expire after 24h.
--
-- We intentionally DO NOT create the tenant/user until verification completes — keeps
-- the auth.users table clean of bot/scraper signups.

CREATE TABLE IF NOT EXISTS pending_signups (
    id              BIGSERIAL PRIMARY KEY,
    email           TEXT          NOT NULL,
    workspace_name  TEXT          NOT NULL,
    requested_slug  TEXT          NOT NULL,
    bcrypt_hash     TEXT          NOT NULL,
    token_hash      TEXT          NOT NULL,    -- sha256 of the link token
    ip_address      TEXT          NOT NULL DEFAULT '',
    user_agent      TEXT          NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ   NOT NULL,
    consumed_at     TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_pending_signups_token       ON pending_signups (token_hash);
CREATE        INDEX IF NOT EXISTS ix_pending_signups_email       ON pending_signups (lower(email));
CREATE        INDEX IF NOT EXISTS ix_pending_signups_unconsumed  ON pending_signups (expires_at) WHERE consumed_at IS NULL;

-- Public table — no RLS needed (no tenant_id yet); rate-limiting is enforced at the
-- API edge per-IP.
ALTER TABLE pending_signups DISABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE ON pending_signups TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE pending_signups_id_seq TO weissman_app;
