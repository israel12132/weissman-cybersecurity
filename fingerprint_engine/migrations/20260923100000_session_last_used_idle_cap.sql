-- Session hardening: idle timeout, concurrent-session cap, and sign-out-everywhere.
--
-- Adds two nullable columns to user_refresh_tokens:
--   * last_used_at -- stamped at mint and refreshed on every rotation; the refresh
--     path revokes a session whose gap since last_used_at exceeds the idle window.
--   * created_ip   -- best-effort origin IP (from the auth stream binding), surfaced
--     by the owner's GET /api/auth/sessions listing; carried forward across rotations.
-- Both are nullable; pre-existing rows read as NULL and the application COALESCEs
-- last_used_at to created_at.
--
-- user_refresh_tokens already has ENABLE + FORCE ROW LEVEL SECURITY and a tenant
-- policy (20260611130200_agent_auth_force_rls.sql). This migration only adds columns,
-- an index, and one column-level GRANT, so no RLS policy change is required.

ALTER TABLE user_refresh_tokens
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
ALTER TABLE user_refresh_tokens
    ADD COLUMN IF NOT EXISTS created_ip TEXT;

-- New rows carry a recency stamp even if a future INSERT omits the column.
ALTER TABLE user_refresh_tokens
    ALTER COLUMN last_used_at SET DEFAULT now();

-- The concurrent-session cap (mint-time prune) and the owner's session list both scan
-- a user's live rows ordered by created_at; index that hot partial predicate.
CREATE INDEX IF NOT EXISTS ix_user_refresh_tokens_user_active
    ON user_refresh_tokens (user_id, created_at)
    WHERE revoked_at IS NULL;

-- weissman_auth (auth pool, BYPASSRLS) already holds table-level UPDATE from
-- 20260409103000_user_refresh_tokens.sql; grant the new column explicitly so a future
-- least-privilege tightening to column-level grants (cf. GRANT UPDATE (access_jti,
-- revoked_at) in 20260611130000) keeps last_used_at writable by the rotation path.
-- created_ip is written only at INSERT, already covered by the table-level INSERT grant.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_auth') THEN
    GRANT UPDATE (last_used_at) ON user_refresh_tokens TO weissman_auth;
  END IF;
END $$;
