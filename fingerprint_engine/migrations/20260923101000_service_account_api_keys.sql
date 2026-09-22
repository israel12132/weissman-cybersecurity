-- Service-account API keys — non-interactive, scoped machine credentials.
-- The secret is shown ONCE at creation; only sha256(secret) is stored (BYTEA).
-- Lookup is by the globally-unique key_prefix via a SECURITY DEFINER function so a
-- machine caller can be resolved before any tenant GUC is set (it has no session).
-- RLS FORCE on the table; tenant policy via public.app_current_tenant_id()
-- (never a raw GUC ::bigint cast). Byte-identical copy in fingerprint_engine/migrations.

CREATE TABLE IF NOT EXISTS api_keys (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    key_prefix    TEXT NOT NULL UNIQUE,
    key_hash      BYTEA NOT NULL,
    scopes        TEXT[] NOT NULL DEFAULT '{}',
    created_by    BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);

-- key_prefix is globally UNIQUE so lookup_api_key (no tenant GUC yet) cannot pick
-- the wrong tenant's row.
CREATE INDEX IF NOT EXISTS ix_api_keys_tenant
    ON api_keys (tenant_id)
    WHERE revoked_at IS NULL;

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS api_keys_tenant ON api_keys;
CREATE POLICY api_keys_tenant ON api_keys FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE api_keys_id_seq TO weissman_app;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON api_keys TO weissman_ro;
    END IF;
END $$;

-- public, not auth: weissman_app has no USAGE on schema auth.
-- SECURITY DEFINER so FORCE RLS does not hide the row before the tenant GUC is set.
-- Resolves by the globally-unique key_prefix and returns the row regardless of
-- revoked_at / expires_at; the application verifies sha256(secret) against key_hash
-- in constant time and enforces revoked_at / expires_at itself.
CREATE OR REPLACE FUNCTION public.lookup_api_key(p_prefix TEXT)
RETURNS TABLE (id BIGINT, tenant_id BIGINT, key_hash BYTEA, scopes TEXT[],
               expires_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT k.id, k.tenant_id, k.key_hash, k.scopes, k.expires_at, k.revoked_at
    FROM api_keys k
    WHERE k.key_prefix = p_prefix
    LIMIT 1;
$$;

REVOKE ALL ON FUNCTION public.lookup_api_key(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.lookup_api_key(TEXT) TO weissman_app;

COMMENT ON TABLE api_keys IS
    'Service-account API keys (wsk_<prefix>_<secret>); only sha256(secret) stored, secret shown once at creation.';
COMMENT ON FUNCTION public.lookup_api_key(TEXT) IS
    'SECURITY DEFINER lookup of a service-account API key by its public prefix before a tenant GUC is set.';
