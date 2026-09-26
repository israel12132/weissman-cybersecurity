-- WebAuthn / FIDO2 passkeys — phishing-resistant MFA factor (alongside TOTP).
--
-- Three tenant-scoped, FORCE-RLS tables:
--   webauthn_credentials — one row per enrolled passkey. `passkey` is the serialized
--                          webauthn_rs::Passkey (JSONB); `cred_id` is the raw credential
--                          id (BYTEA), globally UNIQUE (random, collision-free).
--   webauthn_reg_state   — pending registration ceremony state (PasskeyRegistration),
--                          keyed by user, short TTL — survives the stateless start→finish gap.
--   webauthn_auth_state  — pending authentication ceremony state (PasskeyAuthentication),
--                          keyed by user, short TTL.
--
-- Every access runs INSIDE a begin_tenant_tx (registration under a live AuthContext;
-- authentication under the mfa_pending token, which carries the tenant), so — unlike
-- api_keys — no SECURITY DEFINER pre-session lookup is required. RLS policy uses
-- public.app_current_tenant_id() (never a raw GUC ::bigint cast). Byte-identical copy
-- in fingerprint_engine/migrations and crates/weissman-db/migrations.

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cred_id       BYTEA NOT NULL UNIQUE,
    passkey       JSONB NOT NULL,
    name          TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_webauthn_credentials_tenant_user
    ON webauthn_credentials (tenant_id, user_id);

ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS webauthn_credentials_tenant ON webauthn_credentials;
CREATE POLICY webauthn_credentials_tenant ON webauthn_credentials FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON webauthn_credentials TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE webauthn_credentials_id_seq TO weissman_app;

-- Pending registration ceremony state (one in-flight per user).
CREATE TABLE IF NOT EXISTS webauthn_reg_state (
    user_id     BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    state       JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_webauthn_reg_state_tenant
    ON webauthn_reg_state (tenant_id);

ALTER TABLE webauthn_reg_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_reg_state FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS webauthn_reg_state_tenant ON webauthn_reg_state;
CREATE POLICY webauthn_reg_state_tenant ON webauthn_reg_state FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON webauthn_reg_state TO weissman_app;

-- Pending authentication ceremony state (one in-flight per user).
CREATE TABLE IF NOT EXISTS webauthn_auth_state (
    user_id     BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    state       JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_webauthn_auth_state_tenant
    ON webauthn_auth_state (tenant_id);

ALTER TABLE webauthn_auth_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_auth_state FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS webauthn_auth_state_tenant ON webauthn_auth_state;
CREATE POLICY webauthn_auth_state_tenant ON webauthn_auth_state FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON webauthn_auth_state TO weissman_app;

-- weissman_ro (read-only analytics role) gets SELECT on the durable credential inventory only.
-- The two *_state tables hold short-TTL ceremony material (challenges / in-flight registration
-- and authentication state); they carry no analytics value and are deliberately NOT exposed to
-- the read-only role, minimizing the surface on which challenge state can be read.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON webauthn_credentials TO weissman_ro;
    END IF;
END $$;

COMMENT ON TABLE webauthn_credentials IS
    'Enrolled WebAuthn/FIDO2 passkeys (serialized webauthn_rs::Passkey as JSONB); phishing-resistant MFA factor.';
COMMENT ON TABLE webauthn_reg_state IS
    'Short-TTL pending WebAuthn registration ceremony state (PasskeyRegistration), keyed by user.';
COMMENT ON TABLE webauthn_auth_state IS
    'Short-TTL pending WebAuthn authentication ceremony state (PasskeyAuthentication), keyed by user.';
