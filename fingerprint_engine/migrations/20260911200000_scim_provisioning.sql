-- SCIM 2.0 provisioning (RFC 7643/7644) for Okta / Entra / Google Workspace.
-- Tokens are stored as SHA-256 hex only. The plaintext bearer is shown once at mint.
-- RLS FORCE. Tenant GUC via public.app_current_tenant_id().

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS scim_external_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_tenant_scim_external
    ON users (tenant_id, scim_external_id)
    WHERE scim_external_id IS NOT NULL AND scim_external_id <> '';

CREATE TABLE IF NOT EXISTS scim_tokens (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    token_prefix    TEXT NOT NULL,
    created_by      BIGINT REFERENCES users(id) ON DELETE SET NULL,
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, token_hash)
);

-- Global unique so lookup_scim_token (no tenant GUC yet) cannot pick the wrong tenant.
CREATE UNIQUE INDEX IF NOT EXISTS ux_scim_tokens_hash ON scim_tokens (token_hash);

CREATE INDEX IF NOT EXISTS ix_scim_tokens_tenant ON scim_tokens (tenant_id, revoked_at);

CREATE TABLE IF NOT EXISTS scim_groups (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name    TEXT NOT NULL,
    external_id     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, display_name)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_scim_groups_tenant_external
    ON scim_groups (tenant_id, external_id)
    WHERE external_id IS NOT NULL AND external_id <> '';

CREATE TABLE IF NOT EXISTS scim_group_members (
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_id        BIGINT NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS ix_scim_group_members_user ON scim_group_members (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS scim_audit_events (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_id        BIGINT REFERENCES scim_tokens(id) ON DELETE SET NULL,
    method          TEXT NOT NULL,
    path            TEXT NOT NULL,
    status          INT NOT NULL,
    detail          TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_scim_audit_tenant_time
    ON scim_audit_events (tenant_id, created_at DESC);

ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scim_tokens_tenant ON scim_tokens;
CREATE POLICY scim_tokens_tenant ON scim_tokens FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

ALTER TABLE scim_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scim_groups_tenant ON scim_groups;
CREATE POLICY scim_groups_tenant ON scim_groups FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

ALTER TABLE scim_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_group_members FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scim_group_members_tenant ON scim_group_members;
CREATE POLICY scim_group_members_tenant ON scim_group_members FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

ALTER TABLE scim_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scim_audit_events_tenant ON scim_audit_events;
CREATE POLICY scim_audit_events_tenant ON scim_audit_events FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON scim_tokens TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE scim_tokens_id_seq TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scim_groups TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE scim_groups_id_seq TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scim_group_members TO weissman_app;
GRANT SELECT, INSERT ON scim_audit_events TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE scim_audit_events_id_seq TO weissman_app;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON scim_tokens, scim_groups, scim_group_members, scim_audit_events TO weissman_ro;
    END IF;
END $$;

-- Hash lookup before tenant GUC exists (Okta bearer). Hash-only; never accepts plaintext.
CREATE OR REPLACE FUNCTION public.lookup_scim_token(p_token_hash TEXT)
    RETURNS TABLE (out_id BIGINT, out_tenant_id BIGINT)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS
$$
BEGIN
    IF p_token_hash IS NULL OR length(trim(p_token_hash)) <> 64 THEN
        RETURN;
    END IF;
    IF trim(p_token_hash) !~ '^[0-9a-f]{64}$' THEN
        RETURN;
    END IF;
    RETURN QUERY
    SELECT t.id, t.tenant_id
      FROM scim_tokens AS t
     WHERE t.token_hash = trim(p_token_hash)
       AND t.revoked_at IS NULL
     LIMIT 1;
END;
$$;

REVOKE ALL ON FUNCTION public.lookup_scim_token(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.lookup_scim_token(TEXT) TO weissman_app;

CREATE INDEX IF NOT EXISTS ix_users_tenant_lower_email
    ON users (tenant_id, lower(email));

COMMENT ON FUNCTION public.lookup_scim_token IS
    'Resolve a SHA-256 SCIM bearer hash to tenant_id for /api/scim/v2 (no plaintext).';
