-- SCIM 2.0 directory sync + identity kill-switch (joiner/leaver).
-- Tokens are stored as SHA-256 only. Lookup uses SECURITY DEFINER so the
-- IdP can authenticate before a tenant GUC is set. RLS FORCE on every table.
-- Policies use public.app_current_tenant_id() (never a raw GUC ::bigint cast).

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS scim_id UUID,
    ADD COLUMN IF NOT EXISTS scim_external_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_scim_id
    ON users (scim_id)
    WHERE scim_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_tenant_scim_external
    ON users (tenant_id, scim_external_id)
    WHERE scim_external_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS weissman_scim_tokens (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash    BYTEA NOT NULL UNIQUE,
    token_prefix  TEXT NOT NULL,
    label         TEXT NOT NULL DEFAULT 'entra-okta',
    created_by    BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_scim_tokens_tenant
    ON weissman_scim_tokens (tenant_id)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS weissman_scim_groups (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    external_id   TEXT,
    display_name  TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_scim_groups_tenant_external
    ON weissman_scim_groups (tenant_id, external_id)
    WHERE external_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_scim_groups_tenant_name
    ON weissman_scim_groups (tenant_id, display_name);

CREATE TABLE IF NOT EXISTS weissman_scim_group_members (
    tenant_id  BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_id   UUID NOT NULL REFERENCES weissman_scim_groups(id) ON DELETE CASCADE,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS ix_scim_group_members_user
    ON weissman_scim_group_members (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS weissman_scim_group_role_maps (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_external_id   TEXT NOT NULL,
    group_display_name  TEXT NOT NULL DEFAULT '',
    weissman_role       TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, group_external_id)
);

CREATE TABLE IF NOT EXISTS weissman_scim_events (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action       TEXT NOT NULL,
    user_email   TEXT NOT NULL DEFAULT '',
    user_id      BIGINT,
    role         TEXT,
    sessions_revoked INTEGER NOT NULL DEFAULT 0,
    details      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_scim_events_tenant_time
    ON weissman_scim_events (tenant_id, created_at DESC);

ALTER TABLE weissman_scim_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_scim_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_scim_tokens_tenant ON weissman_scim_tokens;
CREATE POLICY weissman_scim_tokens_tenant ON weissman_scim_tokens FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

ALTER TABLE weissman_scim_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_scim_groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_scim_groups_tenant ON weissman_scim_groups;
CREATE POLICY weissman_scim_groups_tenant ON weissman_scim_groups FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

ALTER TABLE weissman_scim_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_scim_group_members FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_scim_group_members_tenant ON weissman_scim_group_members;
CREATE POLICY weissman_scim_group_members_tenant ON weissman_scim_group_members FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

ALTER TABLE weissman_scim_group_role_maps ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_scim_group_role_maps FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_scim_group_role_maps_tenant ON weissman_scim_group_role_maps;
CREATE POLICY weissman_scim_group_role_maps_tenant ON weissman_scim_group_role_maps FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

ALTER TABLE weissman_scim_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_scim_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_scim_events_tenant ON weissman_scim_events;
CREATE POLICY weissman_scim_events_tenant ON weissman_scim_events FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_scim_tokens TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE weissman_scim_tokens_id_seq TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_scim_groups TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_scim_group_members TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_scim_group_role_maps TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE weissman_scim_group_role_maps_id_seq TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_scim_events TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE weissman_scim_events_id_seq TO weissman_app;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON weissman_scim_groups TO weissman_ro;
        GRANT SELECT ON weissman_scim_group_members TO weissman_ro;
        GRANT SELECT ON weissman_scim_group_role_maps TO weissman_ro;
        GRANT SELECT ON weissman_scim_events TO weissman_ro;
    END IF;
END $$;

-- public, not auth: weissman_app has no USAGE on schema auth.
-- SECURITY DEFINER so FORCE RLS does not hide the hash before tenant GUC is set.
-- Session revoke stays on weissman_auth (BYPASSRLS) — do not GRANT weissman_revoked_tokens to app.
CREATE OR REPLACE FUNCTION public.lookup_scim_token(p_hash BYTEA)
RETURNS TABLE (token_id BIGINT, tenant_id BIGINT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT t.id, t.tenant_id
    FROM weissman_scim_tokens t
    WHERE t.token_hash = p_hash
      AND t.revoked_at IS NULL
    LIMIT 1;
$$;

REVOKE ALL ON FUNCTION public.lookup_scim_token(BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.lookup_scim_token(BYTEA) TO weissman_app;

COMMENT ON TABLE weissman_scim_tokens IS
    'SCIM bearer tokens hashed at rest; raw secret shown once at mint.';
COMMENT ON TABLE weissman_scim_events IS
    'Live joiner/leaver tape. Deprovision revokes sessions; rows are not fabricated.';
COMMENT ON FUNCTION public.lookup_scim_token(BYTEA) IS
    'SECURITY DEFINER token lookup for /scim/v2 before tenant GUC is set.';
