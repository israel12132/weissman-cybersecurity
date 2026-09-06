-- Architect tenant-scope guard.
--
-- Manual bind_requested_client on every new route is a guaranteed multi-tenant
-- leak. This migration:
--
--   1. FORCE ROW LEVEL SECURITY on every public table that already has RLS
--      enabled, so a forgotten handler on the table-owner path cannot skip
--      policies.
--   2. Dual session GUC helper: SET LOCAL app.current_tenant_id (architect
--      mandate) AND app.current_client_id (existing customer RLS) in one
--      transaction — one truth, two names, no bypass.
--   3. Management table: which users may impersonate / scope-switch to which
--      customer ids. Scope-switch issues a new JWT; it is never a client-side
--      picker that keeps the old token and sends another client_id.
--   4. Append-only audit of every switch (actor, from_cid, to_cid, ts).

-- ── 1. FORCE RLS on every already-protected public table ─────────────────────
DO $$
DECLARE
    t RECORD;
BEGIN
    FOR t IN
        SELECT n.nspname AS nsp, c.relname AS rel
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind = 'r'
          AND c.relrowsecurity
          AND NOT c.relforcerowsecurity
    LOOP
        EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY', t.nsp, t.rel);
    END LOOP;
END $$;

-- ── 2. Dual GUC helper (SET LOCAL via set_config is_local = true) ────────────
CREATE OR REPLACE FUNCTION public.app_set_session_scope(p_tenant_id bigint, p_client_id bigint)
RETURNS void
LANGUAGE plpgsql
AS $fn$
BEGIN
    -- is_local = true ≡ SET LOCAL. Parameterized; never string-concatenated SQL.
    PERFORM set_config('app.current_tenant_id', p_tenant_id::text, true);
    PERFORM set_config(
        'app.current_client_id',
        CASE WHEN p_client_id IS NULL THEN '' ELSE p_client_id::text END,
        true
    );
END;
$fn$;

COMMENT ON FUNCTION public.app_set_session_scope(bigint, bigint) IS
    'Transaction-local dual GUC stamp: app.current_tenant_id (architect) + app.current_client_id (customer RLS compatibility). Empty client GUC = staff/worker (all customers in the tenant).';

GRANT EXECUTE ON FUNCTION public.app_set_session_scope(bigint, bigint) TO weissman_app;
GRANT EXECUTE ON FUNCTION public.app_set_session_scope(bigint, bigint) TO weissman_auth;

-- Persist impersonation cid across refresh-token rotation.
ALTER TABLE user_refresh_tokens
    ADD COLUMN IF NOT EXISTS scope_client_id BIGINT REFERENCES clients(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS ix_user_refresh_tokens_scope_client
    ON user_refresh_tokens (tenant_id, scope_client_id)
    WHERE revoked_at IS NULL AND scope_client_id IS NOT NULL;

COMMENT ON COLUMN user_refresh_tokens.scope_client_id IS
    'JWT cid for this session (portal lock or staff impersonation). Copied on refresh rotation. NULL = unscoped staff/owner.';

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_auth') THEN
    GRANT UPDATE (scope_client_id, access_jti, revoked_at) ON user_refresh_tokens TO weissman_auth;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_app') THEN
    GRANT UPDATE (scope_client_id, access_jti, revoked_at) ON user_refresh_tokens TO weissman_app;
  END IF;
END $$;

-- ── 3. Who may switch to which customer ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_client_scope_grants (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- NULL = wildcard: every customer in the tenant.
    client_id   BIGINT REFERENCES clients(id) ON DELETE CASCADE,
    granted_by  BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_client_scope_grants_wildcard
    ON user_client_scope_grants (user_id)
    WHERE client_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_client_scope_grants_client
    ON user_client_scope_grants (user_id, client_id)
    WHERE client_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_user_client_scope_grants_tenant_user
    ON user_client_scope_grants (tenant_id, user_id);

COMMENT ON TABLE user_client_scope_grants IS
    'Server-side impersonation allow-list. Portal users have no rows. Staff/owner wildcard (client_id NULL) or explicit client ids. Scope-switch authenticates against this table and issues a new JWT cid.';

ALTER TABLE user_client_scope_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_client_scope_grants FORCE ROW LEVEL SECURITY;

-- Management plane: readable/writable only when the customer GUC is empty
-- (unscoped staff/owner transaction). A forgotten handler that inherits a
-- scoped JWT cid therefore sees zero grant rows (fail closed).
DROP POLICY IF EXISTS user_client_scope_grants_tenant ON user_client_scope_grants;
CREATE POLICY user_client_scope_grants_tenant ON user_client_scope_grants
    FOR ALL
    USING (
        tenant_id = public.app_current_tenant_id()
        AND public.app_current_client_id() IS NULL
    )
    WITH CHECK (
        tenant_id = public.app_current_tenant_id()
        AND public.app_current_client_id() IS NULL
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON user_client_scope_grants TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE user_client_scope_grants_id_seq TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON user_client_scope_grants TO weissman_auth;
GRANT USAGE, SELECT ON SEQUENCE user_client_scope_grants_id_seq TO weissman_auth;

-- Seed wildcard grants for every existing non-portal human so MSSP staff keep
-- working after this migration without a manual grant pass.
INSERT INTO user_client_scope_grants (tenant_id, user_id, client_id, granted_by)
SELECT u.tenant_id, u.id, NULL, NULL
FROM users u
WHERE u.assigned_client_id IS NULL
  AND lower(trim(COALESCE(u.role, ''))) <> 'client'
  AND COALESCE(u.is_active, true) = true
  AND NOT EXISTS (
      SELECT 1 FROM user_client_scope_grants g
      WHERE g.user_id = u.id AND g.client_id IS NULL
  );

-- ── 4. Scope-switch audit (append-only) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_scope_switch_audit (
    id             BIGSERIAL PRIMARY KEY,
    tenant_id      BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_user_id  BIGINT NOT NULL,
    from_cid       BIGINT,
    to_cid         BIGINT,
    from_jti       TEXT,
    to_jti         TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_user_scope_switch_audit_actor_ts
    ON user_scope_switch_audit (tenant_id, actor_user_id, created_at DESC);

COMMENT ON TABLE user_scope_switch_audit IS
    'Every impersonation / scope-switch: actor, from_cid, to_cid, timestamps. Append-only.';

ALTER TABLE user_scope_switch_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_scope_switch_audit FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS user_scope_switch_audit_select ON user_scope_switch_audit;
CREATE POLICY user_scope_switch_audit_select ON user_scope_switch_audit
    FOR SELECT
    USING (
        tenant_id = public.app_current_tenant_id()
        AND public.app_current_client_id() IS NULL
    );

DROP POLICY IF EXISTS user_scope_switch_audit_insert ON user_scope_switch_audit;
CREATE POLICY user_scope_switch_audit_insert ON user_scope_switch_audit
    FOR INSERT
    WITH CHECK (
        tenant_id = public.app_current_tenant_id()
        AND public.app_current_client_id() IS NULL
    );

GRANT SELECT, INSERT ON user_scope_switch_audit TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE user_scope_switch_audit_id_seq TO weissman_app;
GRANT SELECT, INSERT ON user_scope_switch_audit TO weissman_auth;
GRANT USAGE, SELECT ON SEQUENCE user_scope_switch_audit_id_seq TO weissman_auth;
