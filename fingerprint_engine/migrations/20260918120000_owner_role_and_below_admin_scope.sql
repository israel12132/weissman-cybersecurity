-- Owner role + below-admin per-client scoping.
--
-- Two policy changes, both riding on the existing client-isolation machinery
-- (app.current_client_id RLS + the scope middleware) rather than new plumbing:
--
--   1. A new top human role `owner`, ranked above CEO. It is granted only by an
--      existing owner (or superadmin). The database is a second wall: a row may
--      become role='owner' only when app.owner_role_assignment='1', which the
--      admin handler sets after require_can_assign_owner() has passed — exactly
--      mirroring the existing CEO guard.
--
--   2. Any human role BELOW admin (viewer / analyst / operator) may now be
--      pinned to a single customer via users.assigned_client_id. When a client
--      is assigned they are scoped to it by the existing RLS; when none is
--      assigned the scope middleware refuses every non-self-service request, so
--      they see nothing until the owner assigns them a client. Admin, CEO, owner
--      and superadmin remain tenant-wide (assigned_client_id must stay NULL).
--
-- The previous constraint only allowed assigned_client_id for role='client'.
-- The relaxed form permits an OPTIONAL assignment for below-admin roles, forbids
-- it for admin/CEO/owner, and keeps the superadmin (never scoped) and client
-- (always scoped) invariants. Existing rows (below-admin users with a NULL
-- assigned_client_id) satisfy the new form, so no data backfill is required.

DO $$
BEGIN
    ALTER TABLE users DROP CONSTRAINT IF EXISTS users_client_scope_consistency;
    ALTER TABLE users ADD CONSTRAINT users_client_scope_consistency CHECK (
        CASE
            WHEN COALESCE(is_superadmin, false) THEN assigned_client_id IS NULL
            WHEN lower(trim(COALESCE(role, ''))) = 'client' THEN assigned_client_id IS NOT NULL
            WHEN lower(trim(COALESCE(role, ''))) IN ('admin', 'ceo', 'owner')
                THEN assigned_client_id IS NULL
            ELSE TRUE  -- viewer / analyst / operator (and any unknown role): optional
        END
    );
EXCEPTION
    WHEN others THEN
        RAISE NOTICE 'users_client_scope_consistency: %', SQLERRM;
END $$;

-- The auth plane (JIT/SSO provisioning) must never mint the top human roles.
CREATE OR REPLACE FUNCTION auth.auth_insert_user(
    p_tenant_id BIGINT,
    p_email TEXT,
    p_password_hash TEXT,
    p_role TEXT
)
    RETURNS BIGINT
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, auth
AS
$$
DECLARE
    nid BIGINT;
    v_role TEXT;
BEGIN
    IF p_tenant_id IS NULL THEN
        RAISE EXCEPTION 'tenant required';
    END IF;

    v_role := lower(trim(COALESCE(p_role, '')));
    IF v_role = 'ceo' THEN
        RAISE EXCEPTION 'CEO role cannot be provisioned via auth plane';
    END IF;
    IF v_role = 'owner' THEN
        RAISE EXCEPTION 'owner role cannot be provisioned via auth plane';
    END IF;

    PERFORM auth.audit_auth_access(p_tenant_id, 'auth_insert_user');
    INSERT INTO public.users (tenant_id, email, password_hash, role)
    VALUES (
        p_tenant_id,
        trim(p_email),
        p_password_hash,
        COALESCE(NULLIF(trim(p_role), ''), 'viewer')
    )
    RETURNING id INTO nid;
    RETURN nid;
END;
$$;

REVOKE ALL ON FUNCTION auth.auth_insert_user(BIGINT, TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth.auth_insert_user(BIGINT, TEXT, TEXT, TEXT) TO weissman_auth;

-- Second wall on the owner role, mirroring guard_users_ceo_role: INSERT/UPDATE
-- to role='owner' is refused unless app.owner_role_assignment='1' (set only by
-- the admin handler after require_can_assign_owner).
CREATE OR REPLACE FUNCTION guard_users_owner_role()
    RETURNS trigger
    LANGUAGE plpgsql
AS
$$
DECLARE
    new_role TEXT := lower(trim(COALESCE(NEW.role, '')));
    old_role TEXT := lower(trim(COALESCE(OLD.role, '')));
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF new_role = 'owner'
            AND current_setting('app.owner_role_assignment', true) IS DISTINCT FROM '1' THEN
            RAISE EXCEPTION 'owner role assignment not authorized';
        END IF;
    ELSIF TG_OP = 'UPDATE' THEN
        IF new_role = 'owner'
            AND old_role <> 'owner'
            AND current_setting('app.owner_role_assignment', true) IS DISTINCT FROM '1' THEN
            RAISE EXCEPTION 'owner role assignment not authorized';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_guard_users_owner_role ON users;
CREATE TRIGGER trg_guard_users_owner_role
    BEFORE INSERT OR UPDATE OF role ON users
    FOR EACH ROW
    EXECUTE PROCEDURE guard_users_owner_role();

COMMENT ON FUNCTION guard_users_owner_role IS
    'Blocks owner role INSERT/UPDATE unless app.owner_role_assignment=1 (set by authorized admin handlers after require_can_assign_owner).';
