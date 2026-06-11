-- Restrict CEO role assignment: auth plane cannot provision CEO; users table requires explicit GUC.

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

CREATE OR REPLACE FUNCTION guard_users_ceo_role()
    RETURNS trigger
    LANGUAGE plpgsql
AS
$$
DECLARE
    new_role TEXT := lower(trim(COALESCE(NEW.role, '')));
    old_role TEXT := lower(trim(COALESCE(OLD.role, '')));
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF new_role = 'ceo'
            AND current_setting('app.ceo_role_assignment', true) IS DISTINCT FROM '1' THEN
            RAISE EXCEPTION 'CEO role assignment not authorized';
        END IF;
    ELSIF TG_OP = 'UPDATE' THEN
        IF new_role = 'ceo'
            AND old_role <> 'ceo'
            AND current_setting('app.ceo_role_assignment', true) IS DISTINCT FROM '1' THEN
            RAISE EXCEPTION 'CEO role assignment not authorized';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_guard_users_ceo_role ON users;
CREATE TRIGGER trg_guard_users_ceo_role
    BEFORE INSERT OR UPDATE OF role ON users
    FOR EACH ROW
    EXECUTE PROCEDURE guard_users_ceo_role();

COMMENT ON FUNCTION guard_users_ceo_role IS
    'Blocks CEO role INSERT/UPDATE unless app.ceo_role_assignment=1 (set by authorized admin handlers).';
