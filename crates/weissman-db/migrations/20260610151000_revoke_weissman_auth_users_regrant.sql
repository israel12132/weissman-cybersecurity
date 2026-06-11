-- Undo accidental re-grant from 20260528053000_findings_raw_data_and_persistence.sql.
--
-- 20260418120000_sovereign_auth_hardening.sql restricts weissman_auth to auth.v_user_lookup
-- and SECURITY DEFINER helpers (auth.auth_insert_user). The findings migration re-opened
-- direct heap access on public.users, undoing that hardening.
--
-- /api/admin/users uses app_pool + begin_tenant_tx (weissman_app + RLS), not auth_pool.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_auth') THEN
        REVOKE SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER
            ON TABLE public.users FROM weissman_auth;

        GRANT SELECT ON auth.v_user_lookup TO weissman_auth;
        GRANT USAGE ON SCHEMA auth TO weissman_auth;

        -- Sequence: auth inserts via auth.auth_insert_user (SECURITY DEFINER); no setval.
        REVOKE ALL ON SEQUENCE public.users_id_seq FROM weissman_auth;
        GRANT USAGE, SELECT ON SEQUENCE public.users_id_seq TO weissman_auth;
    END IF;
END
$$;
