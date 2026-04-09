-- Mirror weissman-db migration for sqlx migrate from fingerprint_engine.

CREATE SCHEMA IF NOT EXISTS auth;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true;

CREATE OR REPLACE VIEW auth.v_user_lookup AS
SELECT id,
       tenant_id,
       email,
       password_hash,
       is_active
FROM users;

COMMENT ON VIEW auth.v_user_lookup IS 'Narrow columns for weissman_auth login/JIT; base users table not directly readable by auth role.';

CREATE TABLE IF NOT EXISTS security_events (
    id                 BIGSERIAL PRIMARY KEY,
    event_type         TEXT        NOT NULL DEFAULT 'bypassrls_auth_access',
    tenant_id          BIGINT REFERENCES tenants (id) ON DELETE SET NULL,
    client_ip          INET,
    backend_pid        INTEGER     NOT NULL DEFAULT pg_backend_pid (),
    session_user_name  TEXT        NOT NULL DEFAULT SESSION_USER::text,
    details            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_security_events_created ON security_events (created_at DESC);
CREATE INDEX IF NOT EXISTS ix_security_events_ip_time ON security_events (client_ip, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_security_events_pid_time ON security_events (backend_pid, created_at DESC);

COMMENT ON TABLE security_events IS 'Auth/BYPASSRLS telemetry; consumed by predictive_analyzer + operators.';

GRANT SELECT ON security_events TO weissman_app;

CREATE OR REPLACE FUNCTION auth.audit_auth_access(p_tenant_id BIGINT, p_context TEXT DEFAULT '')
    RETURNS VOID
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, auth
AS
$$
DECLARE
    v_ip       INET := inet_client_addr();
    v_pid      INT := pg_backend_pid();
    v_max      INT := COALESCE(
        NULLIF(trim(current_setting('weissman.auth_tenant_burst_max', true)), '')::INT, 6);
    v_cnt_ip   INT := 0;
    v_cnt_sess INT := 0;
BEGIN
    INSERT INTO public.security_events (event_type, tenant_id, client_ip, backend_pid, details)
    VALUES ('bypassrls_auth_access', p_tenant_id, v_ip, v_pid,
            jsonb_build_object('context', COALESCE(p_context, ''), 'current_user', CURRENT_USER::text));

    IF v_ip IS NOT NULL THEN
        SELECT COUNT(DISTINCT tenant_id)
        INTO v_cnt_ip
        FROM public.security_events
        WHERE client_ip = v_ip
          AND created_at > now() - interval '10 seconds'
          AND event_type = 'bypassrls_auth_access';
    END IF;

    SELECT COUNT(DISTINCT tenant_id)
    INTO v_cnt_sess
    FROM public.security_events
    WHERE backend_pid = v_pid
      AND created_at > now() - interval '10 seconds'
      AND event_type = 'bypassrls_auth_access';

    IF v_cnt_ip >= v_max OR v_cnt_sess >= v_max THEN
        INSERT INTO public.security_events (event_type, tenant_id, client_ip, backend_pid, details)
        VALUES ('auth_abuse_auto_mitigation', NULL, v_ip, v_pid,
                jsonb_build_object('distinct_tenants_ip_window', v_cnt_ip, 'distinct_tenants_session_window',
                                   v_cnt_sess, 'threshold', v_max));
        BEGIN
            ALTER ROLE weissman_auth NOBYPASSRLS;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE WARNING 'weissman_sovereign: could not ALTER ROLE weissman_auth NOBYPASSRLS (run as superuser)';
        END;
        PERFORM pg_notify('weissman_security',
                          json_build_object('kind', 'auth_bypass_burst',
                                            'client_ip', CASE WHEN v_ip IS NULL THEN NULL ELSE host(v_ip) END,
                                            'pid', v_pid,
                                            'tenants_ip', v_cnt_ip, 'tenants_sess', v_cnt_sess)::text);
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION auth.audit_auth_access(BIGINT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth.audit_auth_access(BIGINT, TEXT) TO weissman_auth;

CREATE OR REPLACE FUNCTION auth.auth_insert_user(p_tenant_id BIGINT, p_email TEXT, p_password_hash TEXT,
                                                 p_role TEXT)
    RETURNS BIGINT
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, auth
AS
$$
DECLARE
    nid BIGINT;
BEGIN
    IF p_tenant_id IS NULL THEN
        RAISE EXCEPTION 'tenant required';
    END IF;
    PERFORM auth.audit_auth_access(p_tenant_id, 'auth_insert_user');
    INSERT INTO public.users (tenant_id, email, password_hash, role)
    VALUES (p_tenant_id, trim(p_email), p_password_hash,
            COALESCE(NULLIF(trim(p_role), ''), 'viewer'))
    RETURNING id INTO nid;
    RETURN nid;
END;
$$;

REVOKE ALL ON FUNCTION auth.auth_insert_user(BIGINT, TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth.auth_insert_user(BIGINT, TEXT, TEXT, TEXT) TO weissman_auth;

REVOKE SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER ON TABLE users FROM weissman_auth;
GRANT SELECT ON auth.v_user_lookup TO weissman_auth;
GRANT USAGE ON SCHEMA auth TO weissman_auth;

DO
$$
    BEGIN
        EXECUTE 'REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM weissman_auth';
    EXCEPTION
        WHEN undefined_object THEN NULL;
        WHEN insufficient_privilege THEN NULL;
    END
$$;
DO
$$
    BEGIN
        EXECUTE 'REVOKE TRUNCATE ON ALL TABLES IN SCHEMA intel FROM weissman_auth';
    EXCEPTION
        WHEN invalid_schema_name THEN NULL;
        WHEN insufficient_privilege THEN NULL;
    END
$$;

COMMENT ON ROLE weissman_auth IS 'BYPASSRLS login plane; SELECT auth.v_user_lookup only; use auth.audit_auth_access + auth.auth_insert_user; connect via WEISSMAN_AUTH_DATABASE_URL (peer or rotated secret).';

REVOKE UPDATE ON SEQUENCE users_id_seq FROM weissman_auth;
