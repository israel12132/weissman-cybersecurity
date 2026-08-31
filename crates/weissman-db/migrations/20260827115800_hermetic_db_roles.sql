-- Hermetic PostgreSQL role split (weissman_app / weissman_auth / weissman_ro).
--
-- Runtime SQLx pools must never connect as a superuser: FORCE ROW LEVEL SECURITY
-- does not apply to table owners or BYPASSRLS roles. This migration re-asserts
-- the three-role contract on every volume, including ones created before the
-- split was documented, and locks weissman_ro to SELECT on the 13 Ask-Weissman
-- tables with a 15s statement timeout.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_app') THEN
        ALTER ROLE weissman_app NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS;
        COMMENT ON ROLE weissman_app IS
            'Application pool (DATABASE_URL). Subject to FORCE RLS; never BYPASSRLS.';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_auth') THEN
        -- Login / IdP plane only. BYPASSRLS is required for auth.v_user_lookup
        -- (users is FORCE RLS). Must not be used for tenant data queries.
        ALTER ROLE weissman_auth NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT BYPASSRLS;
        COMMENT ON ROLE weissman_auth IS
            'Auth pool (WEISSMAN_AUTH_DATABASE_URL). BYPASSRLS for credential lookup only.';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        ALTER ROLE weissman_ro NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
        ALTER ROLE weissman_ro SET statement_timeout = '15s';
        ALTER ROLE weissman_ro SET lock_timeout = '5s';
        ALTER ROLE weissman_ro SET idle_in_transaction_session_timeout = '30s';
        ALTER ROLE weissman_ro SET work_mem = '32MB';
        ALTER ROLE weissman_ro SET default_transaction_read_only = on;
        COMMENT ON ROLE weissman_ro IS
            'Ask Weissman NL→SQL (WEISSMAN_READ_ONLY_DATABASE_URL). SELECT-only, 15s timeout, 13 tables.';
    END IF;
END
$$;

-- Strip every public-table privilege from weissman_ro, then grant SELECT on the
-- approved 13 only. Future tables cannot leak in via ALTER DEFAULT PRIVILEGES.
DO $$
DECLARE
    r RECORD;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public'
        LOOP
            EXECUTE format('REVOKE ALL ON TABLE public.%I FROM weissman_ro', r.tablename);
        END LOOP;
        FOR r IN SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'public'
        LOOP
            EXECUTE format('REVOKE ALL ON SEQUENCE public.%I FROM weissman_ro', r.sequence_name);
        END LOOP;
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM weissman_ro';
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM weissman_ro';
        EXECUTE $g$GRANT SELECT ON
            vulnerabilities,
            weissman_finding_clusters,
            clients,
            risk_graph_nodes,
            risk_graph_edges,
            attack_path_snapshots,
            client_financial_risk_snapshots,
            agent_anomalies,
            endpoint_agents,
            epss_intel,
            kev_intel,
            audit_logs,
            report_runs
        TO weissman_ro$g$;
    END IF;
END
$$;
