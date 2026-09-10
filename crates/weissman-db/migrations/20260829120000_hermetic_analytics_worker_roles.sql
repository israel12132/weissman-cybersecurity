-- Dedicated BYPASSRLS roles outside weissman_app:
--
--   weissman_analytics  — SELECT-only on billing/quota/LLM meter tables. Midnight
--                         billing and worker aggregation MUST use this pool
--                         (WEISSMAN_ANALYTICS_DATABASE_URL). It cannot read
--                         customer findings, endpoint anomalies, or job payloads.
--   weissman_worker     — DML only on the job-bus tables so claim/heartbeat can
--                         cross tenants without weakening weissman_app RLS
--                         (WEISSMAN_WORKER_DATABASE_URL).
--
-- Both roles are BYPASSRLS. weissman_app stays NOBYPASSRLS + FORCE RLS.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_analytics') THEN
        CREATE ROLE weissman_analytics LOGIN PASSWORD 'weissman_analytics_dev'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;
    ELSE
        ALTER ROLE weissman_analytics NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;
    END IF;
    ALTER ROLE weissman_analytics SET default_transaction_read_only = on;
    ALTER ROLE weissman_analytics SET statement_timeout = '60s';
    COMMENT ON ROLE weissman_analytics IS
        'Analytics pool (WEISSMAN_ANALYTICS_DATABASE_URL). BYPASSRLS, SELECT-only on metrics tables.';

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_worker') THEN
        CREATE ROLE weissman_worker LOGIN PASSWORD 'weissman_worker_dev'
            NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT BYPASSRLS;
    ELSE
        ALTER ROLE weissman_worker NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT BYPASSRLS;
    END IF;
    COMMENT ON ROLE weissman_worker IS
        'Job-bus control pool (WEISSMAN_WORKER_DATABASE_URL). BYPASSRLS; GRANT only on job-bus tables.';
END
$$;

DO $$
BEGIN
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO weissman_analytics, weissman_worker',
        current_database()
    );
END
$$;

GRANT USAGE ON SCHEMA public TO weissman_analytics, weissman_worker;

-- Analytics: strip every table, then grant SELECT on metrics only.
DO $$
DECLARE
    r RECORD;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_analytics') THEN
        FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public'
        LOOP
            EXECUTE format('REVOKE ALL ON TABLE public.%I FROM weissman_analytics', r.tablename);
        END LOOP;
        FOR r IN SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'public'
        LOOP
            EXECUTE format('REVOKE ALL ON SEQUENCE public.%I FROM weissman_analytics', r.sequence_name);
        END LOOP;
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM weissman_analytics';
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM weissman_analytics';
    END IF;
END
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_analytics') THEN
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'billing_plans' AND relnamespace = 'public'::regnamespace) THEN
            GRANT SELECT ON billing_plans TO weissman_analytics;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'tenant_usage_counters' AND relnamespace = 'public'::regnamespace) THEN
            GRANT SELECT ON tenant_usage_counters TO weissman_analytics;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'weissman_tenant_quota_usage' AND relnamespace = 'public'::regnamespace) THEN
            GRANT SELECT ON weissman_tenant_quota_usage TO weissman_analytics;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'tenant_llm_usage' AND relnamespace = 'public'::regnamespace) THEN
            GRANT SELECT ON tenant_llm_usage TO weissman_analytics;
        END IF;
        IF EXISTS (
            SELECT 1 FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proname = 'active_tenant_ids' AND p.pronargs = 0
        ) THEN
            GRANT EXECUTE ON FUNCTION public.active_tenant_ids() TO weissman_analytics;
        END IF;
    END IF;
END
$$;

-- Worker: strip every table, then grant DML on the job-bus only.
DO $$
DECLARE
    r RECORD;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_worker') THEN
        FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public'
        LOOP
            EXECUTE format('REVOKE ALL ON TABLE public.%I FROM weissman_worker', r.tablename);
        END LOOP;
        FOR r IN SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'public'
        LOOP
            EXECUTE format('REVOKE ALL ON SEQUENCE public.%I FROM weissman_worker', r.sequence_name);
        END LOOP;
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM weissman_worker';
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM weissman_worker';

        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'weissman_async_jobs' AND relnamespace = 'public'::regnamespace) THEN
            GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_async_jobs TO weissman_worker;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'weissman_job_events' AND relnamespace = 'public'::regnamespace) THEN
            GRANT SELECT, INSERT ON weissman_job_events TO weissman_worker;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'weissman_job_forensic_dlq' AND relnamespace = 'public'::regnamespace) THEN
            GRANT SELECT, INSERT ON weissman_job_forensic_dlq TO weissman_worker;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'weissman_job_events_seq_seq') THEN
            GRANT USAGE, SELECT ON SEQUENCE weissman_job_events_seq_seq TO weissman_worker;
        END IF;
    END IF;
END
$$;
