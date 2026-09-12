-- Ask Weissman hermetic guards on weissman_ro.
--
-- Re-assert session limits so a role that drifted (or a database restored from an
-- older dump) cannot run NL→SQL without statement_timeout = 15000 ms (15s),
-- lock/idle bounds, and default_transaction_read_only. The application pool also
-- SET LOCAL's these on every /api/ask transaction; this is defence in depth at
-- the role default layer.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        ALTER ROLE weissman_ro SET statement_timeout = 15000;
        ALTER ROLE weissman_ro SET lock_timeout = '5s';
        ALTER ROLE weissman_ro SET idle_in_transaction_session_timeout = '30s';
        ALTER ROLE weissman_ro SET work_mem = '32MB';
        ALTER ROLE weissman_ro SET default_transaction_read_only = on;
    END IF;
END $$;
