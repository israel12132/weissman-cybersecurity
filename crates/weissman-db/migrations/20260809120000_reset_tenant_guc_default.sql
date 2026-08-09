-- Supersedes the hardcoded, DB-name-specific default set by
-- 20260602180000_relax_agent_token_rls.sql:14
--     ALTER DATABASE weissman SET app.current_tenant_id = '0';
--
-- Two problems with that statement, both fixed here:
--
--  1. It names the literal database `weissman`. On any deployment whose POSTGRES_DB
--     is not `weissman` (docker-compose parameterises it; docker-compose.test.yml uses
--     `weissman_test`), that migration aborts with `database "weissman" does not exist`,
--     taking the whole boot-time migration run down with it. This migration is
--     DB-name-agnostic (uses current_database()).
--
--  2. A non-NULL database-level default breaks the job-bus RLS escape hatch. The
--     policies in 20260708120000_rls_job_bus_tables.sql treat "GUC unset" as the
--     worker path (dequeue across tenants):
--         NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL OR ...
--     With a database default of '0', current_setting() never returns NULL/'' , so the
--     policy degenerates to `tenant_id = 0` and the worker (job_queue.rs, which never
--     sets the GUC) can only ever see tenant 0 — every real tenant's job queues forever.
--
-- Resetting the default is safe: every RLS policy in the tree reads the GUC with the
-- missing_ok form current_setting('app.current_tenant_id', true), which returns NULL
-- (not an error) when unset. tenant_id = NULL is false, so tenant-scoped tables fail
-- CLOSED, and the job-bus escape-hatch tables fall into their "unset -> unrestricted"
-- branch, restoring cross-tenant dequeue for the worker. Handlers that call
-- begin_tenant_tx still SET the GUC per transaction, so tenant isolation is unchanged.

DO $$
BEGIN
    EXECUTE format('ALTER DATABASE %I RESET app.current_tenant_id', current_database());
END $$;
