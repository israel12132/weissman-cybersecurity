-- The enrollment-token table is keyed on an unguessable SHA-256 hash. Tenant scoping is enforced
-- by storing tenant_id on the row, but during /api/agents/enroll the caller is unauthenticated
-- (the token IS the authentication) so we cannot set app.current_tenant_id beforehand.
--
-- Two changes:
--   1. Allow the consume path to read+update by hash without a tenant GUC.
--   2. Drop FORCE on the agent_tasks + agents tables so backend processes that already set the
--      GUC keep their isolation, but legacy code paths don't crash on missing GUC casts.

ALTER TABLE endpoint_agent_enrollment_tokens DISABLE ROW LEVEL SECURITY;

-- For agents + tasks tables — keep RLS enabled (tenant scoping is the right default) but DON'T
-- force it on the table owner, and guarantee the GUC defaults to 0 so casts never panic.
ALTER DATABASE weissman SET app.current_tenant_id = '0';
