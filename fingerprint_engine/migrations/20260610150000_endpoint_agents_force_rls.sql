-- endpoint_agents / endpoint_agent_tasks were created with ENABLE ROW LEVEL SECURITY only.
-- Align with the rest of the tenant-scoped schema (users, clients, …) by forcing RLS so
-- table owners and superusers cannot bypass tenant isolation.
--
-- endpoint_agent_enrollment_tokens intentionally keeps RLS disabled (see
-- 20260602180000_relax_agent_token_rls.sql) so unauthenticated /api/agents/enroll can
-- consume a token by hash without app.current_tenant_id.

ALTER TABLE endpoint_agents FORCE ROW LEVEL SECURITY;
ALTER TABLE endpoint_agent_tasks FORCE ROW LEVEL SECURITY;
