-- endpoint_agents / endpoint_agent_tasks were created with ENABLE ROW LEVEL SECURITY only.
-- Align with the rest of the tenant-scoped schema (users, clients, …) by forcing RLS so
-- table owners and superusers cannot bypass tenant isolation.
--
-- endpoint_agent_enrollment_tokens gets FORCE RLS in 20260611130200_agent_auth_force_rls.sql;
-- unauthenticated enroll still works via SECURITY DEFINER consume_endpoint_agent_enrollment_token.

ALTER TABLE endpoint_agents FORCE ROW LEVEL SECURITY;
ALTER TABLE endpoint_agent_tasks FORCE ROW LEVEL SECURITY;
