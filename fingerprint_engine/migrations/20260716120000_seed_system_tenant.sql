-- Seed the platform SYSTEM tenant (id = 0).
--
-- `SYSTEM_TENANT = 0` (fingerprint_engine::http::tenant_stream) is a first-class, documented
-- concept: platform-scoped / cross-tenant work — orchestrator cycles that run *outside* any tenant
-- scope (`current_cycle_tenant()` falls back to 0), threat-intel fan-out, and system telemetry — is
-- stamped with tenant 0. The zero-trust, event-sourced job log
-- `weissman_job_events.tenant_id REFERENCES tenants(id)` (and `weissman_job_forensic_dlq`) therefore
-- needs a real `tenants` row for id 0. Without it, every system-scoped durable job fails to record
-- its events with `weissman_job_events_tenant_id_fkey` and retry-storms (observed: hundreds of FK
-- violations per run). This row makes the system tenant first-class and its jobs event-sourceable —
-- aligning the schema with the model the rest of the codebase already assumes.
--
-- The row is INACTIVE (`active = false`) on purpose: every tenant-iteration in the platform selects
-- `... FROM tenants WHERE active = true` (orchestrator, threat-intel, SOAR, scan scheduler, red-team
-- background worker, alert evaluator, self-improve, backups, …), so the system tenant is NEVER itself
-- enumerated or scanned. It exists purely so system-scoped jobs are valid FK targets. Migrations run
-- as the DB superuser, which bypasses the FORCE ROW LEVEL SECURITY on `tenants`; the insert is
-- idempotent on the primary key and does not advance `tenants_id_seq` (real tenants keep getting
-- ids >= 1).
INSERT INTO tenants (id, slug, name, active)
SELECT 0, '__system__', 'Platform System (internal, non-scannable)', false
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE id = 0);
