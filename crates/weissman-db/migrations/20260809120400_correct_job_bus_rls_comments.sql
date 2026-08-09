-- Correct the operator-facing COMMENT ON TABLE prose for the job-bus tables. The live
-- comments (from 20260407140000 / 20260627120000) still say "no RLS", but
-- 20260708120000_rls_job_bus_tables.sql put ENABLE + FORCE ROW LEVEL SECURITY on all
-- three with a tenant-or-worker policy. The stale "no RLS" text (echoed in
-- 20260712120000's header) is exactly what made the tenant-0 dequeue regression invisible.
--
-- This migration only rewrites the psql \d+ comments; it changes no DDL.

COMMENT ON TABLE weissman_async_jobs IS
  'Durable job queue. RLS ENABLED + FORCED with policy async_jobs_tenant_or_worker '
  '(20260708120000): GUC app.current_tenant_id unset/'''' -> unrestricted (worker '
  'dequeues across tenants; job_queue.rs sets no GUC); GUC set -> rows scoped to that '
  'tenant. The database-level GUC default must stay RESET (see 20260809120000) or the '
  'worker collapses to tenant 0 only. Inserts only via trusted server code.';

COMMENT ON TABLE weissman_job_events IS
  'Append-only immutable job event log (event sourcing). RLS ENABLED + FORCED with policy '
  'job_events_tenant_or_worker (20260708120000): same tenant-or-worker semantics as '
  'weissman_async_jobs. Never UPDATE/DELETE — forensic replay only.';

COMMENT ON TABLE weissman_job_forensic_dlq IS
  'Cryptographically sealed forensic DLQ bundles. RLS ENABLED + FORCED with policy '
  'job_forensic_dlq_tenant_or_worker (20260708120000): tenant-or-worker semantics as '
  'weissman_async_jobs. Regression generation / incident response.';
