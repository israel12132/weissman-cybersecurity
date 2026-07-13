-- weissman:no-transaction
--
-- Composite indexes for the two hottest tenant-scoped ORDERED scans (dashboard feeds).
--
-- `vulnerabilities` and `weissman_async_jobs` both lack a `(tenant_id, <time> DESC)` index, so
-- every tenant list feed (e.g. "SELECT ... WHERE tenant_id=$1 ORDER BY discovered_at/created_at
-- DESC LIMIT N") does a filtered scan + top-N sort. `vulnerabilities` is the fastest-growing
-- table in the system, and with RLS now on `weissman_async_jobs` every tenant job-list scans.
--
-- Additive, online (CONCURRENTLY → no table lock), zero code change. DROP-first cleans up any
-- INVALID index from a prior interrupted build; IF [NOT] EXISTS makes re-runs idempotent.

DROP   INDEX CONCURRENTLY IF EXISTS ix_vuln_tenant_discovered;
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_vuln_tenant_discovered
    ON vulnerabilities (tenant_id, discovered_at DESC);

DROP   INDEX CONCURRENTLY IF EXISTS ix_async_jobs_tenant_created;
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_async_jobs_tenant_created
    ON weissman_async_jobs (tenant_id, created_at DESC);
