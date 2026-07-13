-- ─── Auto-Heal "WOW" upgrade: applied-fix PR, delivery channels, bilingual brief ──
--
-- The auto-heal pipeline is upgraded from "commit the diff as a PATCH.txt file" to
-- committing the ACTUAL patched source files (proven in the ephemeral Docker sandbox),
-- with a hardened Fixed/BrokeApp/StillVulnerable verdict, several delivery channels,
-- and a bilingual (he/en) remediation brief.
--
-- All columns are additive and idempotent. The target tables already carry
-- FORCE ROW LEVEL SECURITY + weissman_app grants (see 20260411120000_auto_heal_worker_queue.sql
-- and the initial schema), which the new columns inherit — no new policy/grant needed.

-- Bilingual remediation brief, cached per finding. Stored in its own column (NOT raw_data,
-- which is overwritten on every re-scan) so it survives re-scans.
ALTER TABLE vulnerabilities     ADD COLUMN IF NOT EXISTS remediation_brief JSONB;

-- Delivery channel + optional health/control probe + the verified artifact (diff / files /
-- virtual-patch snippet) produced by a run, for retrieval by the UI and non-repo channels.
ALTER TABLE auto_heal_job_specs ADD COLUMN IF NOT EXISTS channel           TEXT NOT NULL DEFAULT 'github_pr';
ALTER TABLE auto_heal_job_specs ADD COLUMN IF NOT EXISTS health_check_curl TEXT;
ALTER TABLE auto_heal_job_specs ADD COLUMN IF NOT EXISTS result_artifact   JSONB;

-- Persist the delivery channel and the hardened verdict on each heal request row.
ALTER TABLE heal_requests       ADD COLUMN IF NOT EXISTS channel TEXT;
ALTER TABLE heal_requests       ADD COLUMN IF NOT EXISTS verdict TEXT;
