-- compliance_control_mappings.live_only means "evidence produced only by a live scan"
-- (compliance_engine.rs) and the UI renders TRUE as a green "LIVE" badge to auditors.
--
-- The evidence-only mappings seeded by 20260715120000 and 20260729120000 (engine_id IS
-- NULL — evidence from platform-wide startup/config mechanisms: RLS isolation, audit
-- hash chain, login lockout, TLS policy) inherited the column DEFAULT TRUE
-- (20260702120000_security_hardening_phase2.sql:32) and are therefore mislabelled as
-- live-scan-backed. Only engine-backed rows (engine_id IS NOT NULL) are truly live.
--
-- Correct the data so live_only reflects engine-backing. Idempotent.

UPDATE compliance_control_mappings
   SET live_only = FALSE
 WHERE engine_id IS NULL
   AND live_only IS DISTINCT FROM FALSE;
