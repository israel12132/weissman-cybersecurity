-- Step 2 (least privilege): shrink the BYPASSRLS write surface, and remove a dead
-- write path into public.vulnerabilities.
--
-- 1) weissman_worker is BYPASSRLS on purpose — it must claim job-bus rows across
--    tenants (WORKER_JOB_BUS_TABLES: weissman_async_jobs / weissman_job_events /
--    weissman_job_forensic_dlq). But proof_layer.sql, adversary_campaign_fabric.sql,
--    apt_emulation_profiles.sql and campaign_event_bus.sql ALSO granted it full CRUD
--    on seven TENANT-scoped (FORCE ROW LEVEL SECURITY) campaign/proof tables. A
--    BYPASSRLS role holding write on a tenant table means any code path — or a future
--    SQL-injection sink — running as that role can cross tenants with ZERO RLS
--    backstop.
--
--    Those grants are UNUSED: the weissman-worker binary contains no reference to
--    campaign/proof (it is the only process that connects as weissman_worker), and
--    every campaign/proof write in the codebase (fingerprint_engine/src/adversary_campaign.rs,
--    proof_layer.rs) runs through crate::db::begin_tenant_tx on the NOBYPASSRLS app
--    pool (weissman_app), where FORCE RLS is a live backstop — begin_tenant_tx is
--    meaningless on a BYPASSRLS pool. Revoke them.
REVOKE ALL PRIVILEGES ON
    weissman_campaigns,
    weissman_campaign_audit,
    weissman_campaign_events,
    weissman_campaign_steps,
    weissman_campaign_world_states,
    weissman_campaign_detection_gaps,
    weissman_proof_artifacts
    FROM weissman_worker;

-- 2) promote_fuzz_candidate(bigint) INSERTed straight into public.vulnerabilities
--    (20260420120000_sovereign_c2_fuzz_staging.sql), bypassing the Rust evidence
--    gate (findings_gate). It has ZERO callers — grep finds it only in its own
--    migration — and is a redundant, latent second write path into the findings
--    table. Drop it; findings_persist remains the single application write path.
DROP FUNCTION IF EXISTS public.promote_fuzz_candidate(bigint);

-- The companion contract test crates/weissman-db/tests/bypassrls_write_grants_contract.rs
-- asserts, against the live schema, that no BYPASSRLS role holds write privileges on a
-- FORCE-RLS table outside a documented control/auth-plane allowlist — so a future grant
-- like the ones revoked above turns the build red instead of silently shipping.
