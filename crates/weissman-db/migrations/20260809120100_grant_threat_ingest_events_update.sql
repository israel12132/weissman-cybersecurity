-- threat_ingest_events is a mutable upsert CACHE, not an append-only audit trail:
-- the ingestor (threat_intel_ingestor.rs) writes it with
--     INSERT ... ON CONFLICT (tenant_id, source, external_id) DO UPDATE SET ...
--
-- 20260416200000_rbac_hardening_audit_sequences_rls_schema.sql:29-31 swept it into the
-- audit-table hardening and did:
--     REVOKE UPDATE, DELETE ON threat_ingest_events FROM weissman_app;
--     GRANT  SELECT, INSERT ON threat_ingest_events TO   weissman_app;
--
-- PostgreSQL checks UPDATE privilege at executor start for any ON CONFLICT DO UPDATE,
-- regardless of whether a conflict actually occurs, so EVERY ingest now fails with
-- `permission denied for table threat_ingest_events` on the first row. The table has no
-- append-only trigger (unlike audit_logs), so restoring UPDATE is sufficient and correct.
-- DELETE is intentionally NOT re-granted (the ingest path never deletes).

DO $$
BEGIN
    IF to_regclass('public.threat_ingest_events') IS NOT NULL THEN
        GRANT UPDATE ON TABLE threat_ingest_events TO weissman_app;
    END IF;
END $$;
