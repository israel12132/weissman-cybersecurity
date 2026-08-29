-- Outbox is ephemeral: persist already committed the finding on logged
-- tables. Skipping WAL here cuts ~80% of disk traffic on the ingest
-- hot path so aggressive autovacuum (scale 0.05 / threshold 1000) cannot
-- burn through cloud I/O bursts.
--
-- PostgreSQL forbids FKs between logged and unlogged tables, so the
-- tenant/client references (the only FKs on this table) are dropped first.
-- Tenant isolation remains FORCE RLS on weissman_cluster_ingest.

DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT conname
          FROM pg_constraint
         WHERE conrelid = 'weissman_cluster_ingest'::regclass
           AND contype = 'f'
    LOOP
        EXECUTE format('ALTER TABLE weissman_cluster_ingest DROP CONSTRAINT IF EXISTS %I', r.conname);
    END LOOP;
END $$;

ALTER TABLE weissman_cluster_ingest SET UNLOGGED;
