-- Crash recovery: UNLOGGED ingest is truncated on an unclean Postgres restart
-- and pending SOAR / SIEM / cluster-watermark work is lost. Return the outbox
-- to LOGGED (WAL). Autovacuum scale 0.05 / threshold 1000 stays.
-- FKs to tenants/clients were dropped to allow UNLOGGED; restore them now that
-- the table is durable again. No FK to vulnerabilities (lock-order safety).

ALTER TABLE weissman_cluster_ingest SET LOGGED;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'weissman_cluster_ingest'::regclass
           AND conname = 'weissman_cluster_ingest_tenant_id_fkey'
    ) THEN
        ALTER TABLE weissman_cluster_ingest
            ADD CONSTRAINT weissman_cluster_ingest_tenant_id_fkey
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'weissman_cluster_ingest'::regclass
           AND conname = 'weissman_cluster_ingest_client_id_fkey'
    ) THEN
        ALTER TABLE weissman_cluster_ingest
            ADD CONSTRAINT weissman_cluster_ingest_client_id_fkey
            FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE;
    END IF;
END $$;
