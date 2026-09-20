-- Idempotent stealth check results: one row per (tenant, client, check).
-- COPY lands in a TEMP ingest table; the app UPSERTs with ON CONFLICT.

DELETE FROM stealth_evasion_check_results a
 WHERE EXISTS (
    SELECT 1 FROM stealth_evasion_check_results b
     WHERE a.tenant_id = b.tenant_id
       AND a.client_id = b.client_id
       AND a.check_id = b.check_id
       AND a.id < b.id
 );

CREATE UNIQUE INDEX IF NOT EXISTS ux_stealth_evasion_check_results_tenant_client_check
    ON stealth_evasion_check_results (tenant_id, client_id, check_id);
