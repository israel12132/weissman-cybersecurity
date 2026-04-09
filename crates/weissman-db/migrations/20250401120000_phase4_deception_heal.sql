-- Phase 4: canary key tracking for CloudTrail / GuardDuty correlation; heal verification job id.

ALTER TABLE deception_assets
    ADD COLUMN IF NOT EXISTS canary_access_key_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS cloud_injection_uri TEXT NOT NULL DEFAULT '';

ALTER TABLE heal_requests
    ADD COLUMN IF NOT EXISTS verification_job_id TEXT NOT NULL DEFAULT '';

-- Webhook / EventBridge forwarder: resolve canary key without tenant session (SECURITY DEFINER).
CREATE OR REPLACE FUNCTION lookup_deception_by_canary(p_ak TEXT)
RETURNS TABLE(id BIGINT, tenant_id BIGINT, client_id BIGINT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT a.id, a.tenant_id, a.client_id
    FROM deception_assets a
    WHERE a.canary_access_key_id = p_ak AND a.status = 'active'
    LIMIT 10;
$$;

GRANT EXECUTE ON FUNCTION lookup_deception_by_canary(TEXT) TO weissman_app;
