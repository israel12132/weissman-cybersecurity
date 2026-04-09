-- Canary lookup must match assets after cloud injection (status becomes 'deployed').
CREATE OR REPLACE FUNCTION lookup_deception_by_canary(p_ak TEXT)
RETURNS TABLE(id BIGINT, tenant_id BIGINT, client_id BIGINT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT a.id, a.tenant_id, a.client_id
    FROM deception_assets a
    WHERE a.canary_access_key_id = p_ak
      AND a.status IN ('active', 'deployed')
    LIMIT 10;
$$;
