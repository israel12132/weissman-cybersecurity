-- SECURITY DEFINER RPCs so weissman_app can read/update default-tenant scan_interval_secs
-- (orchestrator loop reads this row; RLS would otherwise block cross-tenant access).

CREATE OR REPLACE FUNCTION public.weissman_default_tenant_scan_interval_get()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT sc.value
  FROM system_configs sc
  INNER JOIN tenants t ON t.id = sc.tenant_id AND t.slug = 'default'
  WHERE sc.key = 'scan_interval_secs'
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public.weissman_default_tenant_scan_interval_set(p_value text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  n int;
BEGIN
  IF p_value IS NULL OR trim(p_value) = '' THEN
    RAISE EXCEPTION 'scan_interval_secs required';
  END IF;
  IF p_value !~ '^[0-9]+$' THEN
    RAISE EXCEPTION 'scan_interval_secs must be a positive integer';
  END IF;
  n := p_value::int;
  IF n < 10 OR n > 86400 THEN
    RAISE EXCEPTION 'scan_interval_secs must be between 10 and 86400';
  END IF;
  UPDATE system_configs sc
  SET value = p_value
  FROM tenants t
  WHERE sc.tenant_id = t.id AND t.slug = 'default' AND sc.key = 'scan_interval_secs';
END;
$$;

REVOKE ALL ON FUNCTION public.weissman_default_tenant_scan_interval_get() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.weissman_default_tenant_scan_interval_set(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.weissman_default_tenant_scan_interval_get() TO weissman_app;
GRANT EXECUTE ON FUNCTION public.weissman_default_tenant_scan_interval_set(text) TO weissman_app;
