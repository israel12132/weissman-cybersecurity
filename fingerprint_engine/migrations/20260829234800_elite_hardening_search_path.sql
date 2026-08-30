-- Seal SECURITY DEFINER / trigger search_path against pg_temp hijack (CVE-2018-1058).
-- pg_temp is last so an attacker-created temp object cannot shadow public.
-- Re-applied here so databases that already ran 20260827194500 pick up the pin.

ALTER FUNCTION public.insert_supreme_council_memory(
    bigint, text, text, jsonb, text, jsonb, text, text, text
) SET search_path = public, pg_temp;

ALTER FUNCTION public.supreme_council_memory_acl()
    SET search_path = public, pg_temp;

COMMENT ON FUNCTION public.insert_supreme_council_memory(
    bigint, text, text, jsonb, text, jsonb, text, text, text
) IS
    'Sole INSERT path for supreme_council_memory. Tenant GUC + trusted source. '
    'SECURITY DEFINER SET search_path = public, pg_temp (pg_temp last). '
    'weissman_app has EXECUTE only; table INSERT is revoked.';
