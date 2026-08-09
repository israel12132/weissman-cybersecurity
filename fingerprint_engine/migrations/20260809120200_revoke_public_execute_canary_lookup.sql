-- lookup_deception_by_canary(TEXT) is SECURITY DEFINER (owner = postgres) and returns
-- (id, tenant_id, client_id) straight out of deception_assets, bypassing both the table
-- grant and RLS. It was created in 20250401120000_phase4_deception_heal.sql (and
-- CREATE OR REPLACE'd in 20250402120000) with only:
--     GRANT EXECUTE ON FUNCTION lookup_deception_by_canary(TEXT) TO weissman_app;
-- but PostgreSQL grants EXECUTE to PUBLIC by default and neither migration revoked it.
--
-- Consequence: the locked-down read-only NL->SQL role weissman_ro (which has NO grant on
-- deception_assets and is NOBYPASSRLS) can still call this function and read another
-- tenant's deception assets from a single guessed canary key — defeating the containment
-- promise of the NL->SQL layer. weissman_auth and any future login role get the same.
--
-- weissman_app retains its explicit grant; only the implicit PUBLIC grant is removed.

REVOKE EXECUTE ON FUNCTION public.lookup_deception_by_canary(TEXT) FROM PUBLIC;
