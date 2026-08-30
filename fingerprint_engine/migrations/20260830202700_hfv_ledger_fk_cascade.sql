-- Direct UPDATE/DELETE on vulnerability_lifecycle_events stay forbidden
-- (REVOKE + trigger). The original BEFORE DELETE trigger also fired for
-- foreign-key CASCADE, so DELETE FROM clients / tenants aborted whenever a
-- ledger row existed. Cargo-test cleanup (persist_real_pool_starvation) then
-- left client id=1 + starve_engine findings in the engine-wiring database;
-- PATCH /api/findings/:id/status 404'd because the inbox row belonged to the
-- leftover tenant.
--
-- Nested trigger depth (pg_trigger_depth() > 1) is the RI cascade from
-- clients / tenants / vulnerabilities. Direct DELETE (depth 1) still raises.
-- UPDATE is never a cascade we want; keep it blocked at every depth.

CREATE OR REPLACE FUNCTION vulnerability_lifecycle_events_reject_mutate() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'vulnerability_lifecycle_events is append-only';
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION vulnerability_lifecycle_events_reject_mutate() IS
    'Block direct UPDATE/DELETE on the HFV ledger. FK CASCADE (nested trigger depth) is allowed so client/tenant offboarding can remove a customer''s history with the customer.';
