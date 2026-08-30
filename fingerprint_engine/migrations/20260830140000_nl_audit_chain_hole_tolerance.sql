-- Sequence holes (BIGSERIAL nextval is non-transactional) must not stall the
-- NL audit hash-chain walk. A rolled-back id is gone forever; an in-flight
-- INSERT may still COMMIT. The sealer waits MAX_HOLE_AGE (5 minutes in Rust)
-- then records SKIPPED_ROLLBACK and continues chaining later ids.
--
-- Missing-id lookup is SECURITY DEFINER: FORCE RLS on nl_query_audit would
-- otherwise hide other tenants' committed ids and every inter-tenant gap
-- would look like a hole, stalling the walk under load.

CREATE TABLE IF NOT EXISTS nl_query_audit_chain_holes (
    tenant_id     BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    missing_id    BIGINT      NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    skipped_at    TIMESTAMPTZ,
    reason        TEXT,
    PRIMARY KEY (tenant_id, missing_id)
);

CREATE INDEX IF NOT EXISTS ix_nlqa_holes_open
    ON nl_query_audit_chain_holes (tenant_id, first_seen_at)
    WHERE skipped_at IS NULL;

ALTER TABLE nl_query_audit_chain_holes ENABLE ROW LEVEL SECURITY;
ALTER TABLE nl_query_audit_chain_holes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS nl_query_audit_chain_holes_tenant ON nl_query_audit_chain_holes;
CREATE POLICY nl_query_audit_chain_holes_tenant ON nl_query_audit_chain_holes FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE ON nl_query_audit_chain_holes TO weissman_app;

COMMENT ON TABLE nl_query_audit_chain_holes IS
    'Internal log of BIGSERIAL gaps observed while sealing nl_query_audit. reason=SKIPPED_ROLLBACK after the 5-minute hole-tolerance window.';

CREATE OR REPLACE FUNCTION public.nl_audit_missing_ids(lo bigint, hi bigint)
    RETURNS TABLE(missing_id bigint)
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = ''
    AS $fn$
DECLARE
    expected bigint;
    actual bigint;
BEGIN
    IF lo IS NULL OR hi IS NULL OR lo > hi THEN
        RETURN;
    END IF;
    expected := hi - lo + 1;
    SELECT COUNT(*)::bigint INTO actual
      FROM public.nl_query_audit a
     WHERE a.id >= lo AND a.id <= hi;
    IF actual = expected THEN
        RETURN;
    END IF;
    -- Enumerate only modest gaps. A huge sparse range is treated as a single
    -- sentinel (lo) so the sealer applies one hole-tolerance window, never a
    -- generate_series of millions of ids.
    IF expected > 10000 THEN
        missing_id := lo;
        RETURN NEXT;
        RETURN;
    END IF;
    RETURN QUERY
        SELECT gs
          FROM generate_series(lo, hi) AS gs
         WHERE NOT EXISTS (
             SELECT 1 FROM public.nl_query_audit a WHERE a.id = gs
         );
END
$fn$;

COMMENT ON FUNCTION public.nl_audit_missing_ids(bigint, bigint) IS
    'Ids in [lo,hi] with no committed nl_query_audit row (in-flight or rolled-back sequence values). Bypasses RLS so other tenants'' rows are not mistaken for holes.';

REVOKE ALL ON FUNCTION public.nl_audit_missing_ids(bigint, bigint) FROM PUBLIC;

DO $$
DECLARE
    r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['weissman_app'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION public.nl_audit_missing_ids(bigint, bigint) TO %I', r);
        END IF;
    END LOOP;
END $$;
