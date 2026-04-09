-- High-velocity fuzz candidates: UNLOGGED staging (no WAL), tenant RLS. Promote to `vulnerabilities` only after confirmation.

CREATE UNLOGGED TABLE IF NOT EXISTS fuzz_candidate_staging (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    run_id          BIGINT NOT NULL REFERENCES report_runs (id) ON DELETE CASCADE,
    finding_id      TEXT        NOT NULL,
    title           TEXT        NOT NULL DEFAULT '',
    severity        TEXT        NOT NULL DEFAULT 'medium',
    source          TEXT        NOT NULL DEFAULT '',
    description     TEXT        NOT NULL DEFAULT '',
    status          TEXT        NOT NULL DEFAULT 'CANDIDATE',
    proof           TEXT,
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_fuzz_staging_tenant ON fuzz_candidate_staging (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fuzz_staging_run ON fuzz_candidate_staging (run_id);

ALTER TABLE fuzz_candidate_staging ENABLE ROW LEVEL SECURITY;
ALTER TABLE fuzz_candidate_staging FORCE ROW LEVEL SECURITY;
CREATE POLICY fuzz_candidate_staging_tenant ON fuzz_candidate_staging FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

COMMENT ON TABLE fuzz_candidate_staging IS 'Ephemeral UNLOGGED fuzz hits; promote to vulnerabilities after analyst/LLM confirmation.';

-- Invoker rights: RLS on staging + vulnerabilities applies to weissman_app session tenant.
CREATE OR REPLACE FUNCTION public.promote_fuzz_candidate (p_id BIGINT)
    RETURNS BIGINT
    LANGUAGE plpgsql
    SET search_path = public
AS
$$
DECLARE
    vid BIGINT;
    r   RECORD;
BEGIN
    SELECT *
    INTO r
    FROM fuzz_candidate_staging
    WHERE id = p_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    INSERT INTO vulnerabilities (run_id, tenant_id, client_id, finding_id, title, severity, source, description, status, proof)
    VALUES (r.run_id, r.tenant_id, r.client_id, r.finding_id, r.title, r.severity, r.source, r.description,
            CASE WHEN r.status = 'CANDIDATE' THEN 'OPEN' ELSE COALESCE (NULLIF (TRIM (r.status), ''), 'OPEN') END,
            r.proof)
    RETURNING id INTO vid;

    DELETE FROM fuzz_candidate_staging
    WHERE id = p_id;

    RETURN vid;
END;
$$;

COMMENT ON FUNCTION public.promote_fuzz_candidate (BIGINT) IS 'Move one fuzz_candidate_staging row into RLS-protected vulnerabilities; requires tenant-scoped session.';

GRANT SELECT, INSERT, UPDATE, DELETE ON fuzz_candidate_staging TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE fuzz_candidate_staging_id_seq TO weissman_app;
GRANT EXECUTE ON FUNCTION public.promote_fuzz_candidate (BIGINT) TO weissman_app;
