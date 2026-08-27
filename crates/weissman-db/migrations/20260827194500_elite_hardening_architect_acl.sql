-- Elite hardening architect review: DB-level Council ACL + nlqa1 hash chain.
-- Timestamp is unique vs 20260827170000 (part 2) and later peer-agent migrations.

-- ── nl_query_audit SHA-256 chain (written by the Ask mPSC worker, not the hot path)
ALTER TABLE nl_query_audit
    ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS event_hash TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS ix_nlqa_chain_head
    ON nl_query_audit (tenant_id, id DESC);

COMMENT ON COLUMN nl_query_audit.prev_hash IS
    'SHA-256 of the previous tenant audit row (nlqa1 chain). Empty string is genesis.';
COMMENT ON COLUMN nl_query_audit.event_hash IS
    'SHA-256 of canonical nlqa1|prev|tenant|user|question|plan|sql|rows|elapsed|error|asked_at';

-- ── Supreme Council memory: trusted-source CHECK + BEFORE INSERT trigger
ALTER TABLE supreme_council_memory
    DROP CONSTRAINT IF EXISTS supreme_council_memory_source_trusted;
ALTER TABLE supreme_council_memory
    ADD CONSTRAINT supreme_council_memory_source_trusted
    CHECK (source IN (
        'oast_success',
        'analyst_confirmed',
        'winning_path',
        'pentest_memory_win'
    ));

CREATE OR REPLACE FUNCTION public.supreme_council_memory_acl()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.source IS NULL OR NEW.source NOT IN (
        'oast_success', 'analyst_confirmed', 'winning_path', 'pentest_memory_win'
    ) THEN
        RAISE EXCEPTION 'supreme_council_memory: source % is not a trusted council origin',
            NEW.source;
    END IF;
    IF TG_OP = 'INSERT'
       AND NEW.source = 'oast_success'
       AND length(btrim(COALESCE(NEW.oast_token, ''))) < 8 THEN
        RAISE EXCEPTION 'supreme_council_memory: oast_success requires oast_token length >= 8';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_supreme_council_memory_acl ON supreme_council_memory;
CREATE TRIGGER trg_supreme_council_memory_acl
    BEFORE INSERT OR UPDATE ON supreme_council_memory
    FOR EACH ROW
    EXECUTE PROCEDURE public.supreme_council_memory_acl();

-- ── SECURITY DEFINER insert: the only write path for weissman_app
CREATE OR REPLACE FUNCTION public.insert_supreme_council_memory(
    p_tenant_id bigint,
    p_target_fingerprint text,
    p_brief_excerpt text,
    p_orchestrator_instruction jsonb,
    p_strategy_summary text,
    p_embedding jsonb,
    p_embedding_vec text,
    p_oast_token text,
    p_source text
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_id bigint;
    v_guc text;
BEGIN
    v_guc := current_setting('app.current_tenant_id', true);
    IF v_guc IS NULL OR btrim(v_guc) = '' OR v_guc::bigint IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'council insert denied: tenant GUC mismatch';
    END IF;
    IF p_source NOT IN (
        'oast_success', 'analyst_confirmed', 'winning_path', 'pentest_memory_win'
    ) THEN
        RAISE EXCEPTION 'council insert denied: untrusted source %', p_source;
    END IF;
    IF p_source = 'oast_success' AND length(btrim(COALESCE(p_oast_token, ''))) < 8 THEN
        RAISE EXCEPTION 'council insert denied: oast_token too short for oast_success';
    END IF;
    INSERT INTO public.supreme_council_memory (
        tenant_id, target_fingerprint, brief_excerpt,
        orchestrator_instruction, strategy_summary,
        embedding, embedding_vec, oast_token, source
    ) VALUES (
        p_tenant_id,
        p_target_fingerprint,
        p_brief_excerpt,
        COALESCE(p_orchestrator_instruction, '{}'::jsonb),
        p_strategy_summary,
        COALESCE(p_embedding, '[]'::jsonb),
        NULLIF(p_embedding_vec, '')::public.vector,
        COALESCE(p_oast_token, ''),
        p_source
    )
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

COMMENT ON FUNCTION public.insert_supreme_council_memory(
    bigint, text, text, jsonb, text, jsonb, text, text, text
) IS
    'Sole INSERT path for supreme_council_memory. Enforces tenant GUC + trusted source. '
    'weissman_app has EXECUTE only; table INSERT is revoked.';

REVOKE ALL ON FUNCTION public.insert_supreme_council_memory(
    bigint, text, text, jsonb, text, jsonb, text, text, text
) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_app') THEN
        REVOKE INSERT, UPDATE, DELETE ON supreme_council_memory FROM weissman_app;
        GRANT SELECT ON supreme_council_memory TO weissman_app;
        GRANT EXECUTE ON FUNCTION public.insert_supreme_council_memory(
            bigint, text, text, jsonb, text, jsonb, text, text, text
        ) TO weissman_app;
    END IF;
END $$;
