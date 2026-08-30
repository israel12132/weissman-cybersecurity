-- Extend SECURITY DEFINER insert_supreme_council_memory with RAG HMAC provenance.
-- Direct table INSERT stays revoked; this is the sole weissman_app write path.
-- The 9-arg overload is dropped so callers cannot persist unsigned embeddings.

DROP FUNCTION IF EXISTS public.insert_supreme_council_memory(
    bigint, text, text, jsonb, text, jsonb, text, text, text
);

CREATE OR REPLACE FUNCTION public.insert_supreme_council_memory(
    p_tenant_id bigint,
    p_target_fingerprint text,
    p_brief_excerpt text,
    p_orchestrator_instruction jsonb,
    p_strategy_summary text,
    p_embedding jsonb,
    p_embedding_vec text,
    p_oast_token text,
    p_source text,
    p_embedding_checksum text,
    p_provenance_hmac text,
    p_provenance_kind text,
    p_provenance_issuer text
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
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
        embedding, embedding_vec, oast_token, source,
        embedding_checksum, provenance_hmac, provenance_kind, provenance_issuer
    ) VALUES (
        p_tenant_id,
        p_target_fingerprint,
        p_brief_excerpt,
        COALESCE(p_orchestrator_instruction, '{}'::jsonb),
        p_strategy_summary,
        COALESCE(p_embedding, '[]'::jsonb),
        NULLIF(p_embedding_vec, '')::public.vector,
        COALESCE(p_oast_token, ''),
        p_source,
        COALESCE(p_embedding_checksum, ''),
        COALESCE(p_provenance_hmac, ''),
        COALESCE(p_provenance_kind, ''),
        COALESCE(p_provenance_issuer, '')
    )
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

COMMENT ON FUNCTION public.insert_supreme_council_memory(
    bigint, text, text, jsonb, text, jsonb, text, text, text, text, text, text, text
) IS
    'Sole INSERT path for supreme_council_memory. Tenant GUC + trusted source + RAG HMAC. '
    'SECURITY DEFINER SET search_path = public, pg_temp (pg_temp last). '
    'weissman_app has EXECUTE only; table INSERT is revoked.';

REVOKE ALL ON FUNCTION public.insert_supreme_council_memory(
    bigint, text, text, jsonb, text, jsonb, text, text, text, text, text, text, text
) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_app') THEN
        REVOKE INSERT, UPDATE, DELETE ON supreme_council_memory FROM weissman_app;
        GRANT SELECT ON supreme_council_memory TO weissman_app;
        GRANT EXECUTE ON FUNCTION public.insert_supreme_council_memory(
            bigint, text, text, jsonb, text, jsonb, text, text, text, text, text, text, text
        ) TO weissman_app;
    END IF;
END $$;
