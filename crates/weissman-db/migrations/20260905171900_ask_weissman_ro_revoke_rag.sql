-- Ask Weissman: weissman_ro must never SELECT RAG / embedding tables.
-- Contextual memory is fetched on weissman_app via ask_rag (fixed SQL, k<=5).

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        IF to_regclass('public.supreme_council_memory') IS NOT NULL THEN
            EXECUTE 'REVOKE SELECT ON supreme_council_memory FROM weissman_ro';
        END IF;
        IF to_regclass('public.supreme_council_rag_hits') IS NOT NULL THEN
            EXECUTE 'REVOKE SELECT ON supreme_council_rag_hits FROM weissman_ro';
        END IF;
        IF to_regclass('public.pentest_winning_paths') IS NOT NULL THEN
            EXECUTE 'REVOKE SELECT ON pentest_winning_paths FROM weissman_ro';
        END IF;
    END IF;
END $$;
