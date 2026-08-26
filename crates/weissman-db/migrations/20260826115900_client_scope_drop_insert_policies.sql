-- Prerequisite for the frozen 20260826120000_client_scope_isolation file.
--
-- That file (389751f) synthesizes `USING (true AND vis)` on every policy. Postgres
-- rejects USING on INSERT-only policies ("only WITH CHECK expression allowed for
-- INSERT"). 2a960be patched 20260826120000 in place; live volumes that had already
-- applied it then failed sqlx checksum verification.
--
-- 20260826120000 is restored byte-for-byte. These two INSERT policies are dropped
-- here so the frozen file can apply on a fresh database. FORCE RLS default-denies
-- INSERT for weissman_app while they are absent (fail-closed). Recreated with the
-- client-visibility predicate in 20260826180000_client_scope_insert_only_policies.

DO $$
BEGIN
    IF to_regclass('public.risk_graph_nodes') IS NOT NULL THEN
        DROP POLICY IF EXISTS risk_graph_nodes_insert ON public.risk_graph_nodes;
    END IF;
    IF to_regclass('public.risk_graph_edges') IS NOT NULL THEN
        DROP POLICY IF EXISTS risk_graph_edges_insert ON public.risk_graph_edges;
    END IF;
END $$;
