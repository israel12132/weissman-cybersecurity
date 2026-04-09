-- Enterprise RBAC: narrow grants on append-only / audit tables, sequence hardening (no setval abuse),
-- stricter risk_graph RLS (endpoint + client binding), and revoke CREATE on application schemas.

-- -----------------------------------------------------------------------------
-- 1) Immutable / audit-style tables: SELECT + INSERT only for weissman_app
--    (audit_logs already has BEFORE UPDATE/DELETE triggers; this adds privilege-layer defense.)
--    report_runs / scan orchestration remain UPDATE-capable — not listed here.
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.audit_logs') IS NOT NULL THEN
        REVOKE UPDATE, DELETE ON TABLE audit_logs FROM weissman_app;
        GRANT SELECT, INSERT ON TABLE audit_logs TO weissman_app;
    END IF;
    IF to_regclass('public.tenant_llm_usage') IS NOT NULL THEN
        REVOKE UPDATE, DELETE ON TABLE tenant_llm_usage FROM weissman_app;
        REVOKE UPDATE, DELETE ON TABLE tenant_llm_usage FROM weissman_auth;
        GRANT SELECT, INSERT ON TABLE tenant_llm_usage TO weissman_app;
        GRANT SELECT, INSERT ON TABLE tenant_llm_usage TO weissman_auth;
    END IF;
    IF to_regclass('public.runtime_traces') IS NOT NULL THEN
        REVOKE UPDATE, DELETE ON TABLE runtime_traces FROM weissman_app;
        GRANT SELECT, INSERT ON TABLE runtime_traces TO weissman_app;
    END IF;
    IF to_regclass('public.swarm_events') IS NOT NULL THEN
        REVOKE UPDATE, DELETE ON TABLE swarm_events FROM weissman_app;
        GRANT SELECT, INSERT ON TABLE swarm_events TO weissman_app;
    END IF;
    IF to_regclass('public.threat_ingest_events') IS NOT NULL THEN
        REVOKE UPDATE, DELETE ON TABLE threat_ingest_events FROM weissman_app;
        GRANT SELECT, INSERT ON TABLE threat_ingest_events TO weissman_app;
    END IF;
    IF to_regclass('public.privilege_escalation_events') IS NOT NULL THEN
        REVOKE UPDATE, DELETE ON TABLE privilege_escalation_events FROM weissman_app;
        GRANT SELECT, INSERT ON TABLE privilege_escalation_events TO weissman_app;
    END IF;
END $$;

-- -----------------------------------------------------------------------------
-- 2) Sequences: USAGE (nextval) + SELECT (currval) only — revoke UPDATE (setval / manual advance)
-- -----------------------------------------------------------------------------
REVOKE UPDATE ON ALL SEQUENCES IN SCHEMA public FROM weissman_app;
REVOKE UPDATE ON ALL SEQUENCES IN SCHEMA public FROM weissman_auth;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO weissman_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO weissman_auth;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'intel') THEN
        REVOKE UPDATE ON ALL SEQUENCES IN SCHEMA intel FROM weissman_app;
        REVOKE UPDATE ON ALL SEQUENCES IN SCHEMA intel FROM weissman_auth;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA intel TO weissman_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA intel TO weissman_auth;
    END IF;
END $$;

-- Future objects created by the migration superuser (typically postgres)
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    REVOKE UPDATE ON SEQUENCES FROM weissman_app;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    REVOKE UPDATE ON SEQUENCES FROM weissman_auth;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO weissman_app;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO weissman_auth;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'intel') THEN
        ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA intel
            REVOKE UPDATE ON SEQUENCES FROM weissman_app;
        ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA intel
            REVOKE UPDATE ON SEQUENCES FROM weissman_auth;
        ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA intel
            GRANT USAGE, SELECT ON SEQUENCES TO weissman_app;
        ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA intel
            GRANT USAGE, SELECT ON SEQUENCES TO weissman_auth;
    END IF;
END $$;

-- -----------------------------------------------------------------------------
-- 3) Schema hardening: application roles must not create objects (migrations use superuser)
-- -----------------------------------------------------------------------------
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM weissman_app;
REVOKE CREATE ON SCHEMA public FROM weissman_auth;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'intel') THEN
        REVOKE CREATE ON SCHEMA intel FROM PUBLIC;
        REVOKE CREATE ON SCHEMA intel FROM weissman_app;
        REVOKE CREATE ON SCHEMA intel FROM weissman_auth;
    END IF;
END $$;

-- -----------------------------------------------------------------------------
-- 4) risk_graph: stricter RLS — nodes must belong to a real tenant client; edges must
--    reference endpoints in the same (tenant_id, client_id) as the edge row.
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('public.risk_graph_nodes') IS NULL OR to_regclass('public.risk_graph_edges') IS NULL THEN
        RETURN;
    END IF;

    DROP POLICY IF EXISTS risk_graph_nodes_tenant ON risk_graph_nodes;
    DROP POLICY IF EXISTS risk_graph_edges_tenant ON risk_graph_edges;

    CREATE POLICY risk_graph_nodes_select ON risk_graph_nodes
        FOR SELECT USING (
            tenant_id = current_setting('app.current_tenant_id', true)::bigint
        );

    CREATE POLICY risk_graph_nodes_insert ON risk_graph_nodes
        FOR INSERT WITH CHECK (
            tenant_id = current_setting('app.current_tenant_id', true)::bigint
            AND EXISTS (
                SELECT 1 FROM clients c
                WHERE c.id = risk_graph_nodes.client_id
                  AND c.tenant_id = risk_graph_nodes.tenant_id
            )
        );

    CREATE POLICY risk_graph_nodes_update ON risk_graph_nodes
        FOR UPDATE USING (
            tenant_id = current_setting('app.current_tenant_id', true)::bigint
        )
        WITH CHECK (
            tenant_id = current_setting('app.current_tenant_id', true)::bigint
            AND EXISTS (
                SELECT 1 FROM clients c
                WHERE c.id = risk_graph_nodes.client_id
                  AND c.tenant_id = risk_graph_nodes.tenant_id
            )
        );

    CREATE POLICY risk_graph_nodes_delete ON risk_graph_nodes
        FOR DELETE USING (
            tenant_id = current_setting('app.current_tenant_id', true)::bigint
        );

    CREATE POLICY risk_graph_edges_select ON risk_graph_edges
        FOR SELECT USING (
            tenant_id = current_setting('app.current_tenant_id', true)::bigint
            AND EXISTS (
                SELECT 1 FROM risk_graph_nodes fn
                WHERE fn.id = risk_graph_edges.from_node_id
                  AND fn.tenant_id = risk_graph_edges.tenant_id
                  AND fn.client_id = risk_graph_edges.client_id
            )
            AND EXISTS (
                SELECT 1 FROM risk_graph_nodes tn
                WHERE tn.id = risk_graph_edges.to_node_id
                  AND tn.tenant_id = risk_graph_edges.tenant_id
                  AND tn.client_id = risk_graph_edges.client_id
            )
        );

    CREATE POLICY risk_graph_edges_insert ON risk_graph_edges
        FOR INSERT WITH CHECK (
            tenant_id = current_setting('app.current_tenant_id', true)::bigint
            AND EXISTS (
                SELECT 1 FROM risk_graph_nodes fn
                WHERE fn.id = risk_graph_edges.from_node_id
                  AND fn.tenant_id = risk_graph_edges.tenant_id
                  AND fn.client_id = risk_graph_edges.client_id
            )
            AND EXISTS (
                SELECT 1 FROM risk_graph_nodes tn
                WHERE tn.id = risk_graph_edges.to_node_id
                  AND tn.tenant_id = risk_graph_edges.tenant_id
                  AND tn.client_id = risk_graph_edges.client_id
            )
        );

    CREATE POLICY risk_graph_edges_update ON risk_graph_edges
        FOR UPDATE USING (
            tenant_id = current_setting('app.current_tenant_id', true)::bigint
            AND EXISTS (
                SELECT 1 FROM risk_graph_nodes fn
                WHERE fn.id = risk_graph_edges.from_node_id
                  AND fn.tenant_id = risk_graph_edges.tenant_id
                  AND fn.client_id = risk_graph_edges.client_id
            )
            AND EXISTS (
                SELECT 1 FROM risk_graph_nodes tn
                WHERE tn.id = risk_graph_edges.to_node_id
                  AND tn.tenant_id = risk_graph_edges.tenant_id
                  AND tn.client_id = risk_graph_edges.client_id
            )
        )
        WITH CHECK (
            tenant_id = current_setting('app.current_tenant_id', true)::bigint
            AND EXISTS (
                SELECT 1 FROM risk_graph_nodes fn
                WHERE fn.id = risk_graph_edges.from_node_id
                  AND fn.tenant_id = risk_graph_edges.tenant_id
                  AND fn.client_id = risk_graph_edges.client_id
            )
            AND EXISTS (
                SELECT 1 FROM risk_graph_nodes tn
                WHERE tn.id = risk_graph_edges.to_node_id
                  AND tn.tenant_id = risk_graph_edges.tenant_id
                  AND tn.client_id = risk_graph_edges.client_id
            )
        );

    CREATE POLICY risk_graph_edges_delete ON risk_graph_edges
        FOR DELETE USING (
            tenant_id = current_setting('app.current_tenant_id', true)::bigint
            AND EXISTS (
                SELECT 1 FROM risk_graph_nodes fn
                WHERE fn.id = risk_graph_edges.from_node_id
                  AND fn.tenant_id = risk_graph_edges.tenant_id
                  AND fn.client_id = risk_graph_edges.client_id
            )
            AND EXISTS (
                SELECT 1 FROM risk_graph_nodes tn
                WHERE tn.id = risk_graph_edges.to_node_id
                  AND tn.tenant_id = risk_graph_edges.tenant_id
                  AND tn.client_id = risk_graph_edges.client_id
            )
        );
END $$;

COMMENT ON TABLE audit_logs IS 'Append-only audit trail: triggers + REVOKE UPDATE/DELETE on weissman_app.';
COMMENT ON TABLE tenant_llm_usage IS 'Append-only LLM metering: INSERT/SELECT only for application roles.';
