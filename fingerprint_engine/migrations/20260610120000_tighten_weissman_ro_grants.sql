-- Tighten weissman_ro to match nl_query.rs ALLOWED_TABLES only (defence in depth).
-- The initial nl_query migration granted SELECT on extra tables (audit_logs, etc.).

REVOKE SELECT ON
    risk_graph_edges,
    client_financial_risk_snapshots,
    endpoint_agents,
    weissman_async_jobs,
    epss_intel,
    kev_intel,
    audit_logs
FROM weissman_ro;
