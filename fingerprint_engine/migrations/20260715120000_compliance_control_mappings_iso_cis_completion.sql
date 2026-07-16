-- Complete the live control-mapping catalog for the frameworks that already carry canonical
-- control sets in the product (ISO/IEC 27001 and CIS). Before this migration these frameworks were
-- only partially mapped, so the control-mapping enforcement gate refused (409) their reports and
-- evidence packs. Every remaining requirement is bound to a concrete, live evidence source here so
-- the artifacts generate cleanly without weakening the gate for genuinely-unmapped frameworks.
--
-- All rows are evidence-only (engine_id IS NULL): the evidence is produced by platform-wide
-- capabilities (RLS isolation, hash-chained audit log, distributed lockout, TLS policy, live
-- vulnerability management) rather than a single named engine — consistent with the existing
-- A.5.15 / A.8.15 rows and avoiding any stale-engine references.

INSERT INTO compliance_control_mappings
    (framework, control_id, control_title, control_family, engine_id, evidence_type, evidence_source, mapping_notes)
VALUES
    -- ISO/IEC 27001 — A.9 Access control
    ('ISO27001', 'A.9.2', 'User access management', 'Access control', NULL, 'rls_isolation', 'clients', 'Per-tenant RBAC + Postgres RLS enforce least-privilege access to client data'),
    ('ISO27001', 'A.9.4', 'System and application access control', 'Access control', NULL, 'login_lockout', 'redis', 'Authenticated APIs behind JWT policy with distributed login lockout and rate limits'),
    -- ISO/IEC 27001 — A.10 Cryptography
    ('ISO27001', 'A.10.1', 'Cryptographic controls', 'Cryptography', NULL, 'tls_policy', 'security_startup', 'Enforced TLS policy (secure ciphers, HSTS) and secure-cookie posture validated at startup'),
    -- ISO/IEC 27001 — A.12 Operations security
    ('ISO27001', 'A.12.4', 'Logging and monitoring', 'Operations security', NULL, 'audit_log_chain', 'audit_logs', 'Tamper-evident SHA-256 hash chain on append-only audit_logs with auditor export'),
    ('ISO27001', 'A.12.6', 'Technical vulnerability management', 'Operations security', NULL, 'vuln_management', 'vulnerabilities', 'Live vulnerability findings tracked to remediation with severity SLAs'),
    -- ISO/IEC 27001 — A.13 Communications security
    ('ISO27001', 'A.13.1', 'Network security management', 'Communications security', NULL, 'network_posture', 'engines', 'Agentless network / TLS posture evidence from live scan engines'),
    ('ISO27001', 'A.13.2', 'Information transfer', 'Communications security', NULL, 'tls_policy', 'security_startup', 'Transport confidentiality enforced by TLS policy on all information transfer paths'),

    -- CIS Controls v8 — space-vocabulary group identifiers matching the product control catalog
    ('CIS', 'CIS 1', 'Inventory and control of enterprise assets', 'Asset Management', NULL, 'asset_inventory', 'asm', 'Continuous attack-surface asset discovery inventories enterprise assets'),
    ('CIS', 'CIS 3', 'Data protection', 'Data Protection', NULL, 'rls_isolation', 'clients', 'Tenant data isolated by Postgres RLS; sensitive fields protected at rest and in transit'),
    ('CIS', 'CIS 6', 'Access control management', 'Access Control', NULL, 'login_lockout', 'redis', 'Centralized access control: JWT policy, per-tenant RBAC, distributed brute-force lockout')
ON CONFLICT DO NOTHING;
