-- Make the compliance framework catalog dynamic (database-driven instead of a hardcoded Rust vec)
-- and onboard the remaining product frameworks to the live control-mapping gate. Before this,
-- SOC2 / NIS2 / GDPR / IEC62443 / PCI / CSA-CCM were listed in the UI but carried no live control
-- mappings, so they slipped through the enforcement gate un-evaluated — silent rot. This migration
-- (a) creates compliance_frameworks as the authoritative list and (b) binds every one of those
-- frameworks' canonical controls to a verified, audit-traceable platform evidence source.
--
-- All control-mapping rows are evidence-only (engine_id IS NULL): evidence is produced by
-- platform-wide, inspectable mechanisms (Postgres RLS isolation, tamper-evident audit hash chain,
-- distributed login lockout, startup-enforced TLS policy, agentless cloud posture, live
-- vulnerability management) rather than a single named engine — no stale-engine references.
--
-- Only frameworks that are fully mapped here are seeded as enabled. NIST / HIPAA / FedRAMP carry a
-- canonical control set in the product but no live evidence mapping yet, so they are deliberately
-- absent: listing an unmapped framework would (correctly) void every official artifact through the
-- listed-but-unmapped signal. They are onboarded the same way once their evidence sources exist.

-- 1. Dynamic framework catalog -----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id             BIGSERIAL PRIMARY KEY,
    slug           TEXT NOT NULL UNIQUE,          -- UI slug, e.g. 'iso27001'
    name           TEXT NOT NULL,                 -- display name, e.g. 'ISO/IEC 27001:2022'
    scope          TEXT NOT NULL DEFAULT '',
    db_framework   TEXT NOT NULL,                 -- compliance_control_mappings.framework value
    enabled        BOOLEAN NOT NULL DEFAULT TRUE, -- listed frameworks are subject to the gate
    display_order  INT NOT NULL DEFAULT 100,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_compliance_frameworks_enabled
    ON compliance_frameworks(enabled, display_order);

GRANT SELECT, INSERT, UPDATE ON compliance_frameworks TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE compliance_frameworks_id_seq TO weissman_app;

INSERT INTO compliance_frameworks (slug, name, scope, db_framework, display_order)
VALUES
    ('iso27001', 'ISO/IEC 27001:2022', 'Information Security Management',      'ISO27001', 10),
    ('soc2',     'SOC 2 Type II',      'Trust Services Criteria',              'SOC2',     20),
    ('nis2',     'NIS 2 Directive',    'EU Network and Information Security',  'NIS2',     30),
    ('gdpr',     'GDPR',               'EU General Data Protection Regulation','GDPR',     40),
    ('iec62443', 'IEC 62443',          'OT / Industrial Cybersecurity',        'IEC62443', 50),
    ('pci',      'PCI DSS 4.0',        'Payment Card Industry',                'PCI',      60),
    ('csa-ccm',  'CSA CCM',            'Cloud Controls Matrix',                'CSA-CCM',  70),
    ('cis',      'CIS Benchmarks',     'Center for Internet Security Controls','CIS',      80)
ON CONFLICT (slug) DO NOTHING;

-- 2. Verified control mappings for the six newly-onboarded frameworks ---------------------------
-- Control ids and titles mirror the product's canonical control catalog exactly
-- (static_framework_controls in server_handlers_ui_aliases.inc), so the coverage gate resolves
-- every requirement. A drift-proof unit test parses this file and asserts that.
INSERT INTO compliance_control_mappings
    (framework, control_id, control_title, control_family, engine_id, evidence_type, evidence_source, mapping_notes)
VALUES
    -- SOC 2 (Trust Services Criteria)
    ('SOC2', 'CC6.1', 'Logical and physical access controls', 'Common Criteria', NULL, 'rls_isolation', 'clients', 'Per-tenant RBAC + Postgres RLS enforce least-privilege access to client data'),
    ('SOC2', 'CC6.6', 'Cloud network security', 'Common Criteria', NULL, 'cloud_posture', 'cloud_scan_findings', 'Agentless cloud posture flags dangerous network exposure (open security groups, public buckets)'),
    ('SOC2', 'CC6.7', 'Cryptographic controls', 'Common Criteria', NULL, 'tls_policy', 'security_startup', 'Startup-enforced TLS policy (secure ciphers, HSTS) and secure-cookie posture'),
    ('SOC2', 'CC7.1', 'Detection and monitoring', 'Common Criteria', NULL, 'telemetry', 'job_events', 'Signed zero-trust job bus event sourcing provides continuous detection and monitoring'),

    -- NIS 2 Directive (Art. 21(2) risk-management measures)
    ('NIS2', 'Art.21(2)(d)', 'Supply-chain security', 'Risk-management measures', NULL, 'supply_chain', 'vulnerabilities', 'Supply-chain / dependency findings tracked as live vulnerabilities with remediation SLAs'),
    ('NIS2', 'Art.21(2)(h)', 'Use of cryptography', 'Risk-management measures', NULL, 'tls_policy', 'security_startup', 'Cryptography posture enforced by startup-validated TLS policy'),
    ('NIS2', 'Art.21(2)(i)', 'Access control', 'Risk-management measures', NULL, 'rls_isolation', 'clients', 'Per-tenant RBAC + Postgres RLS enforce access control'),

    -- GDPR
    ('GDPR', 'Art.32', 'Security of processing', 'Data protection', NULL, 'rls_isolation', 'clients', 'Tenant data isolated by Postgres RLS; access controlled per tenant boundary'),

    -- IEC 62443 (Foundational Requirements)
    ('IEC62443', 'FR-1', 'Identification and authentication', 'Foundational Requirements', NULL, 'login_lockout', 'redis', 'Authentication with distributed login lockout and rate limiting'),
    ('IEC62443', 'FR-3', 'System integrity', 'Foundational Requirements', NULL, 'audit_log_chain', 'audit_logs', 'Tamper-evident SHA-256 audit hash chain provides system-integrity evidence'),

    -- PCI DSS 4.0
    ('PCI', '4.1', 'Strong cryptography on public networks', 'Requirement 4', NULL, 'tls_policy', 'security_startup', 'Strong TLS enforced on all public-facing transport via startup-validated TLS policy'),

    -- CSA Cloud Controls Matrix
    ('CSA-CCM', 'DCS-04', 'Data classification', 'Data Security & Privacy', NULL, 'rls_isolation', 'clients', 'Tenant data governed and isolated by Postgres RLS at the tenant boundary')
ON CONFLICT DO NOTHING;
