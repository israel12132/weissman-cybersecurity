-- Phase 2 security hardening: tamper-evident audit chain + live compliance control mappings.

-- 2.4 Audit log hash chain (SHA-256 prev_hash linkage per tenant).
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS event_hash TEXT;

CREATE INDEX IF NOT EXISTS ix_audit_logs_event_hash
    ON audit_logs(event_hash)
    WHERE event_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_audit_logs_tenant_chain
    ON audit_logs(tenant_id, id DESC)
    WHERE event_hash IS NOT NULL;

COMMENT ON COLUMN audit_logs.prev_hash IS
    'SHA-256 hex digest of the previous audit entry in the tenant chain (genesis uses empty string).';
COMMENT ON COLUMN audit_logs.event_hash IS
    'SHA-256 hex digest of canonical v1 audit payload (prev_hash || tenant || actor || action || details || ip || created_at).';

-- 2.7 Live compliance control mappings (framework controls → engines / evidence sources).
CREATE TABLE IF NOT EXISTS compliance_control_mappings (
    id              BIGSERIAL PRIMARY KEY,
    framework       TEXT NOT NULL,
    control_id      TEXT NOT NULL,
    control_title   TEXT NOT NULL DEFAULT '',
    control_family  TEXT NOT NULL DEFAULT '',
    engine_id       TEXT,
    evidence_type   TEXT NOT NULL,
    evidence_source TEXT NOT NULL DEFAULT '',
    live_only       BOOLEAN NOT NULL DEFAULT TRUE,
    mapping_notes   TEXT NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_compliance_control_mappings_natural
    ON compliance_control_mappings (framework, control_id, evidence_type, COALESCE(engine_id, ''));

CREATE INDEX IF NOT EXISTS ix_compliance_control_mappings_framework
    ON compliance_control_mappings(framework);

GRANT SELECT, INSERT, UPDATE ON compliance_control_mappings TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE compliance_control_mappings_id_seq TO weissman_app;

INSERT INTO compliance_control_mappings
    (framework, control_id, control_title, control_family, engine_id, evidence_type, evidence_source, mapping_notes)
VALUES
    ('ISO27001', 'A.8.15', 'Logging', 'Technological', NULL, 'audit_log_chain', 'audit_logs', 'Tamper-evident SHA-256 hash chain on append-only audit_logs'),
    ('ISO27001', 'A.8.16', 'Monitoring activities', 'Technological', NULL, 'telemetry', 'job_events', 'Signed zero-trust job bus event sourcing'),
    ('ISO27001', 'A.5.15', 'Access control', 'Organizational', NULL, 'rls_isolation', 'clients', 'Postgres RLS cross-tenant isolation (weissman_app)'),
    ('ISO27001', 'A.8.5', 'Secure authentication', 'Technological', NULL, 'login_lockout', 'redis', 'Distributed login lockout + rate limits via Redis'),
    ('STIG', 'SRG-APP-000016', 'Session management', 'Application', NULL, 'jwt_policy', 'security_startup', 'Production JWT >=48 chars, secure cookies'),
    ('STIG', 'SRG-APP-000380', 'Account lockout', 'Application', NULL, 'login_lockout', 'redis', 'Per-tenant email lockout after failed attempts'),
    ('STIG', 'SRG-APP-000395', 'Audit record generation', 'Application', NULL, 'audit_log_chain', 'audit_logs', 'Immutable audit trail with hash chain export'),
    ('STIG', 'SRG-APP-000430', 'Audit record retention', 'Application', NULL, 'audit_export', 'audit_logs', 'Auditor export API with chain verification'),
    ('NIST800-53', 'AC-7', 'Unsuccessful logon attempts', 'Access Control', NULL, 'login_lockout', 'redis', 'Distributed brute-force protection'),
    ('NIST800-53', 'AU-9', 'Protection of audit information', 'Audit', NULL, 'audit_log_chain', 'audit_logs', 'Append-only rows + cryptographic hash chain'),
    ('NIST800-53', 'SC-8', 'Transmission confidentiality', 'System', 'tls_posture', 'engine_scan', 'engines', 'Live TLS posture engine evidence'),
    ('CIS', 'CIS-8.2', 'Collect audit logs', 'Logging', NULL, 'audit_log_chain', 'audit_logs', 'Centralized tenant-scoped audit with export'),
    ('CIS', 'CIS-6.1', 'Access control enforcement', 'IAM', NULL, 'rls_isolation', 'clients', 'Database RLS tenant isolation contract')
ON CONFLICT DO NOTHING;
