-- Phase 3: Agentless cloud integration, compliance mappings, cloud scan findings.

ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS aws_cross_account_role_arn TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS aws_external_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS gcp_project_id TEXT NOT NULL DEFAULT '';

-- Global control catalog (no tenant_id); readable by all tenants via app role.
CREATE TABLE IF NOT EXISTS compliance_mappings (
    id                 BIGSERIAL PRIMARY KEY,
    framework          TEXT NOT NULL,
    control_id         TEXT NOT NULL,
    control_title      TEXT NOT NULL,
    rule_key           TEXT NOT NULL UNIQUE,
    cloud_rule_id      TEXT,
    vuln_source_contains TEXT,
    vuln_title_contains  TEXT,
    vuln_min_severity    TEXT
);

CREATE INDEX IF NOT EXISTS ix_compliance_mappings_framework ON compliance_mappings (framework);
CREATE INDEX IF NOT EXISTS ix_compliance_mappings_cloud_rule ON compliance_mappings (cloud_rule_id) WHERE cloud_rule_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS cloud_scan_findings (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    region          TEXT NOT NULL DEFAULT '',
    rule_id         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    detail_json     TEXT NOT NULL DEFAULT '{}',
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_cloud_scan_tenant ON cloud_scan_findings (tenant_id);
CREATE INDEX IF NOT EXISTS ix_cloud_scan_client ON cloud_scan_findings (client_id);
CREATE INDEX IF NOT EXISTS ix_cloud_scan_rule ON cloud_scan_findings (rule_id);

ALTER TABLE cloud_scan_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_scan_findings FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_scan_findings_tenant ON cloud_scan_findings FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

-- Seed mappings: cloud + vulnerability patterns → SOC 2 / ISO 27001 / GDPR
INSERT INTO compliance_mappings (framework, control_id, control_title, rule_key, cloud_rule_id, vuln_source_contains, vuln_title_contains, vuln_min_severity)
VALUES
    ('SOC2', 'CC6.1', 'Logical and physical access controls', 's3_public_exposure', 's3_bucket_public_access', NULL, NULL, NULL),
    ('ISO27001', 'A.8.5', 'Authentication information', 's3_public_iso', 's3_bucket_public_access', NULL, NULL, NULL),
    ('GDPR', 'Art.32', 'Security of processing', 's3_public_gdpr', 's3_bucket_public_access', NULL, NULL, NULL),
    ('SOC2', 'CC6.6', 'Boundary protection', 'ec2_sg_open_iso', 'ec2_security_group_dangerous_ingress', NULL, NULL, NULL),
    ('ISO27001', 'A.13.1', 'Network security management', 'ec2_sg_open_iso2', 'ec2_security_group_dangerous_ingress', NULL, NULL, NULL),
    ('GDPR', 'Art.32', 'Security of processing', 'ec2_sg_gdpr', 'ec2_security_group_dangerous_ingress', NULL, NULL, NULL),
    ('SOC2', 'CC7.2', 'Detection of security events', 'vuln_critical_soc2', NULL, NULL, NULL, 'critical'),
    ('ISO27001', 'A.12.6', 'Management of technical vulnerabilities', 'vuln_critical_iso', NULL, NULL, NULL, 'critical'),
    ('GDPR', 'Art.32', 'Security of processing', 'vuln_critical_gdpr', NULL, NULL, NULL, 'critical'),
    ('SOC2', 'CC7.2', 'Detection of security events', 'vuln_high_soc2', NULL, NULL, NULL, 'high'),
    ('ISO27001', 'A.12.6', 'Management of technical vulnerabilities', 'vuln_high_iso', NULL, NULL, NULL, 'high'),
    ('GDPR', 'Art.32', 'Security of processing', 'vuln_high_gdpr', NULL, NULL, NULL, 'high'),
    ('SOC2', 'CC2.1', 'Communication of objectives', 'fuzzing_soc2', NULL, 'semantic_ai_fuzz', NULL, 'medium'),
    ('SOC2', 'CC2.1', 'Communication of objectives', 'fuzzing_soc2_ollama', NULL, 'ollama_fuzz', NULL, 'medium'),
    ('ISO27001', 'A.14.2', 'Security in development', 'fuzzing_iso', NULL, 'semantic_ai_fuzz', NULL, 'medium'),
    ('GDPR', 'Art.25', 'Data protection by design', 'osint_gdpr', NULL, 'osint', NULL, 'low')
ON CONFLICT (rule_key) DO NOTHING;

GRANT SELECT ON compliance_mappings TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON cloud_scan_findings TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE cloud_scan_findings_id_seq TO weissman_app;
