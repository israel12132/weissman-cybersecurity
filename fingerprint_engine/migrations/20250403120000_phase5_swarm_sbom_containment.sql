-- Phase 5: SBOM inventory, global threat ingestion, auto-containment rules.

CREATE TABLE IF NOT EXISTS client_sbom_components (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    package_name    TEXT NOT NULL,
    ecosystem       TEXT NOT NULL DEFAULT '',
    version_spec    TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT 'manual',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_sbom_tenant ON client_sbom_components (tenant_id);
CREATE INDEX IF NOT EXISTS ix_sbom_client ON client_sbom_components (client_id);
CREATE INDEX IF NOT EXISTS ix_sbom_pkg_lower ON client_sbom_components (lower(package_name));

ALTER TABLE client_sbom_components ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_sbom_components FORCE ROW LEVEL SECURITY;
CREATE POLICY client_sbom_components_tenant ON client_sbom_components FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON client_sbom_components TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE client_sbom_components_id_seq TO weissman_app;

CREATE TABLE IF NOT EXISTS threat_ingest_events (
    id                   BIGSERIAL PRIMARY KEY,
    tenant_id            BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source               TEXT NOT NULL,
    external_id          TEXT NOT NULL,
    title                TEXT NOT NULL,
    severity             TEXT NOT NULL,
    matched_packages     TEXT NOT NULL DEFAULT '[]',
    exploit_signature_json TEXT NOT NULL DEFAULT '{}',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, source, external_id)
);

CREATE INDEX IF NOT EXISTS ix_threat_ingest_tenant ON threat_ingest_events (tenant_id);

ALTER TABLE threat_ingest_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_ingest_events FORCE ROW LEVEL SECURITY;
CREATE POLICY threat_ingest_events_tenant ON threat_ingest_events FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON threat_ingest_events TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE threat_ingest_events_id_seq TO weissman_app;

CREATE TABLE IF NOT EXISTS containment_rules (
    id                      BIGSERIAL PRIMARY KEY,
    tenant_id               BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id               BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name                    TEXT NOT NULL,
    enabled                 BOOLEAN NOT NULL DEFAULT false,
    pre_approved            BOOLEAN NOT NULL DEFAULT false,
    aws_region              TEXT NOT NULL DEFAULT '',
    forensic_source_cidr    TEXT NOT NULL DEFAULT '0.0.0.0/0',
    forensic_ports_csv      TEXT NOT NULL DEFAULT '22,443',
    k8s_api_server          TEXT NOT NULL DEFAULT '',
    k8s_token_env_var       TEXT NOT NULL DEFAULT '',
    k8s_namespace           TEXT NOT NULL DEFAULT 'default',
    k8s_pod_label_key       TEXT NOT NULL DEFAULT '',
    k8s_pod_label_value     TEXT NOT NULL DEFAULT '',
    allow_dns_egress        BOOLEAN NOT NULL DEFAULT true,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_containment_tenant ON containment_rules (tenant_id);
CREATE INDEX IF NOT EXISTS ix_containment_client ON containment_rules (client_id);

ALTER TABLE containment_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE containment_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY containment_rules_tenant ON containment_rules FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON containment_rules TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE containment_rules_id_seq TO weissman_app;
