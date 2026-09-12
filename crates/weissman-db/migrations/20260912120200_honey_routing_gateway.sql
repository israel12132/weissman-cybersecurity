-- Honey-Routing Gateway: attacker sessions, captured payloads, FAIR ARO floor,
-- vhost→client bindings. Live ingest only — no demo rows.

CREATE TABLE IF NOT EXISTS honey_route_sessions (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT REFERENCES clients(id) ON DELETE CASCADE,
    session_fp          TEXT NOT NULL,
    source_ip           TEXT NOT NULL DEFAULT '',
    user_agent          TEXT NOT NULL DEFAULT '',
    decoy_path          TEXT NOT NULL DEFAULT '',
    confidence          INTEGER NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
    high_confidence     BOOLEAN NOT NULL DEFAULT FALSE,
    lateral_attempt     BOOLEAN NOT NULL DEFAULT FALSE,
    scanner_signals     JSONB NOT NULL DEFAULT '[]'::jsonb,
    mitre_techniques    JSONB NOT NULL DEFAULT '[]'::jsonb,
    browser_profile     JSONB NOT NULL DEFAULT '{}'::jsonb,
    hit_count           INTEGER NOT NULL DEFAULT 1,
    last_payload_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    soar_paged_at       TIMESTAMPTZ,
    soar_isolated_at    TIMESTAMPTZ,
    isolate_requested_by BIGINT,
    isolate_requested_at TIMESTAMPTZ,
    isolate_approved_by  BIGINT,
    isolate_approved_at  TIMESTAMPTZ,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, session_fp)
);

CREATE INDEX IF NOT EXISTS ix_honey_route_sessions_client
    ON honey_route_sessions (tenant_id, client_id, last_payload_at DESC);
CREATE INDEX IF NOT EXISTS ix_honey_route_sessions_ip
    ON honey_route_sessions (source_ip, last_payload_at DESC);

ALTER TABLE honey_route_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE honey_route_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS honey_route_sessions_tenant ON honey_route_sessions;
CREATE POLICY honey_route_sessions_tenant ON honey_route_sessions FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

CREATE TABLE IF NOT EXISTS honey_route_payloads (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT REFERENCES clients(id) ON DELETE CASCADE,
    session_id          BIGINT NOT NULL REFERENCES honey_route_sessions(id) ON DELETE CASCADE,
    http_method         TEXT NOT NULL DEFAULT 'GET',
    path                TEXT NOT NULL,
    query_string        TEXT NOT NULL DEFAULT '',
    body_excerpt        TEXT NOT NULL DEFAULT '',
    headers_json        JSONB NOT NULL DEFAULT '{}'::jsonb,
    mitre_techniques    JSONB NOT NULL DEFAULT '[]'::jsonb,
    shell_command       TEXT,
    decoy_kind          TEXT NOT NULL DEFAULT 'http',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_honey_route_payloads_session
    ON honey_route_payloads (session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_honey_route_payloads_client
    ON honey_route_payloads (tenant_id, client_id, created_at DESC);

ALTER TABLE honey_route_payloads ENABLE ROW LEVEL SECURITY;
ALTER TABLE honey_route_payloads FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS honey_route_payloads_tenant ON honey_route_payloads;
CREATE POLICY honey_route_payloads_tenant ON honey_route_payloads FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

CREATE TABLE IF NOT EXISTS honey_route_vhost_bindings (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    host                TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_honey_route_vhost
    ON honey_route_vhost_bindings (tenant_id, lower(host));

ALTER TABLE honey_route_vhost_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE honey_route_vhost_bindings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS honey_route_vhost_bindings_tenant ON honey_route_vhost_bindings;
CREATE POLICY honey_route_vhost_bindings_tenant ON honey_route_vhost_bindings FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

-- Live FAIR ARO floor when a honey-route attack is in progress (architecture: min 3.0).
CREATE TABLE IF NOT EXISTS honey_route_fair_overrides (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    aro_floor           DOUBLE PRECISION NOT NULL DEFAULT 3.0 CHECK (aro_floor >= 0),
    reason              TEXT NOT NULL DEFAULT 'honey_route_live_attack',
    session_id          BIGINT REFERENCES honey_route_sessions(id) ON DELETE SET NULL,
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, client_id)
);

ALTER TABLE honey_route_fair_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE honey_route_fair_overrides FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS honey_route_fair_overrides_tenant ON honey_route_fair_overrides;
CREATE POLICY honey_route_fair_overrides_tenant ON honey_route_fair_overrides FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON honey_route_sessions TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON honey_route_payloads TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON honey_route_vhost_bindings TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON honey_route_fair_overrides TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE honey_route_sessions_id_seq TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE honey_route_payloads_id_seq TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE honey_route_vhost_bindings_id_seq TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE honey_route_fair_overrides_id_seq TO weissman_app;

-- Optional operator playbooks for the default tenant (idempotent).
INSERT INTO weissman_playbooks (
    tenant_id, name, description, enabled, trigger_dsl, actions_dsl
)
SELECT t.id,
       'Honey-Route High Confidence Page',
       'Pages on-call when the honey-routing gateway scores a 100% confidence attacker session. cooldown_seconds=3600.',
       TRUE,
       '{"severity":["critical"],"engines":["honey_routing_gateway"],"kinds":["honey_route_high_confidence"],"cooldown_seconds":3600}'::jsonb,
       '[{"kind":"page_oncall","params":{"team":"sec-oncall","severity":"critical"}}]'::jsonb
  FROM tenants t
 WHERE t.slug = 'default'
   AND NOT EXISTS (
        SELECT 1 FROM weissman_playbooks p
         WHERE p.tenant_id = t.id
           AND lower(p.name) = lower('Honey-Route High Confidence Page')
   );

INSERT INTO weissman_playbooks (
    tenant_id, name, description, enabled, trigger_dsl, actions_dsl
)
SELECT t.id,
       'Honey-Route Lateral Isolation',
       'HITL-only isolate_host template. Disabled in production; kinds=["honey_route_isolate_hitl"] so automatic 100% page events never isolate. cooldown_seconds=3600.',
       FALSE,
       '{"severity":["critical"],"engines":["honey_routing_gateway"],"kinds":["honey_route_isolate_hitl"],"cooldown_seconds":3600}'::jsonb,
       '[{"kind":"isolate_host","params":{"target":"{{target}}","duration_seconds":3600}}]'::jsonb
  FROM tenants t
 WHERE t.slug = 'default'
   AND NOT EXISTS (
        SELECT 1 FROM weissman_playbooks p
         WHERE p.tenant_id = t.id
           AND lower(p.name) = lower('Honey-Route Lateral Isolation')
   );
