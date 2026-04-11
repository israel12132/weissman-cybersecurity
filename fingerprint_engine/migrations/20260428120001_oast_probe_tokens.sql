-- Structured OAST probe token registry.
--
-- Each probe generates a UUID token bound to a client/finding for zero-false-positive callback verification.
-- The weissman-oast-server writes hits into `oast_interaction_hits` (existing); this table provides
-- the structured binding so the API can answer "did THIS specific probe for THIS finding get a callback?"

CREATE TABLE oast_probe_tokens (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    client_id       BIGINT REFERENCES clients (id) ON DELETE SET NULL,
    finding_id      TEXT,                                 -- optional link to vulnerabilities.finding_id
    hitl_queue_id   BIGINT REFERENCES council_hitl_queue (id) ON DELETE SET NULL,

    token           UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    probe_type      TEXT NOT NULL DEFAULT 'generic'
        CHECK (probe_type IN ('log4shell', 'blind_xss', 'blind_xxe', 'blind_ssrf', 'generic')),
    target_url      TEXT NOT NULL DEFAULT '',
    label           TEXT NOT NULL DEFAULT '',             -- free-form note from the operator

    -- Verification state (updated by poll)
    hit_count       INT  NOT NULL DEFAULT 0,
    first_hit_at    TIMESTAMPTZ,
    last_polled_at  TIMESTAMPTZ,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '7 days')
);

CREATE INDEX ix_oast_probe_tokens_tenant  ON oast_probe_tokens (tenant_id, created_at DESC);
CREATE INDEX ix_oast_probe_tokens_client  ON oast_probe_tokens (client_id);
CREATE INDEX ix_oast_probe_tokens_token   ON oast_probe_tokens (token);
CREATE INDEX ix_oast_probe_tokens_hitl    ON oast_probe_tokens (hitl_queue_id);

ALTER TABLE oast_probe_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE oast_probe_tokens FORCE ROW LEVEL SECURITY;

CREATE POLICY oast_probe_tokens_tenant ON oast_probe_tokens FOR ALL
    USING  (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE ON oast_probe_tokens TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE oast_probe_tokens_id_seq TO weissman_app;

COMMENT ON TABLE oast_probe_tokens IS 'Structured OAST probe registry. Each row is one OOB probe token linked to client/finding. Callbacks are correlated via oast_interaction_hits.interaction_token.';
