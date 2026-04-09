-- Mirror weissman-db migration for fingerprint_engine migrate runs.

CREATE TABLE oast_interaction_hits (
    id              BIGSERIAL PRIMARY KEY,
    interaction_token UUID NOT NULL,
    channel         TEXT NOT NULL CHECK (channel IN ('http', 'dns')),
    source_ip       INET,
    http_method     TEXT,
    http_path       TEXT,
    host_header     TEXT,
    headers_json    JSONB NOT NULL DEFAULT '{}'::jsonb,
    dns_qname       TEXT,
    dns_qtype       TEXT,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_oast_hits_token_time ON oast_interaction_hits(interaction_token, created_at DESC);
CREATE INDEX ix_oast_hits_created ON oast_interaction_hits(created_at DESC);

GRANT SELECT, INSERT ON oast_interaction_hits TO weissman_app;
