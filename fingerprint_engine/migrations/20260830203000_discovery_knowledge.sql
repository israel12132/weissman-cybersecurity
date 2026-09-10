-- Unbounded growing corpus of HTTP paths and DNS subdomain prefixes.
-- Shared intel (no RLS) — same model as intel.dynamic_payloads. Seed + live LLM + probe hits.

CREATE SCHEMA IF NOT EXISTS intel;

CREATE TABLE IF NOT EXISTS intel.discovery_knowledge (
    id              BIGSERIAL PRIMARY KEY,
    kind            TEXT NOT NULL CHECK (kind IN ('path', 'subdomain_prefix')),
    value           TEXT NOT NULL,
    value_key       TEXT NOT NULL GENERATED ALWAYS AS (lower(value)) STORED,
    tech_hint       TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT 'seed',
    confirmed       BOOLEAN NOT NULL DEFAULT false,
    hit_count       BIGINT NOT NULL DEFAULT 1,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT discovery_knowledge_value_len CHECK (char_length(value) BETWEEN 1 AND 512),
    CONSTRAINT ux_discovery_knowledge_kind_value UNIQUE (kind, value_key, tech_hint)
);

CREATE INDEX IF NOT EXISTS ix_discovery_knowledge_kind_hits
    ON intel.discovery_knowledge (kind, confirmed DESC, hit_count DESC);

CREATE INDEX IF NOT EXISTS ix_discovery_knowledge_source
    ON intel.discovery_knowledge (source, last_seen_at DESC);

COMMENT ON TABLE intel.discovery_knowledge IS
    'Unbounded discovery corpus: HTTP paths and DNS subdomain prefixes. Seed + live LLM + confirmed probe hits. Shared intel, no RLS.';

GRANT USAGE ON SCHEMA intel TO weissman_app;
GRANT USAGE ON SCHEMA intel TO weissman_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON intel.discovery_knowledge TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON intel.discovery_knowledge TO weissman_auth;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE intel.discovery_knowledge_id_seq TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE intel.discovery_knowledge_id_seq TO weissman_auth;
