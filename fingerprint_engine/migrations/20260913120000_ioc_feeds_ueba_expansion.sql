-- ─── IOC feeds + extended UEBA behavioural analytics ────────────────────────
--
-- Two fused capabilities:
--
--   A. Indicator-of-Compromise (IOC) store + multi-source feed ingestion.
--      Public threat-intel indicators (abuse.ch ThreatFox/URLhaus/Feodo,
--      AlienVault OTX, STIX/TAXII bundles, plain blocklists, MISP) are the SAME
--      for every tenant, so the indicator store is GLOBAL (no RLS) — mirroring
--      the `intel` schema / global `weissman_async_jobs` pattern. Duplicating
--      millions of rows per tenant would be both wasteful and wrong.
--      What a specific tenant SAW (a host talking to a known-bad IP, a local
--      process whose SHA-256 is a known dropper) is tenant-secret, so
--      `ioc_sightings` and the per-tenant `ioc_watchlist` ARE RLS-scoped.
--
--   B. Extended UEBA — peer-group (cohort) robust baselines (median + MAD →
--      modified z-score) and a decayed per-entity risk score with
--      explainability. Both are tenant-scoped telemetry, so RLS applies.
--
-- All tenant tables use FORCE ROW LEVEL SECURITY so even the table owner is
-- subject to `app.current_tenant_id` — identical to agent_metric_* tables.

-- ════════════════════════════════════════════════════════════════════════════
-- A1. ioc_indicators — GLOBAL normalized indicator store
-- ════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS ioc_indicators (
    id              BIGSERIAL   PRIMARY KEY,
    -- ipv4 | ipv6 | domain | url | sha256 | sha1 | md5 | email | ja3 | ja3s |
    -- file_path | mutex | registry_key | cidr
    ioc_type        TEXT        NOT NULL,
    -- As published by the source (defanged values are re-fanged on ingest).
    value           TEXT        NOT NULL,
    -- Canonical match key: lowercased, trailing-dot stripped, URL host+path.
    value_norm      TEXT        NOT NULL,
    source          TEXT        NOT NULL,                 -- threatfox | urlhaus | feodo | otx | stix | blocklist | misp | manual
    -- Base confidence 0..100 as published; effective confidence after decay is
    -- computed at read time (see ioc::decay).
    confidence      SMALLINT    NOT NULL DEFAULT 50,
    severity        TEXT        NOT NULL DEFAULT 'medium', -- info|low|medium|high|critical
    tlp             TEXT        NOT NULL DEFAULT 'amber',  -- white|green|amber|red
    malware_family  TEXT        NOT NULL DEFAULT '',
    mitre           TEXT        NOT NULL DEFAULT '',       -- comma-separated ATT&CK technique ids
    tags            JSONB       NOT NULL DEFAULT '[]'::jsonb,
    reference_url   TEXT        NOT NULL DEFAULT '',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Hard expiry; decay also ages confidence toward zero well before this.
    expires_at      TIMESTAMPTZ,
    active          BOOLEAN     NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Re-ingesting the same indicator from the same feed updates it in place.
    CONSTRAINT ioc_indicators_uq UNIQUE (ioc_type, value_norm, source)
);

-- Matching is by normalized value (exact / host / CIDR done in-engine after a
-- cheap value_norm hit). Keep it a plain btree — the retrohunt path queries by
-- equality and prefix.
CREATE INDEX IF NOT EXISTS ix_ioc_value_norm ON ioc_indicators (value_norm);
CREATE INDEX IF NOT EXISTS ix_ioc_type_active ON ioc_indicators (ioc_type, active);
CREATE INDEX IF NOT EXISTS ix_ioc_expires ON ioc_indicators (expires_at);
CREATE INDEX IF NOT EXISTS ix_ioc_source ON ioc_indicators (source);
CREATE INDEX IF NOT EXISTS ix_ioc_last_seen ON ioc_indicators (last_seen DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON ioc_indicators TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE ioc_indicators_id_seq TO weissman_app;

-- ════════════════════════════════════════════════════════════════════════════
-- A2. ioc_feed_runs — GLOBAL feed-fetch audit / health
-- ════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS ioc_feed_runs (
    id              BIGSERIAL   PRIMARY KEY,
    source          TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'running', -- running|ok|error|skipped
    fetched         INTEGER     NOT NULL DEFAULT 0,
    inserted        INTEGER     NOT NULL DEFAULT 0,
    updated         INTEGER     NOT NULL DEFAULT 0,
    expired         INTEGER     NOT NULL DEFAULT 0,
    error           TEXT        NOT NULL DEFAULT '',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    duration_ms     BIGINT      NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_ioc_feed_runs_recent ON ioc_feed_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS ix_ioc_feed_runs_source ON ioc_feed_runs (source, started_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON ioc_feed_runs TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE ioc_feed_runs_id_seq TO weissman_app;

-- ════════════════════════════════════════════════════════════════════════════
-- A3. ioc_sightings — TENANT-SCOPED: a tenant asset matched a known indicator
-- ════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS ioc_sightings (
    id              BIGSERIAL   PRIMARY KEY,
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT      REFERENCES clients(id) ON DELETE SET NULL,
    agent_id        TEXT        NOT NULL DEFAULT '',
    -- Soft reference (public-feed ids are global; custom-watchlist sightings
    -- carry no indicator_id). Not an FK so a feed refresh can't orphan history.
    indicator_id    BIGINT,
    ioc_type        TEXT        NOT NULL,
    value           TEXT        NOT NULL,
    -- Where it was seen: agent_process_hash | agent_remote_ip | agent_dns |
    -- finding | scan_target | watchlist
    context         TEXT        NOT NULL,
    finding_id      TEXT,                                  -- loose string id (findings use string ids)
    severity        TEXT        NOT NULL DEFAULT 'high',
    confidence      SMALLINT    NOT NULL DEFAULT 75,
    source          TEXT        NOT NULL DEFAULT '',
    detail          TEXT        NOT NULL DEFAULT '',
    seen_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_ioc_sightings_recent ON ioc_sightings (tenant_id, seen_at DESC);
CREATE INDEX IF NOT EXISTS ix_ioc_sightings_agent ON ioc_sightings (tenant_id, agent_id, seen_at DESC);
CREATE INDEX IF NOT EXISTS ix_ioc_sightings_value ON ioc_sightings (tenant_id, value);

ALTER TABLE ioc_sightings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ioc_sightings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ioc_sightings_tenant ON ioc_sightings;
CREATE POLICY ioc_sightings_tenant ON ioc_sightings FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON ioc_sightings TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE ioc_sightings_id_seq TO weissman_app;

-- ════════════════════════════════════════════════════════════════════════════
-- A4. ioc_watchlist — TENANT-SCOPED: analyst-curated custom indicators
-- ════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS ioc_watchlist (
    id              BIGSERIAL   PRIMARY KEY,
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ioc_type        TEXT        NOT NULL,
    value           TEXT        NOT NULL,
    value_norm      TEXT        NOT NULL,
    severity        TEXT        NOT NULL DEFAULT 'high',
    confidence      SMALLINT    NOT NULL DEFAULT 90,
    note            TEXT        NOT NULL DEFAULT '',
    created_by      TEXT        NOT NULL DEFAULT '',
    active          BOOLEAN     NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ioc_watchlist_uq UNIQUE (tenant_id, ioc_type, value_norm)
);

CREATE INDEX IF NOT EXISTS ix_ioc_watchlist_tenant ON ioc_watchlist (tenant_id, active);
CREATE INDEX IF NOT EXISTS ix_ioc_watchlist_value ON ioc_watchlist (tenant_id, value_norm);

ALTER TABLE ioc_watchlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE ioc_watchlist FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ioc_watchlist_tenant ON ioc_watchlist;
CREATE POLICY ioc_watchlist_tenant ON ioc_watchlist FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON ioc_watchlist TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE ioc_watchlist_id_seq TO weissman_app;

-- ════════════════════════════════════════════════════════════════════════════
-- B1. ueba_peer_baselines — TENANT-SCOPED cohort robust baselines
--     One row per (cohort, metric, hour-of-week). Robust stats (median + MAD)
--     resist the masking/swamping that mean+stddev suffer when a host is
--     already compromised during the learning window.
-- ════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS ueba_peer_baselines (
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Cohort key: "os:linux", "os:windows", "client:42", or "fleet".
    cohort          TEXT        NOT NULL,
    metric_name     TEXT        NOT NULL,
    hour_of_week    SMALLINT    NOT NULL,
    n               INTEGER     NOT NULL DEFAULT 0,
    median          DOUBLE PRECISION NOT NULL DEFAULT 0,
    -- Median absolute deviation (scaled by 1.4826 at read time for the
    -- Gaussian-consistent robust sigma).
    mad             DOUBLE PRECISION NOT NULL DEFAULT 0,
    p95             DOUBLE PRECISION NOT NULL DEFAULT 0,
    mean            DOUBLE PRECISION NOT NULL DEFAULT 0,
    stddev          DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, cohort, metric_name, hour_of_week)
);

CREATE INDEX IF NOT EXISTS ix_upb_cohort ON ueba_peer_baselines (tenant_id, cohort);

ALTER TABLE ueba_peer_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE ueba_peer_baselines FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ueba_peer_baselines_tenant ON ueba_peer_baselines;
CREATE POLICY ueba_peer_baselines_tenant ON ueba_peer_baselines FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON ueba_peer_baselines TO weissman_app;

-- ════════════════════════════════════════════════════════════════════════════
-- B2. ueba_entity_risk — TENANT-SCOPED decayed risk score per entity
--     risk(t) = risk(t0) * exp(-ln2 * dt_hours / half_life_hours) + new_weight
--     Contributors carries the top signals feeding the score (explainability).
-- ════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS ueba_entity_risk (
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entity_type     TEXT        NOT NULL,                  -- agent | user | host
    entity_id       TEXT        NOT NULL,
    client_id       BIGINT,
    risk_score      DOUBLE PRECISION NOT NULL DEFAULT 0,
    peak_score      DOUBLE PRECISION NOT NULL DEFAULT 0,
    severity        TEXT        NOT NULL DEFAULT 'low',
    event_count     INTEGER     NOT NULL DEFAULT 0,
    contributors    JSONB       NOT NULL DEFAULT '[]'::jsonb,
    last_event_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_decay_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, entity_type, entity_id)
);

CREATE INDEX IF NOT EXISTS ix_uer_score ON ueba_entity_risk (tenant_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS ix_uer_updated ON ueba_entity_risk (tenant_id, updated_at DESC);

ALTER TABLE ueba_entity_risk ENABLE ROW LEVEL SECURITY;
ALTER TABLE ueba_entity_risk FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ueba_entity_risk_tenant ON ueba_entity_risk;
CREATE POLICY ueba_entity_risk_tenant ON ueba_entity_risk FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON ueba_entity_risk TO weissman_app;
