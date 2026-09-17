-- ─── IOC feed credentials (platform-global, encrypted at rest) ──────────────
--
-- The IOC feed connectors (abuse.ch, OTX, MISP, custom blocklists) authenticate
-- with the PLATFORM's own feed accounts, and they populate the GLOBAL shared
-- indicator store — so their credentials are a platform-level setting, not a
-- per-tenant one. This table is therefore GLOBAL (no RLS), mirroring
-- `ioc_indicators` / `ioc_feed_runs`, and is writable only through the
-- admin-gated `PUT /api/ioc/credentials` handler.
--
-- Values are stored encrypted with the shared AES-256-GCM integrations vault
-- (`soar::integrations_vault`) — the same audited envelope used for MFA seeds
-- and connector secrets. An empty `value_enc` means "not configured" (cleared),
-- in which case the connector falls back to the matching environment variable.

CREATE TABLE IF NOT EXISTS ioc_feed_credentials (
    -- Well-known key == the connector's env-var name (e.g. ABUSE_CH_AUTH_KEY).
    key         TEXT        PRIMARY KEY,
    -- AES-256-GCM envelope (`wzi1:` prefix) or '' when cleared. Never plaintext
    -- for secret keys once a vault key is configured.
    value_enc   TEXT        NOT NULL DEFAULT '',
    updated_by  TEXT        NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON ioc_feed_credentials TO weissman_app;
