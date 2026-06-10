-- ─── Threat-intel enrichment: EPSS + CISA KEV ─────────────────────────────────
--
-- Sources:
--   * EPSS (Exploit Prediction Scoring System) — FIRST.org
--     GET https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2,...
--     Daily-refreshed score (0.0–1.0) + percentile (0.0–1.0). Source-of-truth for
--     "how likely is this CVE to be exploited in the next 30 days".
--   * CISA KEV (Known Exploited Vulnerabilities) — cisa.gov
--     GET https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
--     Authoritative list of CVEs proven exploited in the wild. Binary signal.
--
-- Both are public, license-free, and updated daily (KEV more often). We mirror them
-- locally (intel pool — tenant-agnostic, no RLS) and join into vulnerabilities at
-- enrichment time.
--
-- This migration adds:
--   1. epss_intel    — one row per CVE, refreshed by the EPSS worker
--   2. kev_intel     — one row per CVE listed in KEV, refreshed by the KEV worker
--   3. New columns on `vulnerabilities`: epss_score, epss_percentile, kev_listed,
--      kev_known_ransomware_use, kev_due_date, intel_enriched_at
--   4. Functional index on raw_data->>'cve' so the enrichment query is fast
--   5. Idempotent — uses IF NOT EXISTS everywhere.

CREATE TABLE IF NOT EXISTS epss_intel (
    cve              TEXT        PRIMARY KEY,
    score            REAL        NOT NULL,                  -- 0.0..1.0
    percentile       REAL        NOT NULL,                  -- 0.0..1.0
    epss_date        DATE        NOT NULL,                  -- the date FIRST.org assigned the score for
    refreshed_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_epss_intel_refreshed ON epss_intel(refreshed_at);
CREATE INDEX IF NOT EXISTS ix_epss_intel_score_desc ON epss_intel(score DESC);

CREATE TABLE IF NOT EXISTS kev_intel (
    cve                          TEXT        PRIMARY KEY,
    vendor_project               TEXT        NOT NULL DEFAULT '',
    product                      TEXT        NOT NULL DEFAULT '',
    vulnerability_name           TEXT        NOT NULL DEFAULT '',
    date_added                   DATE,
    short_description            TEXT        NOT NULL DEFAULT '',
    required_action              TEXT        NOT NULL DEFAULT '',
    due_date                     DATE,
    known_ransomware_use         BOOLEAN     NOT NULL DEFAULT FALSE,
    notes                        TEXT        NOT NULL DEFAULT '',
    refreshed_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_kev_intel_added ON kev_intel(date_added DESC);

-- Both tables are global (CVE intel is not tenant-scoped). Explicitly disable RLS
-- and grant the app role read+write; the workers run as `weissman_app`.
ALTER TABLE epss_intel DISABLE ROW LEVEL SECURITY;
ALTER TABLE kev_intel  DISABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON epss_intel TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON kev_intel  TO weissman_app;

-- ─── Enrichment columns on vulnerabilities ────────────────────────────────────
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS epss_score              REAL,
    ADD COLUMN IF NOT EXISTS epss_percentile         REAL,
    ADD COLUMN IF NOT EXISTS kev_listed              BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS kev_known_ransomware    BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS kev_due_date            DATE,
    ADD COLUMN IF NOT EXISTS intel_enriched_at       TIMESTAMPTZ;

-- Functional index on the CVE extracted from raw_data so the enrichment join scales.
CREATE INDEX IF NOT EXISTS ix_vuln_raw_cve
    ON vulnerabilities ((raw_data->>'cve'))
    WHERE raw_data->>'cve' IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_vuln_kev_listed
    ON vulnerabilities(tenant_id, kev_listed) WHERE kev_listed = TRUE;

CREATE INDEX IF NOT EXISTS ix_vuln_epss_high
    ON vulnerabilities(tenant_id, epss_score DESC) WHERE epss_score IS NOT NULL;
