-- DNS covert audits: hourly validated-anomaly summaries only.
-- Raw per-query INSERTs are forbidden (Postgres pool / WAL saturation under
-- enterprise DNS QPS). Dedup + aggregation happen in-memory and Redis
-- (`weissman:dns_covert_seen:*`, `weissman:dns_covert_summary:{tenant}:{host}:{hour}`).

ALTER TABLE dns_covert_query_audits
    ADD COLUMN IF NOT EXISTS hour_utc TIMESTAMPTZ;

COMMENT ON TABLE dns_covert_query_audits IS
    'Hourly DNS covert-channel anomaly summaries (per domain/hour). Raw per-query rows are never written. RLS-enforced.';

CREATE UNIQUE INDEX IF NOT EXISTS ux_dns_covert_summary_host_hour
    ON dns_covert_query_audits (tenant_id, query_host, hour_utc)
    WHERE qtype = 'SUMMARY' AND hour_utc IS NOT NULL;
