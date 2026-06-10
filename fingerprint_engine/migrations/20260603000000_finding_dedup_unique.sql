-- Finding dedup: enforce uniqueness on (tenant_id, client_id, finding_id) so
-- ON CONFLICT … DO UPDATE in findings_persist::persist_engine_findings actually
-- collapses repeat detections instead of inserting fresh rows every scan.
--
-- Adds two recurrence-tracking columns the upsert needs:
--   * last_seen_at — last time the engine re-confirmed the finding
--   * seen_count   — number of times the same vulnerability re-fired
--
-- Old rows are squashed before the constraint is added (keep newest per group,
-- preserve max(seen_count) for any prior runs).

-- 1) New columns (idempotent)
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS seen_count   INTEGER     NOT NULL DEFAULT 1;

-- 2) Backfill last_seen_at to discovered_at for rows created before the column existed
UPDATE vulnerabilities
   SET last_seen_at = discovered_at
 WHERE last_seen_at = '1970-01-01'::timestamptz OR last_seen_at < discovered_at;

-- 3) Collapse pre-existing duplicates per (tenant_id, client_id, finding_id) keeping
--    the latest row, accumulating seen_count.
WITH dup AS (
    SELECT id,
           tenant_id,
           client_id,
           finding_id,
           ROW_NUMBER() OVER (
               PARTITION BY tenant_id, client_id, finding_id
               ORDER BY discovered_at DESC, id DESC
           ) AS rn,
           COUNT(*)   OVER (PARTITION BY tenant_id, client_id, finding_id) AS dup_total
      FROM vulnerabilities
),
keep AS (
    SELECT tenant_id, client_id, finding_id, dup_total
      FROM dup
     WHERE rn = 1 AND dup_total > 1
)
UPDATE vulnerabilities v
   SET seen_count = GREATEST(v.seen_count, keep.dup_total::int)
  FROM keep
 WHERE v.tenant_id = keep.tenant_id
   AND v.client_id = keep.client_id
   AND v.finding_id = keep.finding_id;

DELETE FROM vulnerabilities
 WHERE id IN (
    SELECT id FROM (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY tenant_id, client_id, finding_id
                   ORDER BY discovered_at DESC, id DESC
               ) AS rn
          FROM vulnerabilities
    ) d
    WHERE d.rn > 1
);

-- 4) Add the unique constraint (named so app code / future migrations can target it)
ALTER TABLE vulnerabilities
    DROP CONSTRAINT IF EXISTS vulnerabilities_dedup_uq;
ALTER TABLE vulnerabilities
    ADD  CONSTRAINT vulnerabilities_dedup_uq UNIQUE (tenant_id, client_id, finding_id);

-- 5) Functional index for the hot read path (severity filter): /api/findings does
--    `WHERE lower(severity) = $1` which forces a seqscan without this index.
CREATE INDEX IF NOT EXISTS ix_vuln_lower_severity
    ON vulnerabilities (tenant_id, lower(severity), discovered_at DESC);

-- 6) Composite index for client-scoped listing (the second most common UI query)
CREATE INDEX IF NOT EXISTS ix_vuln_client_discovered
    ON vulnerabilities (client_id, discovered_at DESC);
