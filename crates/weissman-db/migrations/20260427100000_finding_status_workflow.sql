-- Finding status workflow: normalize existing values and add audit column.
-- Allowed statuses: OPEN, ACKNOWLEDGED, IN_PROGRESS, FIXED, FALSE_POSITIVE

-- Normalize any legacy values to OPEN
UPDATE vulnerabilities
SET status = 'OPEN'
WHERE status IS NULL OR status NOT IN ('OPEN','ACKNOWLEDGED','IN_PROGRESS','FIXED','FALSE_POSITIVE');

-- Add status_changed_at column for workflow audit trail (no-op if already exists)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'vulnerabilities' AND column_name = 'status_changed_at'
    ) THEN
        ALTER TABLE vulnerabilities ADD COLUMN status_changed_at TIMESTAMPTZ;
    END IF;
END$$;
