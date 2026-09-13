-- Durable notification outbox for alert delivery (webhook / Slack / Teams / PagerDuty / email).
--
-- Alert delivery used to be fire-and-forget: a transient 5xx from a webhook/Slack/PagerDuty
-- endpoint silently DROPPED a security alert (one WARN, no retry, no record). This table makes
-- delivery durable: every per-channel attempt is persisted `pending` BEFORE it is tried, flipped to
-- `delivered` on success, or left for the retry worker (exponential backoff) and finally
-- `dead`-lettered after the max attempts so a silent failure becomes a loud, queryable one.
--
-- FORCE ROW LEVEL SECURITY with a tenant policy via public.app_current_tenant_id() (the cast-safe
-- helper — never current_setting(...)::bigint, which raises on an empty GUC and took production down
-- for four days). The retry worker sweeps per tenant inside begin_tenant_tx, so the tenant GUC is
-- always a concrete id and RLS is satisfied without a BYPASSRLS connection.

CREATE TABLE IF NOT EXISTS notification_outbox (
    id               BIGSERIAL PRIMARY KEY,
    tenant_id        BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    channel          TEXT NOT NULL,
    payload          JSONB NOT NULL DEFAULT '{}'::jsonb,
    status           TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'delivered', 'dead')),
    attempts         INT NOT NULL DEFAULT 0,
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error       TEXT,
    delivered_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Worker scan: oldest-due pending rows first. Partial index stays tight as delivered/dead pile up.
CREATE INDEX IF NOT EXISTS ix_notification_outbox_due
    ON notification_outbox (next_attempt_at)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS ix_notification_outbox_tenant
    ON notification_outbox (tenant_id, created_at DESC);

ALTER TABLE notification_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_outbox FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS notification_outbox_tenant ON notification_outbox;
CREATE POLICY notification_outbox_tenant ON notification_outbox FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_outbox TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE notification_outbox_id_seq TO weissman_app;
