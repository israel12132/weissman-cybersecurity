-- ROE override governance: weaponized ROE requires explicit approval trail.
-- Default flow:
--  - patch client config roe_mode=weaponized_god_mode → creates pending request (unless confirm header secret is provided)
--  - two distinct admin approvals → status becomes approved; optional auto-apply can set client config.

CREATE TABLE IF NOT EXISTS roe_override_requests (
    id                         BIGSERIAL PRIMARY KEY,
    tenant_id                   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id                   BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    desired_roe_mode            TEXT NOT NULL DEFAULT 'weaponized_god_mode',
    status                      TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected | expired | applied
    justification               TEXT NOT NULL DEFAULT '',
    requested_by_user_id        BIGINT,
    requested_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at                  TIMESTAMPTZ NOT NULL DEFAULT now() + interval '2 hours',
    first_approved_by_user_id   BIGINT,
    first_approved_at           TIMESTAMPTZ,
    second_approved_by_user_id  BIGINT,
    second_approved_at          TIMESTAMPTZ,
    rejected_by_user_id         BIGINT,
    rejected_at                 TIMESTAMPTZ,
    applied_by_user_id          BIGINT,
    applied_at                  TIMESTAMPTZ,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_roe_override_requests_status
    ON roe_override_requests (tenant_id, status, expires_at);

CREATE INDEX IF NOT EXISTS idx_roe_override_requests_client
    ON roe_override_requests (tenant_id, client_id, requested_at DESC);

ALTER TABLE roe_override_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY roe_override_requests_tenant_isolation
    ON roe_override_requests
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

