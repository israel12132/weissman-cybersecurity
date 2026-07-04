-- Military-grade job orchestration: append-only event log + forensic DLQ.
-- CQRS read model remains `weissman_async_jobs`; all transitions are projected from events.

CREATE TABLE IF NOT EXISTS weissman_job_events (
    seq         bigserial PRIMARY KEY,
    job_id      uuid NOT NULL,
    tenant_id   bigint NOT NULL REFERENCES tenants (id),
    kind        text NOT NULL,
    payload     jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    event_hash  text NOT NULL,
    prev_hash   text,
    CONSTRAINT weissman_job_events_kind_chk CHECK (
        kind IN (
            'job_dispatched',
            'worker_claimed',
            'lease_acquired',
            'lease_extended',
            'exploit_fired',
            'job_completed',
            'job_failed',
            'job_retry_scheduled',
            'worker_terminated',
            'job_orphaned',
            'forensic_dlq_enqueued'
        )
    )
);

CREATE INDEX IF NOT EXISTS ix_weissman_job_events_job_seq
    ON weissman_job_events (job_id, seq);

CREATE INDEX IF NOT EXISTS ix_weissman_job_events_occurred
    ON weissman_job_events (occurred_at DESC);

COMMENT ON TABLE weissman_job_events IS
    'Append-only immutable job event log (event sourcing). Never UPDATE/DELETE — forensic replay only.';

CREATE TABLE IF NOT EXISTS weissman_job_forensic_dlq (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id            uuid NOT NULL,
    tenant_id         bigint NOT NULL REFERENCES tenants (id),
    worker_id         text NOT NULL,
    failure_class     text NOT NULL,
    stack_trace       text NOT NULL,
    input_params      jsonb NOT NULL DEFAULT '{}'::jsonb,
    memory_snapshot   jsonb NOT NULL DEFAULT '{}'::jsonb,
    event_chain_hash  text NOT NULL,
    bundle_seal       text NOT NULL,
    signed_envelope   jsonb,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_weissman_job_forensic_dlq_job
    ON weissman_job_forensic_dlq (job_id, created_at DESC);

COMMENT ON TABLE weissman_job_forensic_dlq IS
    'Cryptographically sealed forensic DLQ bundles — regression generation / incident response.';

GRANT SELECT, INSERT ON weissman_job_events TO weissman_app;
GRANT SELECT, INSERT ON weissman_job_forensic_dlq TO weissman_app;
GRANT SELECT, INSERT ON weissman_job_events TO weissman_auth;
GRANT SELECT, INSERT ON weissman_job_forensic_dlq TO weissman_auth;

GRANT USAGE, SELECT ON SEQUENCE weissman_job_events_seq_seq TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE weissman_job_events_seq_seq TO weissman_auth;
