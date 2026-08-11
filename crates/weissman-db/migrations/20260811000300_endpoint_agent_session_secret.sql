-- Give each enrolled agent a long-lived credential so it can renew its short-lived session JWT.
--
-- Enrollment tokens are strictly single-use (20260611140000 sets consumed_at on redemption), but
-- `crates/weissman-agent/src/main.rs` called `enroll()` unconditionally on EVERY process start and
-- kept nothing on disk. So the agent could only ever run once: any restart — systemd, a reboot, a
-- crash, the `Restart=always` in the installer's unit file — re-enrolled with a consumed token,
-- got HTTP 401, and exited. Combined with the installer burning the token in its own pre-flight
-- check, no agent could ever come up at all. The live table confirms it: zero rows, ever.
--
-- The session JWT is separately short-lived (WEISSMAN_AGENT_JWT_TTL_MINS, default 240) and there
-- was no way to renew it, so even a hypothetically-surviving agent went dark after four hours.
--
-- The fix is the standard split: a long-lived credential that never crosses the wire after
-- enrollment except to mint a short-lived one. Stored as a SHA-256 hash — the plaintext is
-- returned exactly once, in the enrollment response, and only the agent keeps it.
--
-- Nullable on purpose: rows enrolled before this migration have no secret and simply cannot use
-- the renewal endpoint (there are none in this deployment, but a NOT NULL with a fabricated
-- default would mean minting a credential nobody holds).

ALTER TABLE endpoint_agents
    ADD COLUMN IF NOT EXISTS session_secret_hash text;

COMMENT ON COLUMN endpoint_agents.session_secret_hash IS
    'SHA-256 of the agent''s long-lived renewal credential. Plaintext is returned only in the '
    'enrollment response and never stored. Used by POST /api/agents/session to mint a fresh '
    'short-lived session JWT without consuming another enrollment token.';

-- Renewal looks the agent up by uuid and compares the hash; the uuid already has a unique index.
