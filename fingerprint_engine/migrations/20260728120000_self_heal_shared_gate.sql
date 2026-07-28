-- Durable cross-replica self-heal gate: fleet-wide coordination of the in-process
-- load-shed / backoff recovery gates (fingerprint_engine::self_heal_recovery). When any
-- replica engages a gate on a diagnosed fault, it publishes the gate's remaining TTL here;
-- every replica reads the fleet-max expiry each 10s health round and ORs it into its local
-- gate. So load-shed / backoff apply across the WHOLE fleet, not only on the one replica
-- that happened to diagnose the saturation — a load balancer otherwise spreads new intake
-- across N replicas and a single local gate only sheds ~1/N of it.
--
-- Platform-wide OPERATIONAL state (never tenant data): no tenant_id, no RLS. At most two rows
-- (one per gate); engagements upsert-EXTEND the expiry (GREATEST), so a shorter remaining from
-- one replica never shortens a gate another replica set. Readers filter on expires_at > now(),
-- so nothing accumulates and an expired gate simply reads "off". Fail-open by construction: if
-- this table is unreachable, publish/refresh are best-effort no-ops and each replica degrades
-- to local-only gating.

CREATE TABLE IF NOT EXISTS weissman_self_heal_gate (
    -- Logical gate name: 'load_shed' | 'backoff'.
    gate        TEXT        PRIMARY KEY,
    -- The gate is engaged fleet-wide while now() < expires_at. Anchored to the DB clock on every
    -- write (now() + remaining TTL), so cross-replica gating is robust to node/DB clock skew.
    expires_at  TIMESTAMPTZ NOT NULL,
    -- Replica id (WEISSMAN_REPLICA_ID / HOSTNAME) that last extended the gate — observability only.
    engaged_by  TEXT        NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_self_heal_gate TO weissman_app;

COMMENT ON TABLE weissman_self_heal_gate IS
    'Durable cross-replica self-heal gate (fleet-wide load-shed/backoff coordination). Platform-wide operational state, no RLS.';
