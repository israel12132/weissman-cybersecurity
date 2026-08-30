-- Supreme Brain Part 6: attack-path inference, FAIR blast-radius, RAG council memory.
-- All statements are idempotent (IF NOT EXISTS / ADD COLUMN IF NOT EXISTS).

-- ── Graph nodes: agent / honey / region / last_seen / criticality ──────────
ALTER TABLE risk_graph_nodes
    ADD COLUMN IF NOT EXISTS agent_present          BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS honey_node             BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS region                 TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_seen              TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS criticality_override   REAL,
    ADD COLUMN IF NOT EXISTS mitre_technique_id     TEXT    NOT NULL DEFAULT '';

UPDATE risk_graph_nodes SET last_seen = created_at WHERE last_seen IS NULL;
ALTER TABLE risk_graph_nodes ALTER COLUMN last_seen SET DEFAULT now();

-- Partial index: internet-exposed entry points (shortest-path seeds).
CREATE INDEX IF NOT EXISTS ix_risk_nodes_internet_exposed
    ON risk_graph_nodes (tenant_id, client_id, id)
    WHERE internet_exposed = TRUE;

CREATE INDEX IF NOT EXISTS ix_risk_nodes_tenant_target
    ON risk_graph_nodes (tenant_id, client_id);

CREATE INDEX IF NOT EXISTS ix_risk_nodes_tenant_created
    ON risk_graph_nodes (tenant_id, created_at DESC);

-- Non-negative asset values.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_risk_nodes_business_value_nonneg'
    ) THEN
        ALTER TABLE risk_graph_nodes
            ADD CONSTRAINT chk_risk_nodes_business_value_nonneg
            CHECK (business_value_usd IS NULL OR business_value_usd >= 0);
    END IF;
EXCEPTION WHEN undefined_column THEN
    NULL;
END $$;

-- ── Graph edges: last_seen + MITRE + prune support ─────────────────────────
ALTER TABLE risk_graph_edges
    ADD COLUMN IF NOT EXISTS last_seen           TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS mitre_technique_id  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS engine_id           TEXT NOT NULL DEFAULT '';

UPDATE risk_graph_edges SET last_seen = created_at WHERE last_seen IS NULL;
ALTER TABLE risk_graph_edges ALTER COLUMN last_seen SET DEFAULT now();

CREATE INDEX IF NOT EXISTS ix_risk_edges_tenant_created
    ON risk_graph_edges (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_risk_edges_tenant_from_to
    ON risk_graph_edges (tenant_id, client_id, from_node_id, to_node_id);

-- ── Attack-path snapshots: dollar value of the path ────────────────────────
ALTER TABLE attack_path_snapshots
    ADD COLUMN IF NOT EXISTS total_path_ale_usd  BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_path_score      REAL   NOT NULL DEFAULT 0;

-- ── FAIR snapshots: concentration / delay / agent discount ─────────────────
ALTER TABLE client_financial_risk_snapshots
    ADD COLUMN IF NOT EXISTS concentration_pct         REAL   NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS delay_cost_usd_per_day    BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS agent_protected_ale_usd   BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS path_ale_usd              BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS currency                  TEXT   NOT NULL DEFAULT 'USD';

-- ── RAG council memory: provenance + checksum (HNSW rebuilt CONCURRENTLY) ──
ALTER TABLE supreme_council_memory
    ADD COLUMN IF NOT EXISTS embedding_checksum  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS reinforcement       REAL NOT NULL DEFAULT 1.0,
    ADD COLUMN IF NOT EXISTS last_retrieved_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS mitre_technique_id  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provenance_hmac     TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provenance_kind     TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provenance_issuer   TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS ix_supreme_council_mem_success_partial
    ON supreme_council_memory (tenant_id, created_at DESC)
    WHERE source IN ('oast_success', 'replay_hit', 'verified_win');

CREATE INDEX IF NOT EXISTS ix_supreme_council_mem_gin_meta
    ON supreme_council_memory USING GIN (orchestrator_instruction);

-- ── Pentest winning paths: decay + checksum + HMAC provenance ──────────────
ALTER TABLE pentest_winning_paths
    ADD COLUMN IF NOT EXISTS decay_weight        REAL NOT NULL DEFAULT 1.0,
    ADD COLUMN IF NOT EXISTS embedding_checksum  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_retrieved_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS mitre_technique_id  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provenance_hmac     TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provenance_kind     TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provenance_issuer   TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS ix_pwp_success_partial
    ON pentest_winning_paths (tenant_id, engine, last_won_at DESC)
    WHERE won_count > 0;
