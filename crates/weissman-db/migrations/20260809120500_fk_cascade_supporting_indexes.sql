-- weissman:no-transaction
--
-- Supporting indexes for ON DELETE CASCADE foreign keys that currently have none.
--
-- DELETE /api/clients/:id (server_handlers_rest.inc: "DELETE FROM clients WHERE id=$1")
-- cascades into 21 tables via client_id and a tenant delete cascades into 6 via tenant_id.
-- None of these 27 FK columns is the leading column of any index, so each cascade forces a
-- sequential scan of the child table under an exclusive lock — turning a routine admin
-- delete into a multi-second-to-minute stall that blocks other tenants on the same tables.
-- The same indexes also speed the per-client / per-tenant list queries that filter on them.
--
-- Additive, online (CONCURRENTLY -> no table lock), idempotent (IF NOT EXISTS), zero code
-- change. Verified against the live schema: none of these 27 (table, column) pairs is
-- already covered by a leading-column index.

-- client_id ON DELETE CASCADE (21)
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_agent_anomalies_client_id                ON agent_anomalies (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_agent_metric_samples_client_id           ON agent_metric_samples (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_asm_graph_edges_client_id                ON asm_graph_edges (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_asm_graph_nodes_client_id                ON asm_graph_nodes (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_attack_chain_client_id                   ON attack_chain (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_attack_path_snapshots_client_id          ON attack_path_snapshots (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_auto_heal_job_specs_client_id            ON auto_heal_job_specs (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_chronos_events_client_id                 ON chronos_events (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_client_asset_value_rules_client_id       ON client_asset_value_rules (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_client_financial_risk_snapshots_client_id ON client_financial_risk_snapshots (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_cognitive_starvation_sessions_client_id  ON cognitive_starvation_sessions (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_deception_triggers_client_id             ON deception_triggers (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_endpoint_agent_enrollment_tokens_client_id ON endpoint_agent_enrollment_tokens (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_engagements_client_id                    ON engagements (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_evidence_items_client_id                 ON evidence_items (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_fuzz_candidate_staging_client_id         ON fuzz_candidate_staging (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_liquid_matrix_rotations_client_id        ON liquid_matrix_rotations (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_liquid_matrix_routing_tokens_client_id   ON liquid_matrix_routing_tokens (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_poe_jobs_client_id                       ON poe_jobs (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_roe_override_requests_client_id          ON roe_override_requests (client_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_weissman_finding_clusters_client_id      ON weissman_finding_clusters (client_id);

-- tenant_id ON DELETE CASCADE (6)
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_deception_assets_tenant_id               ON deception_assets (tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_deception_triggers_tenant_id             ON deception_triggers (tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_heal_requests_tenant_id                  ON heal_requests (tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_soar_revert_runbooks_tenant_id           ON soar_revert_runbooks (tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_soar_verification_tasks_tenant_id        ON soar_verification_tasks (tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_user_refresh_tokens_tenant_id            ON user_refresh_tokens (tenant_id);
