-- Global pipeline scope uses literal '__global__' (dag_pipeline::GLOBAL_SCOPE_ID), not a clients.id FK.
ALTER TABLE pipeline_run_state DROP CONSTRAINT IF EXISTS pipeline_run_state_client_id_fkey;
ALTER TABLE pipeline_run_state
    ALTER COLUMN client_id TYPE TEXT USING client_id::text;
