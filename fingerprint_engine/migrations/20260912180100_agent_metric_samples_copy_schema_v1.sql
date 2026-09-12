-- Documents the binary COPY contract for public.agent_metric_samples.
-- The Rust encoder (weissman_db::pg_binary_copy) asserts schema version 1
-- against pg_attribute before streaming COPY. Adding a trailing DEFAULT
-- column is safe (named COPY). Reordering, renaming, dropping, or changing
-- the type of a v1 column requires bumping AGENT_METRIC_SAMPLES_SCHEMA_VERSION
-- and updating AGENT_METRIC_SAMPLES_COPY_COLUMNS in lockstep.

COMMENT ON TABLE public.agent_metric_samples IS
  'weissman:copy-schema-version=1 columns=id,tenant_id,agent_id,client_id,sampled_at,hour_of_week,metrics,raw_size_bytes';
