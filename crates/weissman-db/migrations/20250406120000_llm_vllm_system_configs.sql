-- OpenAI-compatible (vLLM) settings; seed from legacy ollama_* keys where present.

INSERT INTO system_configs (tenant_id, key, value, description)
SELECT sc.tenant_id,
       'llm_base_url',
       CASE
           WHEN trim(sc.value) = '' THEN 'http://127.0.0.1:8000/v1'
           WHEN sc.value LIKE '%11434%' THEN 'http://127.0.0.1:8000/v1'
           ELSE trim(sc.value)
       END,
       'OpenAI-compatible API base URL (vLLM); should end with /v1'
FROM system_configs sc
WHERE sc.key = 'ollama_base_url'
  AND NOT EXISTS (
        SELECT 1
        FROM system_configs x
        WHERE x.tenant_id = sc.tenant_id
          AND x.key = 'llm_base_url'
    );

INSERT INTO system_configs (tenant_id, key, value, description)
SELECT sc.tenant_id,
       'llm_temperature',
       sc.value,
       'Sampling temperature for chat completions'
FROM system_configs sc
WHERE sc.key = 'ollama_temperature'
  AND NOT EXISTS (
        SELECT 1
        FROM system_configs x
        WHERE x.tenant_id = sc.tenant_id
          AND x.key = 'llm_temperature'
    );

INSERT INTO system_configs (tenant_id, key, value, description)
SELECT t.id,
       'llm_base_url',
       'http://127.0.0.1:8000/v1',
       'OpenAI-compatible API base URL (vLLM); should end with /v1'
FROM tenants t
WHERE NOT EXISTS (
      SELECT 1 FROM system_configs x WHERE x.tenant_id = t.id AND x.key = 'llm_base_url'
  );

INSERT INTO system_configs (tenant_id, key, value, description)
SELECT t.id,
       'llm_temperature',
       '0.7',
       'Sampling temperature for chat completions'
FROM tenants t
WHERE NOT EXISTS (
      SELECT 1 FROM system_configs x WHERE x.tenant_id = t.id AND x.key = 'llm_temperature'
  );

INSERT INTO system_configs (tenant_id, key, value, description)
SELECT t.id,
       'llm_model',
       '',
       'vLLM model id (e.g. meta-llama/Llama-3.2-3B-Instruct); empty uses WEISSMAN_LLM_MODEL or default'
FROM tenants t
WHERE NOT EXISTS (
      SELECT 1 FROM system_configs x WHERE x.tenant_id = t.id AND x.key = 'llm_model'
  );

UPDATE compliance_mappings
SET vuln_source_contains = 'llm_path_fuzz'
WHERE vuln_source_contains = 'ollama_fuzz';
