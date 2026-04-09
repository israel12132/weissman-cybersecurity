-- Default tenant for bootstrap (admin user created at runtime from WEISSMAN_ADMIN_* env)

INSERT INTO tenants (slug, name)
SELECT 'default', 'Default Organization'
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE slug = 'default');

-- Default system_configs rows for tenant 1 (id resolved at insert time)
INSERT INTO system_configs (tenant_id, key, value, description)
SELECT t.id, v.key, v.value, v.description
FROM tenants t
CROSS JOIN (VALUES
    ('scan_interval_secs', '60', 'Orchestrator loop interval in seconds when scanning is active'),
    ('active_engines', '["osint","asm","supply_chain","bola_idor","ollama_fuzz","semantic_ai_fuzz","microsecond_timing","ai_adversarial_redteam"]', 'JSON array of engine IDs'),
    ('asm_ports', '[80,443,8080,8443,22,21,25,3306,5432,27017,6379,9200,3000,5000,8000,8888,9443,111,135,139,445,1433,3389,9000]', 'TCP ports for ASM'),
    ('asm_port_timeout_ms', '500', 'TCP connect timeout per port (ms)'),
    ('osint_timeout_secs', '10', 'HTTP timeout for OSINT'),
    ('supply_chain_timeout_secs', '8', 'HTTP timeout for supply chain'),
    ('bola_idor_timeout_secs', '6', 'HTTP timeout for BOLA'),
    ('ollama_fuzz_timeout_secs', '6', 'HTTP timeout for Ollama fuzz'),
    ('recon_subdomain_prefixes', '["www","mail","ftp","admin","api","dev","staging"]', 'Subdomain prefixes'),
    ('enable_rfc3161_signing', 'true', 'RFC 3161 PDF signing'),
    ('x509_cert_path', '', 'X.509 path'),
    ('proxy_swarm', '', 'Proxy URLs'),
    ('jitter_min_ms', '0', 'Jitter min'),
    ('jitter_max_ms', '800', 'Jitter max'),
    ('enable_identity_morphing', 'true', 'Identity morphing'),
    ('ollama_base_url', 'http://127.0.0.1:11434', 'Ollama URL'),
    ('ollama_temperature', '0.7', 'Ollama temperature'),
    ('max_sequence_depth', '8', 'Semantic max depth'),
    ('timing_sample_size', '100', 'Timing samples'),
    ('z_score_sensitivity', '3.0', 'Z-score'),
    ('ai_redteam_endpoint', '', 'AI red team endpoint'),
    ('adversarial_strategy', 'data_leak', 'Strategy'),
    ('enable_zero_day_probing', 'true', 'Zero-day radar'),
    ('custom_feed_urls', '[]', 'Custom feeds'),
    ('github_token', '', 'GitHub token'),
    ('gitlab_api_url', '', 'GitLab API'),
    ('enable_poe_synthesis', 'true', 'PoE synthesis'),
    ('poe_safety_rails_no_shells', 'true', 'No shells'),
    ('poe_max_poc_length', '104857600', 'Max PoC length'),
    ('poe_use_raw_tcp', 'true', 'Raw TCP'),
    ('poe_entropy_leak_threshold', '7.0', 'Entropy threshold'),
    ('poe_gadget_chains', '{}', 'Gadget chains'),
    ('payload_sync_last_at', '', 'Last payload sync'),
    ('payload_sync_active', 'true', 'Payload sync active'),
    ('global_safe_mode', 'false', 'Safe mode'),
    ('alert_webhook_url', '', 'Webhook URL'),
    ('backup_interval_secs', '86400', 'Backup interval')
) AS v(key, value, description)
WHERE t.slug = 'default'
ON CONFLICT (tenant_id, key) DO NOTHING;
