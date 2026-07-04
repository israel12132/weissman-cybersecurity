"""
SOC Command Center: Advanced Cyber Engines.
All engines are live-only; no mock data. Empty results = verified 0 findings.
"""
from src.engines.supply_chain_engine import run_supply_chain_audit
from src.engines.ollama_fuzz_engine import run_ollama_fuzz
from src.engines.bola_idor_engine import run_bola_idor
from src.engines.osint_engine import run_osint_crawl
from src.engines.asm_engine import run_attack_surface_scan
from src.engines import remediation_engine

# Group 1: Web / API
from src.engines.graphql_attack_engine import run_graphql_attack
from src.engines.jwt_attack_engine import run_jwt_attack
from src.engines.oauth_oidc_engine import run_oauth_oidc
from src.engines.http_smuggling_engine import run_http_smuggling
from src.engines.prototype_pollution_engine import run_prototype_pollution
from src.engines.ssrf_advanced_engine import run_ssrf_advanced
from src.engines.xxe_engine import run_xxe
from src.engines.ssti_engine import run_ssti
from src.engines.file_upload_engine import run_file_upload
from src.engines.websocket_attack_engine import run_websocket_attack
from src.engines.cache_poisoning_engine import run_cache_poisoning

# Group 2: AI / LLM
from src.engines.llm_redteam_engine import run_llm_redteam
from src.engines.adversarial_ml_engine import run_adversarial_ml
from src.engines.autonomous_pentest_engine import run_autonomous_pentest

# Group 3: Cloud / Infrastructure
from src.engines.aws_attack_engine import run_aws_attack
from src.engines.azure_attack_engine import run_azure_attack
from src.engines.gcp_attack_engine import run_gcp_attack
from src.engines.k8s_container_engine import run_k8s_container
from src.engines.iac_misconfig_engine import run_iac_misconfig
from src.engines.serverless_attack_engine import run_serverless_attack

# Group 4: OT / ICS / IoT
from src.engines.scada_ics_engine import run_scada_ics
from src.engines.iot_firmware_engine import run_iot_firmware
from src.engines.ble_rf_engine import run_ble_rf

# Group 5: Stealth / Evasion
from src.engines.edr_evasion_engine import run_edr_evasion
from src.engines.waf_bypass_engine import run_waf_bypass
from src.engines.timing_sidechannel_engine import run_timing_sidechannel
from src.engines.antiforensics_engine import run_antiforensics

# Group 6: Crypto / Identity
from src.engines.pki_tls_engine import run_pki_tls
from src.engines.pqc_scanner_engine import run_pqc_scanner
from src.engines.password_spray_engine import run_password_spray
from src.engines.kerberoasting_engine import run_kerberoasting
from src.engines.saml_attack_engine import run_saml_attack

# Group 7: Network / Protocol
from src.engines.bgp_dns_hijacking_engine import run_bgp_dns_hijacking
from src.engines.ipv6_attack_engine import run_ipv6_attack
from src.engines.mtls_grpc_engine import run_mtls_grpc
from src.engines.smb_netbios_engine import run_smb_netbios

# Group 8: Supply Chain Advanced
from src.engines.cicd_pipeline_engine import run_cicd_pipeline
from src.engines.container_registry_engine import run_container_registry
from src.engines.sbom_analyzer_engine import run_sbom_analyzer
from src.engines.typosquatting_monitor_engine import run_typosquatting_monitor

# Group 9: Top-Tier / State-of-the-Art
from src.engines.kill_chain_engine import run_kill_chain
from src.engines.oast_oob_engine import run_oast_oob
from src.engines.deception_honeypot_engine import run_deception_honeypot
from src.engines.digital_twin_engine import run_digital_twin
from src.engines.zero_day_prediction_engine import run_zero_day_prediction
from src.engines.threat_emulation_engine import run_threat_emulation

__all__ = [
    # Legacy / core
    "run_supply_chain_audit",
    "run_ollama_fuzz",
    "run_bola_idor",
    "run_osint_crawl",
    "run_attack_surface_scan",
    "remediation_engine",
    # Group 1
    "run_graphql_attack",
    "run_jwt_attack",
    "run_oauth_oidc",
    "run_http_smuggling",
    "run_prototype_pollution",
    "run_ssrf_advanced",
    "run_xxe",
    "run_ssti",
    "run_file_upload",
    "run_websocket_attack",
    "run_cache_poisoning",
    # Group 2
    "run_llm_redteam",
    "run_adversarial_ml",
    "run_autonomous_pentest",
    # Group 3
    "run_aws_attack",
    "run_azure_attack",
    "run_gcp_attack",
    "run_k8s_container",
    "run_iac_misconfig",
    "run_serverless_attack",
    # Group 4
    "run_scada_ics",
    "run_iot_firmware",
    "run_ble_rf",
    # Group 5
    "run_edr_evasion",
    "run_waf_bypass",
    "run_timing_sidechannel",
    "run_antiforensics",
    # Group 6
    "run_pki_tls",
    "run_pqc_scanner",
    "run_password_spray",
    "run_kerberoasting",
    "run_saml_attack",
    # Group 7
    "run_bgp_dns_hijacking",
    "run_ipv6_attack",
    "run_mtls_grpc",
    "run_smb_netbios",
    # Group 8
    "run_cicd_pipeline",
    "run_container_registry",
    "run_sbom_analyzer",
    "run_typosquatting_monitor",
    # Group 9
    "run_kill_chain",
    "run_oast_oob",
    "run_deception_honeypot",
    "run_digital_twin",
    "run_zero_day_prediction",
    "run_threat_emulation",
]

ENGINE_IDS = [
    "supply_chain", "ollama_fuzz", "bola_idor", "osint", "asm",
    "graphql_attack", "jwt_attack", "oauth_oidc", "http_smuggling",
    "prototype_pollution", "ssrf_advanced", "xxe", "ssti", "file_upload",
    "websocket_attack", "cache_poisoning",
    "llm_redteam", "adversarial_ml", "autonomous_pentest",
    "aws_attack", "azure_attack", "gcp_attack", "k8s_container",
    "iac_misconfig", "serverless_attack",
    "scada_ics", "iot_firmware", "ble_rf",
    "edr_evasion", "waf_bypass", "timing_sidechannel", "antiforensics",
    "pki_tls", "pqc_scanner", "password_spray", "kerberoasting", "saml_attack",
    "bgp_dns_hijacking", "ipv6_attack", "mtls_grpc", "smb_netbios",
    "cicd_pipeline", "container_registry", "sbom_analyzer", "typosquatting_monitor",
    "kill_chain", "oast_oob", "deception_honeypot", "digital_twin",
    "zero_day_prediction", "threat_emulation",
]
