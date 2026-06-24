import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import { ENGINES_BY_ID, ENGINE_GROUPS } from '../lib/enginesRegistry'
import { apiFetch, resolveEventSourceUrl } from '../lib/apiBase'
import { downloadBytes } from '../lib/pdfExport'
import { useProductionEngines } from '../lib/useProductionEngines'
import { isTopTierEngine } from '../lib/topTierEngineProfiles'
import { strategicEnginesNeedingDedicatedPage } from '../lib/strategicEngineProgram'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { exportStandardFindingsCsv } from '../lib/exportFindingsCsv'

const MAX_LINES_REAL = 1000
const DEDICATED_ENGINE_IDS = new Set(strategicEnginesNeedingDedicatedPage().map((e) => e.id))

// ─── Engine type classification ────────────────────────────────────────────────

const ENGINE_TYPE_MAP = {
  live_probe: new Set([
    'osint','asm','recon','leak_hunter','discovery_engine',
    'bola_idor','graphql_attack','jwt_attack','oauth_oidc','http_smuggling',
    'prototype_pollution','ssrf_advanced','xxe','ssti','file_upload',
    'websocket_attack','cache_poisoning','http_feedback_fuzz',
    'aws_attack','cloud_posture','azure_attack','gcp_attack','k8s_container','iac_misconfig',
    'serverless_attack','scada_ics','iot_firmware','ble_rf',
    'edr_evasion','waf_bypass','timing_sidechannel','antiforensics','stealth_engine',
    'pki_tls','pqc_scanner','password_spray','kerberoasting','saml_attack','crypto_engine','email_dns_posture',
    'bgp_dns_hijacking','ipv6_attack','mtls_grpc','smb_netbios',
    'cicd_pipeline','container_registry','sbom_analyzer','typosquatting_monitor',
    'kill_chain','oast_oob','deception_honeypot','digital_twin','zero_day_prediction',
    'threat_emulation','microsecond_timing','semantic_ai_fuzz','ai_adversarial_redteam',
    'llm_redteam','adversarial_ml','autonomous_pentest','nexus_sovereign_swarm','llm_path_fuzz','supply_chain',
    'cors_misconfiguration','swagger_abuse','soap_injection','odata_injection',
    'css_injection','template_injection_adv','http_parameter_pollution','api_mass_assignment',
    'clickjacking_engine','subdomain_takeover','file_inclusion_rfi','deserialization_net',
    'api_rate_limit_bypass','graphql_subscription_attack','webrtc_attack',
    'browser_extension_attack','web3_dapp_attack','api_gateway_bypass',
    'arp_spoofing_engine','vlan_hopping_attack','dhcp_attack_engine','dns_cache_poisoning',
    'ntp_amplification','snmp_exploitation','rdp_attack_engine','ldap_injection_engine',
    'voip_sip_attack','wifi_attack_engine','bluetooth_attack_engine',
    'ospf_bgp_hijack','mpls_vpn_attack','lte_5g_attack','network_covert_channel',
    'wpa3_attack_engine','tor_exit_attack','protocol_downgrade','network_baseline_anomaly',
    'packet_injection_engine','network_tap_advanced','multicast_attack','nat_traversal_attack',
    'dnp3_attack','bacnet_attack','zigbee_attack','iec61850_attack','satellite_comm_attack','rfid_nfc_attack',
    'threat_intel_fusion','attack_surface_quantify','passive_dns_forensics','dark_web_monitor',
    'lambda_escape','terraform_state_attack','cloudformation_injection','service_mesh_attack',
    'cloud_audit_evasion','ecr_registry_attack','multi_cloud_pivot','cloud_worm_propagation',
    'serverless_injection','cloud_data_exfil','cloud_network_attack','cloud_privilege_persistence',
    'padding_oracle_attack','hash_extension_attack','ecdsa_nonce_bias','rsa_timing_attack',
    'mfa_bypass_engine','credential_stuffing','kerberos_attack_suite','zero_trust_bypass',
    'pki_hierarchy_attack','session_fixation_adv','password_hash_crack','quantum_key_attack',
    'password_spray_advanced',
    'android_malware_engine','ios_exploit_engine','mobile_mitm','ssl_pinning_bypass',
    'android_intent_attack','ios_url_scheme_attack','mobile_overlay_attack','sim_swap_engine',
    'mobile_banking_trojan','app_store_attack','mdm_bypass_engine','bluetooth_mobile_attack',
    'nfc_relay_attack','mobile_spyware_engine','react_native_attack',
    'github_actions_attack','compiler_backdoor','open_source_backdoor','cdn_poisoning_engine',
    'software_signing_attack','build_system_compromise','dependency_confusion','update_hijacking',
    'sbom_forgery_engine','third_party_api_attack','iac_supply_chain',
  ]),
  ttp_emulation: new Set([
    'apt28_techniques','apt29_techniques','apt41_techniques','lazarus_group_ttps',
    'volt_typhoon_ttps','scattered_spider_ttps','salt_typhoon_ttps','fin7_techniques',
    'conti_ransomware_ttps','lockbit_techniques','cl0p_techniques','blackcat_alphv_ttps',
    'midnight_blizzard_ttps','earth_longzhi_ttps','equation_group_ttps','sandworm_techniques',
    'carbon_spider_ttps','wizard_spider_ttps','unc2452_ttps','unc3944_ttps','quantum_sovereign_nexus',
  ]),
  malware_emulation: new Set([
    'bootkit_uefi','fileless_malware_engine','polymorphic_engine','botnet_c2_engine',
    'keylogger_engine','spyware_stalkerware','worm_propagation','rce_exploit_engine',
    'persistence_mechanism','lateral_movement_engine','data_staging_engine',
    'exploit_kit_engine','trojan_dropper','macro_malware',
    'process_hollowing','living_off_land','heap_exploitation',
  ]),
  social_sim: new Set([
    'spear_phishing_engine','vishing_engine','smishing_engine','qr_phishing',
    'deepfake_voice_engine','business_email_compromise','watering_hole_attack',
    'pretexting_engine','insider_threat_engine','brand_impersonation','fake_update_engine',
    'linkedin_phishing','callback_phishing','physical_social_eng','typosquatting_phishing',
    'adversarial_simulation',
  ]),
  ai_probe: new Set([
    'llm_jailbreak','prompt_injection_chain','model_inversion_attack','ai_supply_chain_attack',
    'llm_agent_hijack','rag_poisoning_engine','adversarial_examples','data_poisoning_engine',
    'deepfake_synthesis','llm_dos_attack','multimodal_ai_attack','ai_bias_exploit',
    'gpt_plugin_attack','autonomous_ai_escape','llm_memory_extraction','neural_backdoor_detect',
    'ai_watermark_bypass',    'federated_learning_attack','llm_red_team_advanced','model_stealing_engine',
    'nexus_sovereign_swarm',
  ]),
  data_exfil: new Set([
    'dns_exfil_engine','http_covert_exfil','cloud_exfil_engine','encrypted_exfil',
    'acoustic_exfil','em_exfil_engine','optical_exfil','cache_timing_exfil',
    'keyboard_acoustic','screen_capture_exfil','clipboard_hijack','database_exfil',
    'email_exfil','insider_exfil','storage_covert_channel',
  ]),
}

function getEngineType(id) {
  for (const [type, set] of Object.entries(ENGINE_TYPE_MAP)) {
    if (set.has(id)) return type
  }
  return 'live_probe'
}

const ENGINE_TYPE_META = {
  live_probe:       { label: 'Live Probe',          color: '#22d3ee', bg: 'bg-cyan-500/10',   border: 'border-cyan-500/30',   icon: '⚡' },
  ttp_emulation:    { label: 'TTP Emulation',        color: '#ef4444', bg: 'bg-red-500/10',    border: 'border-red-500/30',    icon: '🎯' },
  malware_emulation:{ label: 'Behavioral Emulation', color: '#dc2626', bg: 'bg-red-900/20',    border: 'border-red-700/30',    icon: '🦠' },
  social_sim:       { label: 'Social Simulation',    color: '#d97706', bg: 'bg-amber-500/10',  border: 'border-amber-500/30',  icon: '🎭' },
  ai_probe:         { label: 'AI/LLM Probe',         color: '#ec4899', bg: 'bg-pink-500/10',   border: 'border-pink-500/30',   icon: '🤖' },
  data_exfil:       { label: 'Exfil Technique',      color: '#0891b2', bg: 'bg-cyan-900/20',   border: 'border-cyan-700/30',   icon: '💾' },
}

// ─── Per-engine parameter definitions ──────────────────────────────────────────

const PARAM_DEFS = {
  osint:           [{ key:'depth',        label:'Recon Depth',                     type:'select',   options:['1','2','3','4','5'], defaultVal:'3' },
                   { key:'github_token', label:'GitHub Token (optional)',          type:'password', placeholder:'ghp_...', defaultVal:'' }],
  asm:             [{ key:'ports',            label:'Ports',                       type:'text',     placeholder:'top | all | 80,443,8080-8090', defaultVal:'top' },
                   { key:'subdomain_sources', label:'Subdomain Sources',           type:'select',   options:['both','passive','bruteforce'], defaultVal:'both' },
                   { key:'max_subdomains',    label:'Max Subdomains',              type:'number',   placeholder:'50', defaultVal:'50', min:0, max:500 },
                   { key:'port_scan',         label:'Service/Port Exposure',       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'banner_grab',       label:'TCP Service Banners',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'subdomain_enum',    label:'Subdomain Discovery',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'dns_intel',         label:'DNS & Email Posture',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'dkim_probe',        label:'DKIM Selector Discovery',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'dns_hardening',     label:'DNS Hardening (Wildcard/CAA)',type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'rdap_intel',        label:'RDAP Registration Intel',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'ip_asn_enrichment', label:'IP → ASN Enrichment',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'http_posture',      label:'HTTP Security Posture',       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'cors_probe',        label:'CORS Misconfiguration',       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'sensitive_path_probe', label:'Sensitive Path Exposure',  type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'robots_harvest',    label:'robots.txt Intelligence',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'cleartext_http_probe', label:'Cleartext HTTP Probe',    type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'wellknown_probe',   label:'Well-Known URI Probe',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'tls_posture',       label:'TLS / Certificate Posture',   type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'cloud_hunter',      label:'Takeover + Storage Hunt',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'shadow_it_scan',    label:'Shadow IT Detection',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'tech_fingerprint',  label:'Technology Fingerprint',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'attack_path_correlation', label:'Attack Path Correlation', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'severity_threshold',label:'Severity Threshold',          type:'select',   options:['info','low','medium','high','critical'], defaultVal:'info' },
                   { key:'port_timeout_ms',   label:'Port Timeout (ms)',           type:'number',   placeholder:'500', defaultVal:'500', min:100, max:5000 },
                   { key:'http_timeout_ms',   label:'HTTP Timeout (ms)',           type:'number',   placeholder:'6000', defaultVal:'6000', min:1000, max:30000 },
                   { key:'max_findings',      label:'Max Findings',                type:'number',   placeholder:'800', defaultVal:'800', min:1, max:5000 },
                   { key:'subdomain_wordlist',label:'Custom Subdomain Wordlist',   type:'textarea', placeholder:'api, admin, staging, vpn', defaultVal:'' }],
  recon:           [{ key:'depth',        label:'Recon Depth',                     type:'select',   options:['1','2','3','4','5'], defaultVal:'3' }],
  leak_hunter:     [{ key:'github_token', label:'GitHub Token (optional)',         type:'password', placeholder:'ghp_...', defaultVal:'' }],
  discovery_engine:[{ key:'depth',        label:'Spider Depth',                    type:'select',   options:['1','2','3','4','5'], defaultVal:'3' },
                   { key:'ports',        label:'Port Hints',                       type:'text',     placeholder:'80,443,8080', defaultVal:'80,443' }],
  bola_idor:       [{ key:'auth_header',  label:'Auth Header',                     type:'text',     placeholder:'Bearer eyJ...', defaultVal:'' },
                   { key:'paths',        label:'Custom Paths (one per line)',       type:'textarea', placeholder:'/api/v1/users/1', defaultVal:'' }],
  graphql_attack:  [{ key:'introspection',label:'Force Introspection',             type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'depth_limit', label:'Query Depth',                       type:'number',   placeholder:'10', defaultVal:'10', min:1, max:50 }],
  jwt_attack:      [{ key:'wordlist',     label:'Wordlist Size',                   type:'select',   options:['small','medium','large'], defaultVal:'medium' },
                   { key:'alg_none',    label:'Test alg:none',                     type:'select',   options:['true','false'], defaultVal:'true' }],
  oauth_oidc:      [{ key:'issuer',             label:'Issuer / Provider URL (optional)',           type:'text',   placeholder:'https://idp.example.com', defaultVal:'' },
                   { key:'discovery_url',       label:'Discovery Document URL (optional)',          type:'text',   placeholder:'https://idp/.well-known/openid-configuration', defaultVal:'' },
                   { key:'client_id',           label:'OAuth Client ID (improves probe fidelity)',  type:'text',   placeholder:'client_id_here', defaultVal:'' },
                   { key:'probe_redirect_uri',  label:'Probe redirect_uri (open-redirect test)',    type:'text',   placeholder:'https://oauth-validate.weissman.invalid/callback', defaultVal:'' },
                   { key:'probe_scope',         label:'Probe Scope',                                type:'text',   placeholder:'openid', defaultVal:'openid' },
                   { key:'intensity',           label:'Probe Intensity',                            type:'select', options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'probe_authorization', label:'Probe Authorization Endpoint',               type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_implicit',      label:'Probe Implicit Flow (response_type=token)',  type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_token_endpoint', label:'Probe Token Endpoint + PAR',              type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_jwks',          label:'Analyze JWKS Signing Keys',                  type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'attack_paths',        label:'Synthesize Attack Paths',                    type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_extensions',    label:'OIDC Extension Probes (device-code, ROPC)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_cors',          label:'CORS on Metadata/JWKS',                    type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_federation',    label:'SAML Federation Metadata Bridge',          type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_subdomains',    label:'Identity Subdomain Takeover Probe',        type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_control_matrix', label:'RFC 9700 Control Matrix',                 type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_remediation_playbook', label:'Remediation Playbook',              type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'emit_agent_guidance', label:'Emit Agent-Required Guidance',           type:'select', options:['true','false'], defaultVal:'true' }],
  http_smuggling:  [{ key:'intensity',           label:'Scan Intensity',                             type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'paths',               label:'Paths to Test (comma-sep)',                   type:'text',     placeholder:'/, /api, /login, /admin', defaultVal:'/, /api, /login, /admin' },
                   { key:'canary_prefix',       label:'Smuggle Canary Prefix',                       type:'text',     placeholder:'WZSM', defaultVal:'WZSM' },
                   { key:'check_cl_te',         label:'CL.TE Confusion Probe',                       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_te_cl',         label:'TE.CL Confusion Probe',                       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_zero_cl',       label:'0.CL Desync Probe',                           type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_te_te',         label:'TE.TE Dual Headers',                          type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_te_obfuscation',label:'TE Obfuscation Oracle',                       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_cl_anomalies',  label:'Content-Length Anomalies',                    type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_pipeline',      label:'HTTP/1.1 Pipeline Test',                      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_dual_response', label:'Dual-Response Oracle',                        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_response_queue', label:'Response-Queue Self-Oracle',               type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_cl_cl',         label:'CL.CL Duplicate Content-Length',            type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_backend_fingerprint', label:'Front/Back-End Fingerprint Split',  type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_timing_oracle', label:'Timing Desync Oracle (Aggressive)',           type:'select',   options:['true','false'], defaultVal:'false' },
                   { key:'check_h2c_upgrade',   label:'h2c Cleartext Upgrade Probe',                 type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_chunk_extensions', label:'Chunk Extension Ambiguity',                type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_client_desync', label:'Client-Side Desync (Fat GET / HTTP/1.0)',       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_h2_downgrade',  label:'HTTP/1.1 ↔ HTTP/2 Schism',                    type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_fingerprint',   label:'Front-End Fingerprint',                       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_attack_paths',  label:'Attack-Path Synthesis',                       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_posture_score', label:'Posture Scoring',                             type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'include_info_findings', label:'Include Informational Findings',            type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'timeout_ms',          label:'Per-Probe Timeout (ms)',                      type:'number',   placeholder:'8000', defaultVal:'8000', min:500, max:30000 },
                   { key:'concurrency',         label:'Concurrency',                                 type:'number',   placeholder:'16', defaultVal:'16', min:1, max:32 }],
  ssrf_advanced:   [{ key:'intensity',     label:'Scan Intensity',                  type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'check_metadata', label:'Cloud Metadata (IMDS) Probes',    type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'cloud_providers',label:'Cloud Providers (blank = auto)',   type:'text',     placeholder:'aws,gcp,azure,alibaba,digitalocean,oracle', defaultVal:'' },
                   { key:'check_internal', label:'Internal / Localhost SSRF',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_bypass',   label:'Blocklist-Bypass Encodings',       type:'select',   options:['true','false'], defaultVal:'false' },
                   { key:'check_schemes',  label:'file:// Local File Read',          type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_headers',  label:'Header-Based SSRF',                type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_open_redirect', label:'Open Redirect (SSRF chain)',  type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_body',       label:'POST/JSON Body SSRF',            type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_graphql',    label:'GraphQL URL-Variable SSRF',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_multipart',  label:'Multipart Form SSRF',            type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_redirect_chain', label:'Redirect→Metadata Chain',  type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_timing',     label:'Time-Based Blind SSRF Oracle',   type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'params',         label:'SSRF Parameters (blank = defaults)', type:'textarea', placeholder:'url\nuri\nredirect\nwebhook\nfetch', defaultVal:'' },
                   { key:'max_params',     label:'Max Parameters (blank = auto)',    type:'number',   placeholder:'12', defaultVal:'', min:1, max:100 },
                   { key:'paths',          label:'Extra Endpoints (one per line)',   type:'textarea', placeholder:'/api/fetch\n/proxy\n/preview', defaultVal:'' },
                   { key:'max_paths',      label:'Max Endpoints (blank = auto)',     type:'number',   placeholder:'4', defaultVal:'', min:1, max:50 },
                   { key:'internal_hosts', label:'Internal Targets (one per line)',  type:'textarea', placeholder:'http://127.0.0.1/\nhttp://127.0.0.1:6379/', defaultVal:'' },
                   { key:'custom_payloads',label:'Custom SSRF Payloads (one per line)', type:'textarea', placeholder:'http://internal.svc/admin', defaultVal:'' },
                   { key:'redirect_params',label:'Redirect Parameters (blank = defaults)', type:'text', placeholder:'url,next,redirect,goto', defaultVal:'' },
                   { key:'auth_header',    label:'Auth Header (Name: Value)',        type:'text',     placeholder:'Authorization: Bearer eyJ...', defaultVal:'' },
                   { key:'bearer_token',   label:'Bearer Token (optional)',          type:'password', placeholder:'eyJ...', defaultVal:'' },
                   { key:'cookies',        label:'Session Cookie (optional)',        type:'password', placeholder:'session=abc; csrf=xyz', defaultVal:'' },
                   { key:'check_oob',      label:'Blind/OOB SSRF (needs OAST)',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'oast_domain',    label:'OAST Domain (blind SSRF)',         type:'text',     placeholder:'abcd.oast.live', defaultVal:'' },
                   { key:'oast_token',     label:'OAST Token (optional)',            type:'text',     placeholder:'unique-token', defaultVal:'' },
                   { key:'timeout_ms',     label:'Per-Request Timeout (ms)',         type:'number',   placeholder:'6000', defaultVal:'6000', min:400, max:30000 },
                   { key:'concurrency',    label:'Concurrency',                      type:'number',   placeholder:'16', defaultVal:'16', min:1, max:48 },
                   { key:'attack_path_synthesis', label:'Attack-Path Synthesis',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'posture_scoring',label:'Posture Scoring',                  type:'select',   options:['true','false'], defaultVal:'true' }],
  waf_bypass:      [{ key:'technique',           label:'Bypass Technique',                type:'select',   options:['all','encoding','fragmentation','case_variation','comments','header_injection','path_normalization','verb_tampering','json_smuggling'], defaultVal:'all' },
                   { key:'intensity',           label:'Scan Intensity',                  type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'timeout_ms',          label:'HTTP timeout (ms)',               type:'number',   placeholder:'8000', defaultVal:'8000', min:500, max:30000 },
                   { key:'extra_payloads',      label:'Extra probe payloads (comma-sep)', type:'text',    placeholder:'<img src=x onerror=alert(1)>' },
                   { key:'check_fingerprint',   label:'WAF/CDN fingerprint',             type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_query_probes',  label:'Query-string probes',             type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_encoding',      label:'Encoding transforms',             type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_header_injection', label:'Header injection vectors',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_path_normalization', label:'Path normalization probes', type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_verb_tampering', label:'GET vs POST verb gap',           type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_json_smuggling', label:'JSON body inspection gap',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'emit_score',          label:'WAF hardening score',             type:'select',   options:['true','false'], defaultVal:'true' }],
  edr_evasion:     [{ key:'intensity',       label:'Scan Intensity',                  type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'timeout_ms',      label:'HTTP timeout (ms)',               type:'number',   placeholder:'8000', defaultVal:'8000', min:500, max:30000 },
                   { key:'ua_matrix_limit', label:'User-Agent matrix size',          type:'number',   placeholder:'24', defaultVal:'24', min:4, max:80 },
                   { key:'rate_burst_count', label:'Rate-limit burst count',         type:'number',   placeholder:'12', defaultVal:'12', min:3, max:40 },
                   { key:'check_waf',         label:'WAF/CDN fingerprint',            type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_ua_matrix',   label:'Scanner UA block matrix',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_rate_limit',  label:'Rate-limit burst probe',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_headers',     label:'Security headers audit',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_cookies',     label:'Cookie hardening audit',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_csp',         label:'CSP injection runway',           type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_telemetry',   label:'RUM/APM telemetry in page',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_debug_paths', label:'Debug/admin path sweep',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_source_maps', label:'JavaScript source maps',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_error_verbosity', label:'Verbose error pages',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'include_agent_findings', label:'Host EDR agent guidance',   type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'extra_paths',       label:'Extra paths (comma-sep)',        type:'text',     placeholder:'/admin,/internal', defaultVal:'' }],
  file_upload:     [{ key:'intensity',       label:'Probe Intensity',              type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'stack_pack',      label:'Platform Bypass Pack',         type:'select',   options:['auto','all','php','iis','dotnet','java','node'], defaultVal:'auto' },
                   { key:'upload_paths',    label:'Upload Paths (comma-sep)',     type:'text',     placeholder:'/upload,/api/upload', defaultVal:'/upload,/api/upload,/files/upload' },
                   { key:'field_names',     label:'Field Names',                  type:'text',     placeholder:'file,upload,document', defaultVal:'file,upload,document' },
                   { key:'auth_cookie',     label:'Session Cookie',               type:'text',     placeholder:'session=...', defaultVal:'' },
                   { key:'auth_header',     label:'Authorization Header',         type:'text',     placeholder:'Bearer ...', defaultVal:'' },
                   { key:'canary_token',    label:'Canary Token',                 type:'text',     placeholder:'WZUPLOAD9137BENIGN', defaultVal:'' },
                   { key:'verify_storage',  label:'Verify Storage Retrieval',     type:'boolean',  defaultVal:true },
                   { key:'storage_path_oracle', label:'Storage Path Oracle',      type:'boolean',  defaultVal:true },
                   { key:'check_openapi_discovery', label:'OpenAPI Discovery',    type:'boolean',  defaultVal:true },
                   { key:'check_js_discovery', label:'JS Bundle Discovery',       type:'boolean',  defaultVal:true },
                   { key:'check_graphql_upload', label:'GraphQL Multipart Upload',  type:'boolean',  defaultVal:true },
                   { key:'check_base64_json', label:'Base64 JSON Upload API',      type:'boolean',  defaultVal:true },
                   { key:'check_zip_upload', label:'ZIP / Zip-Slip Surface',      type:'boolean',  defaultVal:true },
                   { key:'check_mime_spoof',label:'MIME Spoofing',                type:'boolean',  defaultVal:true },
                   { key:'check_double_extension', label:'Double Extensions',     type:'boolean',  defaultVal:true },
                   { key:'check_php_bypass', label:'PHP Bypass Pack',             type:'boolean',  defaultVal:true },
                   { key:'check_iis_bypass', label:'IIS Bypass Pack',             type:'boolean',  defaultVal:true },
                   { key:'check_dotnet_bypass', label:'.NET Bypass Pack',         type:'boolean',  defaultVal:true },
                   { key:'check_java_bypass', label:'Java Bypass Pack',           type:'boolean',  defaultVal:true },
                   { key:'check_node_bypass', label:'Node Static-Exec Surface',   type:'boolean',  defaultVal:true },
                   { key:'check_svg_xss',   label:'SVG XSS Surface',              type:'boolean',  defaultVal:true },
                   { key:'check_config_upload', label:'Config Upload (.htaccess)', type:'boolean', defaultVal:true },
                   { key:'check_put_upload', label:'HTTP PUT Upload',             type:'boolean',  defaultVal:true },
                   { key:'check_patch_upload', label:'HTTP PATCH Upload',         type:'boolean',  defaultVal:false },
                   { key:'check_upload_idor', label:'Upload IDOR Oracle',       type:'boolean',  defaultVal:true },
                   { key:'check_tus_upload', label:'Tus Resumable Upload',      type:'boolean',  defaultVal:true },
                   { key:'check_webdav_discovery', label:'WebDAV OPTIONS',      type:'boolean',  defaultVal:true },
                   { key:'check_auth_differential', label:'Auth Differential',    type:'boolean',  defaultVal:true },
                   { key:'check_unicode_homoglyph', label:'Unicode Homoglyph',    type:'boolean',  defaultVal:true },
                   { key:'check_multipart_hpp', label:'Multipart HPP',           type:'boolean',  defaultVal:true },
                   { key:'check_content_range', label:'Content-Range PUT',       type:'boolean',  defaultVal:true },
                   { key:'check_cms_paths', label:'CMS / Enterprise Paths',      type:'boolean',  defaultVal:true },
                   { key:'check_directory_listing', label:'Directory Listing',     type:'boolean',  defaultVal:true },
                   { key:'check_presigned_probe', label:'Presigned URL Probe',   type:'boolean',  defaultVal:true },
                   { key:'check_size_limit_oracle', label:'Size Limit Oracle',   type:'boolean',  defaultVal:false },
                   { key:'check_unauth_retrieval', label:'Unauth Download After Upload', type:'boolean', defaultVal:true },
                   { key:'check_cdn_cache_isolation', label:'CDN Cache Isolation', type:'boolean', defaultVal:true },
                   { key:'check_waf_fingerprint', label:'WAF Fingerprint on 403', type:'boolean', defaultVal:true },
                   { key:'check_robots_discovery', label:'robots.txt Discovery', type:'boolean', defaultVal:true },
                   { key:'check_url_encoded_extension', label:'URL-Encoded Extension', type:'boolean', defaultVal:true },
                   { key:'check_long_filename', label:'Long Filename Stress', type:'boolean', defaultVal:true },
                   { key:'check_jpeg_com_polyglot', label:'JPEG COM Polyglot', type:'boolean', defaultVal:true },
                   { key:'check_docx_surface', label:'DOCX OOXML Surface', type:'boolean', defaultVal:true },
                   { key:'check_crlf_filename_reflection', label:'CRLF Filename Oracle', type:'boolean', defaultVal:false },
                   { key:'check_reverse_double_extension', label:'Reverse Double Extension', type:'boolean', defaultVal:true },
                   { key:'check_iis_handlers', label:'IIS Handler Surface (.ashx/.asmx)', type:'boolean', defaultVal:true },
                   { key:'check_template_injection_filename', label:'SSTI Filename Oracle', type:'boolean', defaultVal:true },
                   { key:'check_upload_cors', label:'Upload CORS Misconfig', type:'boolean', defaultVal:true },
                   { key:'check_rate_limit_absence', label:'Rate Limit Absence', type:'boolean', defaultVal:true },
                   { key:'check_error_disclosure', label:'Error Disclosure on Malformed Multipart', type:'boolean', defaultVal:true },
                   { key:'check_delete_without_auth', label:'Unauthenticated DELETE', type:'boolean', defaultVal:true },
                   { key:'check_range_retrieval', label:'Range Byte Leak on Retrieval', type:'boolean', defaultVal:true },
                   { key:'check_sitemap_discovery', label:'Sitemap Upload Discovery', type:'boolean', defaultVal:true },
                   { key:'check_spring_paths', label:'Spring Boot Upload Paths', type:'boolean', defaultVal:true },
                   { key:'check_sharepoint_paths', label:'SharePoint / Graph Upload Paths', type:'boolean', defaultVal:true },
                   { key:'check_eicar_surface', label:'EICAR AV Pipeline Oracle', type:'boolean', defaultVal:true },
                   { key:'check_batch_upload', label:'Batch Multi-File Upload', type:'boolean', defaultVal:true },
                   { key:'check_webp_png_surface', label:'WebP / PNG Format Surface', type:'boolean', defaultVal:true },
                   { key:'check_filename_field_mismatch', label:'Filename Field Mismatch', type:'boolean', defaultVal:true },
                   { key:'check_double_content_disposition', label:'Double Content-Disposition', type:'boolean', defaultVal:true },
                   { key:'check_boundary_smuggling', label:'Multipart Boundary Smuggling', type:'boolean', defaultVal:false },
                   { key:'check_json_multi_file', label:'JSON Multi-File Array API', type:'boolean', defaultVal:true },
                   { key:'check_imagemagick_surface', label:'ImageMagick Policy Fingerprint', type:'boolean', defaultVal:true },
                   { key:'check_svg_foreign_object', label:'SVG foreignObject Surface', type:'boolean', defaultVal:true },
                   { key:'check_internal_url_disclosure', label:'Internal URL Disclosure', type:'boolean', defaultVal:true },
                   { key:'check_semicolon_bypass', label:'Semicolon Mid-Extension Bypass', type:'boolean', defaultVal:true },
                   { key:'check_apache_multisuffix', label:'Apache .php.foo Multi-Suffix', type:'boolean', defaultVal:true },
                   { key:'check_cloud_native_paths', label:'Cloud-Native Upload Paths', type:'boolean', defaultVal:true },
                   { key:'check_security_txt_discovery', label:'security.txt Upload Hints', type:'boolean', defaultVal:true },
                   { key:'check_gzip_upload', label:'Gzip Content-Encoding Upload', type:'boolean', defaultVal:true },
                   { key:'check_expect_continue', label:'Expect 100-Continue Upload', type:'boolean', defaultVal:true },
                   { key:'check_x_forwarded_host', label:'X-Forwarded-Host Reflection', type:'boolean', defaultVal:true },
                   { key:'check_location_header_leak', label:'Location Header Storage Leak', type:'boolean', defaultVal:true },
                   { key:'check_overwrite_oracle', label:'Overwrite / Version Oracle', type:'boolean', defaultVal:true },
                   { key:'check_head_metadata_leak', label:'HEAD Metadata Leak', type:'boolean', defaultVal:true },
                   { key:'check_xlsm_surface', label:'XLSM Macro Surface', type:'boolean', defaultVal:true },
                   { key:'check_pdf_js_surface', label:'PDF JS Surface', type:'boolean', defaultVal:true },
                   { key:'check_rtlo_bypass', label:'RTLO Bidi Filename Bypass', type:'boolean', defaultVal:true },
                   { key:'check_nfkc_bypass', label:'NFKC Fullwidth Extension', type:'boolean', defaultVal:true },
                   { key:'check_newline_extension', label:'Newline in Extension', type:'boolean', defaultVal:false },
                   { key:'oast_host', label:'OAST Callback Host (optional)', type:'text', placeholder:'your-id.oast.example.com', defaultVal:'' },
                   { key:'timeout_ms',      label:'Timeout (ms)',                 type:'number',   defaultVal:8000 },
                   { key:'concurrency',     label:'Concurrency',                  type:'number',   defaultVal:12 },
                   { key:'max_endpoints',   label:'Max Endpoints',                type:'number',   defaultVal:32 },
                   { key:'max_combos_per_endpoint', label:'Max Bypass Combos',    type:'number',   defaultVal:42 }],
  llm_path_fuzz:   [{ key:'llm_base_url', label:'LLM Base URL',                   type:'text',     placeholder:'http://127.0.0.1:11434/v1', defaultVal:'' },
                   { key:'llm_model',   label:'LLM Model',                         type:'text',     placeholder:'llama3', defaultVal:'' }],
  semantic_ai_fuzz:[{ key:'llm_base_url', label:'LLM Base URL',                   type:'text',     placeholder:'http://127.0.0.1:8000/v1', defaultVal:'' },
                   { key:'llm_model',   label:'LLM Model',                         type:'text',     placeholder:'gpt-4o', defaultVal:'' },
                   { key:'temperature', label:'Temperature',                        type:'number',   placeholder:'0.7', defaultVal:'0.7', min:0, max:2 }],
  nexus_sovereign_swarm:[
                   { key:'agent_count', label:'Agent Deployment Count',          type:'number',   placeholder:'2048', defaultVal:'2048', min:64, max:10000 },
                   { key:'hive_mode',   label:'Hive Coordination Mode',            type:'select',   options:['emergent','parallel','stealth','blitz'], defaultVal:'emergent' },
                   { key:'llm_strategy',label:'Oracle LLM Strategy',               type:'select',   options:['adaptive','aggressive','stealth','oracle'], defaultVal:'adaptive' },
                   { key:'archetypes',  label:'Agent Archetypes (comma-sep)',      type:'text',     placeholder:'scout,exploiter,correlator,stealth,oracle', defaultVal:'scout,exploiter,correlator,stealth,oracle' },
                   { key:'endpoint_bridge', label:'Bridge Endpoint Agents',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'edge_distribution', label:'Edge POP Distribution',       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'convergence_threshold', label:'Hive Consensus Threshold', type:'number', placeholder:'0.85', defaultVal:'0.85', min:0.5, max:0.99, step:0.01 },
                   { key:'llm_base_url', label:'Oracle LLM Base URL',             type:'text',     placeholder:'http://127.0.0.1:11434/v1', defaultVal:'' },
                   { key:'llm_model',   label:'Oracle LLM Model',                  type:'text',     placeholder:'gpt-4o', defaultVal:'' }],
  aws_attack:      [{ key:'aws_region',   label:'AWS Region',                      type:'text',     placeholder:'us-east-1', defaultVal:'us-east-1' },
                   { key:'resource_types',label:'Resource Types',                  type:'text',     placeholder:'s3,iam,ec2', defaultVal:'s3,iam,ec2' }],
  cloud_posture:   [{ key:'aws_cross_account_role_arn', label:'Cross-Account Role ARN', type:'text', placeholder:'arn:aws:iam::123456789012:role/WeissmanReadOnly', defaultVal:'' },
                   { key:'aws_external_id', label:'STS External ID',              type:'text',     placeholder:'external-id', defaultVal:'' },
                   { key:'aws_role_session_name', label:'Role Session Name',        type:'text',     placeholder:'weissman-cspm', defaultVal:'weissman-cspm' },
                   { key:'regions',       label:'Regions (comma-sep)',             type:'text',     placeholder:'us-east-1,eu-west-1', defaultVal:'us-east-1,us-west-2,eu-west-1,eu-central-1,ap-southeast-1' },
                   { key:'services',      label:'Services (comma-sep)',            type:'text',     placeholder:'iam,s3,wafv2,logs,redshift,documentdb,neptune,memorydb,backup,organizations,sfn,sso,...', defaultVal:'iam,s3,account,ec2,vpc,elb,eks,ecs,lambda,rds,elasticache,kms,secrets,messaging,ssm,cloudtrail,config,guardduty,accessanalyzer,ecr,acm,dynamodb,apigateway,opensearch,cloudfront,route53,eventbridge,wafv2,logs,redshift,documentdb,neptune,memorydb,backup,organizations,sfn,sso' },
                   { key:'frameworks',    label:'Compliance Frameworks',           type:'text',     placeholder:'CIS,SOC2,ISO27001,PCI,NIST,GDPR', defaultVal:'CIS,SOC2,ISO27001,PCI,NIST,GDPR' },
                   { key:'min_severity',  label:'Min Severity',                    type:'select',   options:['info','low','medium','high','critical'], defaultVal:'info' },
                   { key:'intensity',     label:'Scan Intensity',                  type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'max_resources_per_service', label:'Max Resources / Service', type:'number', placeholder:'300', defaultVal:'300', min:10, max:5000 },
                   { key:'access_key_max_age_days', label:'Access Key Max Age (days)', type:'number', placeholder:'90', defaultVal:'90', min:1, max:3650 },
                   { key:'acm_expiry_days', label:'ACM Expiry Threshold (days)',   type:'number', placeholder:'30', defaultVal:'30', min:1, max:365 },
                   { key:'check_graph_paths', label:'Graph-Native Attack Paths',   type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'include_attack_paths', label:'Attack Path Correlation',  type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'include_security_graph', label:'Security Graph',         type:'select',   options:['true','false'], defaultVal:'true' }],
  azure_attack:    [
                   { key:'azure_tenant_id',     label:'Azure AD Tenant ID',           type:'text',     placeholder:'00000000-0000-0000-0000-000000000000', defaultVal:'' },
                   { key:'azure_client_id',     label:'Service Principal Client ID',  type:'text',     placeholder:'app registration (client) ID', defaultVal:'' },
                   { key:'azure_client_secret', label:'Client Secret',                type:'password', placeholder:'service principal secret', defaultVal:'' },
                   { key:'subscription_id',     label:'Subscription ID (optional)',   type:'text',     placeholder:'single subscription GUID', defaultVal:'' },
                   { key:'subscriptions',       label:'Subscriptions (comma-sep, optional)', type:'text', placeholder:'sub1,sub2 — blank = all visible', defaultVal:'' },
                   { key:'checks',              label:'Posture Checks',               type:'text',     placeholder:'storage,network,sql,keyvault,rbac,defender,arg,acr,aks,appservice,cosmos,compute', defaultVal:'storage,network,sql,keyvault,rbac,defender,arg,acr,aks,appservice,cosmos,compute' },
                   { key:'intensity',           label:'Scan Intensity',               type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'sensitive_ports',     label:'Sensitive Ports (NSG exposure)', type:'text',   placeholder:'blank = built-in set (22,3389,1433,3306,…)', defaultVal:'' },
                   { key:'max_subscriptions',   label:'Max Subscriptions',            type:'number',   placeholder:'5', defaultVal:'5', min:1, max:50 },
                   { key:'section_timeout_secs',label:'Per-section Timeout (s)',       type:'number',   placeholder:'75', defaultVal:'75', min:15, max:300 },
                   { key:'include_security_graph', label:'Include Security Graph JSON', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'include_attack_paths', label:'Correlate Attack Paths',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'posture_scoring',     label:'Executive Posture Score (0–100)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'arg_max_rows',        label:'Resource Graph Max Rows',       type:'number',   placeholder:'200', defaultVal:'200', min:10, max:2000 },
                   { key:'also_external_scan',  label:'Also run external surface scan', type:'select',  options:['false','true'], defaultVal:'false' },
                   { key:'check_takeover',        label:'Azure Subdomain Takeover (external)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'subdomains',            label:'Subdomains for Takeover (external)', type:'text', placeholder:'www,api,staging — blank = built-in set', defaultVal:'' },
                   { key:'max_takeover_hosts',    label:'Max Takeover Hostnames',        type:'number',   placeholder:'25', defaultVal:'25', min:1, max:100 },
                   { key:'arm_endpoint',        label:'ARM Endpoint (sovereign cloud)', type:'text',   placeholder:'https://management.azure.com', defaultVal:'' },
                   { key:'login_endpoint',      label:'Login Endpoint (sovereign cloud)', type:'text', placeholder:'https://login.microsoftonline.com', defaultVal:'' },
                   { key:'storage_accounts',    label:'Blob Account Candidates (external)', type:'text', placeholder:'comma-sep names to test for public blobs', defaultVal:'' },
                   { key:'containers',          label:'Blob Containers (external)',    type:'text',     placeholder:'blank = common set (backup,data,public,…)', defaultVal:'' },
                   { key:'max_account_candidates', label:'Max Blob Account Candidates', type:'number',  placeholder:'12', defaultVal:'12', min:1, max:100 }],
  gcp_attack:      [{ key:'gcp_project',  label:'GCP Project ID (optional)',       type:'text',     placeholder:'my-project-123', defaultVal:'' }],
  k8s_container:   [{ key:'namespace',    label:'Namespace',                       type:'text',     placeholder:'default', defaultVal:'default' }],
  iac_misconfig:   [{ key:'repo_url',     label:'IaC Repository URL',              type:'text',     placeholder:'https://github.com/org/infra', defaultVal:'' },
                   { key:'scan_type',   label:'IaC Type',                          type:'select',   options:['auto','terraform','cloudformation','pulumi','helm'], defaultVal:'auto' }],
  smb_netbios:     [{ key:'ports',           label:'SMB Ports (direct)',              type:'text',     placeholder:'445', defaultVal:'445' },
                   { key:'timeout_ms',       label:'Per-probe Timeout (ms)',          type:'number',   placeholder:'4000', defaultVal:'4000', min:200, max:30000 },
                   { key:'check_smb1',       label:'Detect SMBv1 / EternalBlue',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_signing',    label:'Check SMB Signing (NTLM relay)',  type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_encryption', label:'SMB3 Encryption Posture',       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_smbghost',   label:'Detect SMBGhost (CVE-2020-0796)', type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_spnego',     label:'SPNEGO Kerberos/NTLM Fingerprint', type:'select',  options:['true','false'], defaultVal:'true' },
                   { key:'check_ipc_pipes',  label:'IPC$ / DCE/RPC Pipe Probe',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_ntlm',       label:'NTLM Host/Domain/OS Fingerprint', type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_netbios',    label:'NetBIOS Node Status (UDP 137)',   type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_nbns_roles', label:'NBNS DC / Browser Role Detection', type:'select',  options:['true','false'], defaultVal:'true' },
                   { key:'netbios_udp_port', label:'NetBIOS UDP Port',                type:'number',   placeholder:'137', defaultVal:'137', min:1, max:65535 },
                   { key:'check_139',        label:'Check NetBIOS Session (TCP 139)', type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_uptime',     label:'Server Uptime (FILETIME)',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_petitpotam', label:'PetitPotam Toxic Combination',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_zerologon', label:'Zerologon Surface Correlator',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_printnightmare', label:'PrintNightmare Correlator',   type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_ms17_010',   label:'MS17-010 Trans2 Fingerprint',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_ntlm_weak',  label:'NTLMv1 / LM Weakness Flags',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_admin_shares', label:'Hidden Share Probe (C$/ADMIN$)',  type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_implementation', label:'SMB Stack Fingerprint',       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_capabilities', label:'SMB Global Capabilities',       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_dialect_downgrade', label:'Dialect Downgrade Detection', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_mac_vendor', label:'MAC OUI Vendor (NBNS)',           type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'emit_metrics',     label:'Emit Scan Telemetry (pipe matrix)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'scan_all_ports',   label:'Probe All Configured Ports',      type:'select',   options:['true','false'], defaultVal:'false' },
                   { key:'posture_scoring', label:'Executive Posture Score',          type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'synthesize_attack_path', label:'Synthesize Attack Path',    type:'select',   options:['true','false'], defaultVal:'true' }],
  bgp_dns_hijacking:[
                   { key:'scan_profile',  label:'Scan Profile',                    type:'select',   options:['full','email_auth','hijack_detect','takeover','transfer','quick'], defaultVal:'full' },
                   { key:'intensity',     label:'Intensity',                       type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'check_resolver_consistency', label:'DNS Hijack / Resolver Cross-Check', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_email_auth', label:'Email Auth (SPF/DKIM/DMARC/MTA-STS)', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_ns_hygiene', label:'DNSSEC / CAA / NS Hygiene',     type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_zone_transfer', label:'Zone Transfer (AXFR)',       type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_open_resolver', label:'Open Recursive Resolver',    type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_takeover', label:'Subdomain Takeover',              type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_bgp_rpki', label:'BGP Origin / RPKI Validation',    type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'dkim_selectors', label:'DKIM Selectors (comma-sep)',      type:'text',     placeholder:'default,google,selector1,k1', defaultVal:'' },
                   { key:'subdomains',    label:'Subdomains for Takeover (one per line)', type:'textarea', placeholder:'www\nassets\napi', defaultVal:'' },
                   { key:'timeout_ms',    label:'Per-query Timeout (ms)',           type:'number',   placeholder:'4000', defaultVal:'4000', min:400, max:30000 },
                   { key:'attack_path_synthesis', label:'Attack-Path Synthesis',    type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'posture_scoring', label:'Posture Scoring',                type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'asn',          label:'Target ASN (optional)',            type:'text',     placeholder:'AS12345', defaultVal:'' }],
  ipv6_attack:     [{ key:'technique',    label:'IPv6 Technique',                  type:'select',   options:['all','neighbor_discovery','rogue_router','extension_header'], defaultVal:'all' }],
  mtls_grpc:       [
                   { key:'scan_profile',  label:'Scan Profile',                    type:'select',   options:['full','tls_only','headers_only','quick','grpc_only','grpc_deep','mtls_audit','api_hardening'], defaultVal:'full' },
                   { key:'intensity',     label:'Intensity',                       type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'sni',           label:'SNI Override (optional)',         type:'text',     placeholder:'api.example.com', defaultVal:'' },
                   { key:'ports',         label:'TLS Ports (comma-sep)',           type:'text',     placeholder:'443,8443', defaultVal:'443,8443' },
                   { key:'grpc_ports',    label:'gRPC Ports (comma-sep)',          type:'text',     placeholder:'50051,9090', defaultVal:'50051,9090' },
                   { key:'check_tls_cert', label:'TLS Certificate Analysis',       type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_tls_session', label:'TLS Session Matrix (multi-port)', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_weak_ciphers', label:'Weak Cipher Matrix (RC4/3DES/EXPORT/NULL/PFS)', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_legacy_tls', label:'Legacy TLS 1.0/1.1 Probe',    type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_ocsp',    label:'OCSP Stapling Check',             type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_mtls',    label:'mTLS Enforcement Probe',          type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_sni_policy', label:'SNI Virtual-Host Policy',    type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_cert_consistency', label:'Cert Fingerprint Matrix (multi-port)', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_grpc_reflection', label:'gRPC Reflection / Health', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_grpc_web', label:'gRPC-Web / Connect-RPC Surface', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_headers', label:'Security Headers / Cookies',      type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_cross_origin', label:'Cross-Origin Isolation (COOP/COEP/CORP)', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_api_hardening', label:'API Hardening (TRACE + CORS)', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_h2c',     label:'Cleartext h2c Upgrade Probe',     type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_http3',   label:'HTTP/3 (ALPN h3 + Alt-Svc)',      type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_redirect',label:'HTTP→HTTPS Upgrade Check',        type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_http2',   label:'HTTP/2 (ALPN) Check',             type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_dane',    label:'DANE / TLSA DNS Pinning',         type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_caa',     label:'DNS CAA Policy Check',            type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_ct',      label:'Certificate Transparency (crt.sh)', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_security_txt', label:'security.txt (RFC 9116)',   type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_hsts_preload', label:'HSTS Preload Readiness',   type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_chain_trust', label:'Certificate Chain Trust (system CAs)', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_redirect_chain', label:'Redirect Chain Audit (no HTTP hops)', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'redirect_max_hops', label:'Max Redirect Hops to Follow', type:'number', placeholder:'8', defaultVal:'8', min:2, max:20 },
                   { key:'check_grpc_h2c', label:'gRPC h2c Prior-Knowledge Preface', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_websocket', label:'WebSocket Upgrade Probe', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_cache_policy', label:'Cache-Control Policy (API)', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'emit_coverage_manifest', label:'Emit Probe Coverage Manifest', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_mixed_passive', label:'Mixed Passive Content (HTTP subresources)', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_must_staple', label:'OCSP Must-Staple Extension + Correlation', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_mesh_fingerprint', label:'Mesh/Proxy Fingerprint (Envoy/Istio/Kong)', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'grpc_paths', label:'Custom gRPC Paths (comma-sep)', type:'text', placeholder:'/my.package.Service/Method', defaultVal:'' },
                   { key:'check_tls_compression', label:'TLS Compression / CRIME Probe', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_reporting_headers', label:'NEL / Report-To Reporting Headers', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_upgrade_insecure_requests', label:'Upgrade-Insecure-Requests Oracle', type:'select', options:['auto','on','off'], defaultVal:'auto' },
                   { key:'ct_recent_days', label:'CT Recent Issuance Window (days)', type:'number', placeholder:'30', defaultVal:'30', min:1, max:365 },
                   { key:'ct_high_watermark', label:'CT High-Footprint Threshold', type:'number',   placeholder:'80', defaultVal:'80', min:10, max:5000 },
                   { key:'min_rsa_bits',  label:'Min RSA Key Bits',                type:'number',   placeholder:'2048', defaultVal:'2048', min:1024, max:8192 },
                   { key:'min_hsts_age',  label:'Min HSTS max-age (seconds)',      type:'number',   placeholder:'31536000', defaultVal:'31536000', min:0, max:63072000 },
                   { key:'timeout_ms',    label:'Per-request Timeout (ms)',        type:'number',   placeholder:'6000', defaultVal:'6000', min:400, max:30000 },
                   { key:'attack_path_synthesis', label:'Attack-Path Synthesis',   type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'posture_scoring', label:'Posture Scoring',               type:'select',   options:['true','false'], defaultVal:'true' }],
  pki_tls:         [{ key:'ports',          label:'TLS Ports',                       type:'text',     placeholder:'443,8443,993', defaultVal:'443' },
                   { key:'sni',             label:'SNI / Server Name (optional)',    type:'text',     placeholder:'api.example.com', defaultVal:'' },
                   { key:'starttls',        label:'STARTTLS Protocol',               type:'select',   options:['none','auto','smtp','imap','pop3','ftp'], defaultVal:'none' },
                   { key:'intensity',       label:'Scan Intensity',                  type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'protocols',       label:'Protocols to test (blank = all)', type:'text',     placeholder:'ssl3,tls1.0,tls1.1,tls1.2,tls1.3', defaultVal:'' },
                   { key:'timeout_ms',      label:'Per-handshake timeout (ms)',      type:'number',   placeholder:'4000', defaultVal:'4000', min:200, max:30000 },
                   { key:'cipher_enumeration_limit', label:'Cipher walk depth (per proto)', type:'number', placeholder:'80', defaultVal:'80', min:1, max:512 },
                   { key:'port_budget_secs', label:'Per-port time budget (s)',        type:'number',   placeholder:'45', defaultVal:'45', min:5, max:600 },
                   { key:'expiry_warning_days', label:'Cert expiry warning (days)',   type:'number',   placeholder:'30', defaultVal:'30', min:1, max:365 },
                   { key:'check_protocols',     label:'Map protocol versions',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_ciphers',       label:'Enumerate cipher suites',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_certificate',   label:'Certificate forensics',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_chain_trust',   label:'Verify chain trust',           type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_hostname',      label:'Hostname / SAN match',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_forward_secrecy', label:'Forward-secrecy check',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_vulnerabilities', label:'Vulnerability heuristics',   type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_ocsp',          label:'OCSP stapling check',          type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_http_headers',  label:'HSTS / redirect check',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_security_headers', label:'Security headers audit',    type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_ct_logs',       label:'Certificate Transparency',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_caa',           label:'DNS CAA policy check',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_dane',          label:'DANE / TLSA (DNS pinning)',    type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_posture_score', label:'Aggregate posture score',      type:'select',   options:['true','false'], defaultVal:'true' }],
  email_dns_posture:[{ key:'dkim_selectors',  label:'Extra DKIM Selectors (comma-sep)', type:'text',   placeholder:'selector1,google,k1', defaultVal:'' },
                   { key:'resolver',           label:'DNS Resolver',                    type:'select',   options:['system','cloudflare','google','quad9'], defaultVal:'system' },
                   { key:'check_smtp_tls',      label:'Probe SMTP STARTTLS',             type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'smtp_ports',          label:'SMTP Ports',                      type:'text',     placeholder:'25,465,587', defaultVal:'25,465,587' },
                   { key:'check_mta_sts',       label:'Check MTA-STS (DNS + HTTPS policy)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_dnssec',        label:'Check DNSSEC',                    type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_dane',          label:'Check DANE / TLSA',               type:'select',   options:['true','false'], defaultVal:'false' },
                   { key:'check_caa',           label:'Check CAA',                       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_bimi',          label:'Check BIMI (brand logo)',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'subdomain_policy_required', label:'Require DMARC Subdomain Policy', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'min_dkim_bits',       label:'Min DKIM Key Bits',               type:'number',   placeholder:'2048', defaultVal:'2048', min:1024, max:4096, step:1024 },
                   { key:'spf_lookup_limit',    label:'SPF DNS-Lookup Limit',            type:'number',   placeholder:'10', defaultVal:'10', min:1, max:20 },
                   { key:'strict_mode',         label:'Strict Mode (escalate severities)', type:'select', options:['false','true'], defaultVal:'false' },
                   { key:'check_resolver_consensus', label:'Resolver Consensus (SPF/DMARC/MX)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_mail_subdomains', label:'Mail Subdomain Blast-Radius', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'mail_subdomains',     label:'Mail Subdomains (comma-sep)', type:'text', placeholder:'mail,autodiscover,webmail', defaultVal:'' },
                   { key:'check_autodiscover', label:'Autodiscover Surface Probe', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_bimi_logo_fetch', label:'BIMI Logo HTTPS Fetch', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_dmarc_external_reports', label:'DMARC External Report Auth', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_mx_diversity', label:'Mixed MX Provider Detection', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_spf_ip_inventory', label:'SPF IP Flatten Inventory', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_mx_tls_cert', label:'MX STARTTLS Certificate Probe', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_mta_sts_mx_drift', label:'MTA-STS MX Drift Check', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_ns_posture', label:'Authoritative NS Redundancy', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_soa_posture', label:'SOA Minimum TTL Posture', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_bimi_vmc_fetch', label:'BIMI VMC HTTPS Fetch + PEM Validate', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'timeout_ms',          label:'Per-Probe Timeout (ms)',          type:'number',   placeholder:'5000', defaultVal:'5000', min:1000, max:20000, step:500 }],
  kerberoasting:   [{ key:'domain',            label:'AD Domain (DNS SRV + realm)',     type:'text',     placeholder:'corp.example.com', defaultVal:'' },
                   { key:'intensity',         label:'Probe Intensity',                 type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'check_ports',       label:'AD Port Cartography',             type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_srv',         label:'DNS SRV DC Discovery',            type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_msdcs_dns',   label:'_msdcs DNS Zone Cartography',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_hybrid_entra', label:'Entra GetUserRealm + Autodiscover', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_ldap_anon',   label:'Anonymous LDAP Bind Probe',       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_ldap_enum',   label:'LDAP SPN & AS-REP Enumeration',   type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_ldap_starttls', label:'LDAP StartTLS Probe',           type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_ldaps_tls',   label:'LDAPS TLS Certificate Handshake', type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_kdc_probe',   label:'Kerberos KDC Liveness Probe',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_user_enum_krb', label:'Kerberos User-Enum Oracle',   type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_smb_signing', label:'SMB2 Signing Required Probe',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_spnego_http', label:'HTTP SPNEGO/NTLM Surface',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_adcs_http',   label:'AD CS Web Enrollment',            type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_delegation', label:'Delegation + RBCD LDAP Search',   type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_machine_spns', label:'Machine-Account SPN Enum',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_tier0_spns', label:'Tier-0 Kerberoastable SPNs',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'attack_paths',      label:'Attack-Path Synthesis',           type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'emit_agent_guidance', label:'Agent-Required Gap Guidance',  type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'probe_usernames', label:'Kerberos Probe Usernames',        type:'textarea', placeholder:'administrator\nkrbtgt', defaultVal:'administrator\nadmin\nkrbtgt\nsvc_backup' },
                   { key:'ad_ports',          label:'AD Ports (comma-separated)',      type:'text',     placeholder:'88,389,636,445,5985', defaultVal:'88,389,636,3268,3269,445,464,135,5985,5986,3389' },
                   { key:'dc_hosts',          label:'Additional DC Hosts',             type:'text',     placeholder:'dc01.corp.local,dc02.corp.local', defaultVal:'' },
                   { key:'ldap_base_dn',      label:'LDAP Base DN Override',           type:'text',     placeholder:'DC=corp,DC=local', defaultVal:'' },
                   { key:'extra_http_paths',  label:'Extra HTTP Paths (one per line)', type:'textarea', placeholder:'/adfs/ls/\n/owa/', defaultVal:'' },
                   { key:'max_ldap_entries',  label:'Max LDAP Entries to Report',      type:'number',   placeholder:'32', defaultVal:'32', min:4, max:128 },
                   { key:'resolver',          label:'DNS Resolver',                    type:'select',   options:['system','cloudflare','google','quad9'], defaultVal:'system' },
                   { key:'strict_mode',       label:'Strict Mode',                     type:'select',   options:['false','true'], defaultVal:'false' },
                   { key:'timeout_ms',        label:'TCP/LDAP Timeout (ms)',           type:'number',   placeholder:'5000', defaultVal:'5000', min:1000, max:20000 },
                   { key:'concurrency',       label:'Probe Concurrency',               type:'number',   placeholder:'16', defaultVal:'16', min:1, max:64 }],
  password_spray:  [{ key:'scan_profile', label:'Scan Profile',                    type:'select',   options:['full','discovery_only','spray_test','federation'], defaultVal:'full' },
                   { key:'intensity',    label:'Probe Intensity',                  type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'wordlist',     label:'Username/Password Wordlist',       type:'select',   options:['small','medium','large'], defaultVal:'medium' },
                   { key:'paths',        label:'Login Paths (blank = defaults)',   type:'textarea', placeholder:'/login\n/adfs/ls/\n/owa/\n/api/auth/login', defaultVal:'' },
                   { key:'usernames',    label:'Custom Usernames (one per line)',  type:'textarea', placeholder:'weissman_probe_admin\nweissman_probe_helpdesk', defaultVal:'' },
                   { key:'passwords',    label:'Custom Probe Passwords (one per line)', type:'textarea', placeholder:'WeissmanProbe!2024\nChangeme123!', defaultVal:'' },
                   { key:'domain',       label:'UPN Domain (user enumeration)',    type:'text',     placeholder:'corp.example.com', defaultVal:'' },
                   { key:'delay_ms',     label:'Delay Between Spray Attempts (ms)', type:'number',   placeholder:'1500', defaultVal:'1500', min:200, max:30000 },
                   { key:'max_attempts', label:'Max Spray Attempts per Surface',   type:'number',   placeholder:'18', defaultVal:'18', min:2, max:96 },
                   { key:'timeout_ms',   label:'Per-Request Timeout (ms)',         type:'number',   placeholder:'10000', defaultVal:'10000', min:500, max:30000 },
                   { key:'concurrency',  label:'Path Discovery Concurrency',       type:'number',   placeholder:'16', defaultVal:'16', min:1, max:24 },
                   { key:'check_rate_limit', label:'Rate-Limit Detection',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_lockout', label:'Account Lockout Detection',       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_user_enum', label:'User-Enumeration Oracle',       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_mfa_surface', label:'MFA Step-Up Detection',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_oauth_federation', label:'Federated SSO Exposure', type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_oidc_ropc', label:'OIDC ROPC Grant Detection',       type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_m365_realm', label:'Microsoft GetUserRealm (Entra)', type:'select',  options:['true','false'], defaultVal:'true' },
                   { key:'check_autodiscover', label:'Exchange Autodiscover',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_xff_bypass', label:'X-Forwarded-For Bypass Surface', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_lockout_curve', label:'Lockout-Curve Fingerprint',  type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_subdomain_login', label:'Subdomain Login Hunter',    type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_saml_metadata', label:'SAML Federation Metadata',  type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_password_policy', label:'Password Policy Oracle',    type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_device_code', label:'OIDC Device-Code Grant',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_basic_ntlm', label:'Basic/NTLM Auth Surface',        type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_browser_differential', label:'Browser vs Script WAF Gap', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_breach_differential', label:'Breach-Password Oracle', type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_timing_enum', label:'Timing User-Enumeration',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_entra_errors', label:'Entra AADSTS Token Signals',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_cors_login', label:'Permissive CORS on Login API',    type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_lockout_decay', label:'Lockout Decay Probe',          type:'select',   options:['false','true'], defaultVal:'false' },
                   { key:'check_remediation_playbook', label:'Remediation Playbook',  type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'timing_samples', label:'Timing Samples per User',            type:'number',   placeholder:'8', defaultVal:'8', min:4, max:24 },
                   { key:'lockout_decay_ms', label:'Lockout Decay Wait (ms)',      type:'number',   placeholder:'30000', defaultVal:'30000', min:5000, max:120000 },
                   { key:'subdomain_prefixes', label:'Subdomain Prefixes (comma-sep)', type:'text', placeholder:'login,sso,idp,owa,auth', defaultVal:'' },
                   { key:'check_captcha', label:'CAPTCHA Challenge Detection',    type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_form_login', label:'HTML Form Login Probes',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_json_api', label:'JSON API Login Probes',          type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'dry_run',      label:'Dry Run (discovery only, no spray)', type:'select', options:['false','true'], defaultVal:'false' },
                   { key:'auth_header',  label:'Auth Header (Name: Value)',        type:'text',     placeholder:'Authorization: Bearer eyJ...', defaultVal:'' },
                   { key:'cookies',      label:'Session Cookie (optional)',        type:'password', placeholder:'session=abc; csrf=xyz', defaultVal:'' },
                   { key:'attack_path_synthesis', label:'Attack-Path Synthesis',   type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'posture_scoring', label:'Posture Scoring (0–100)',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'emit_agent_guidance', label:'Emit Agent-Required Guidance', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_hsts_auth', label:'HSTS on Auth Surfaces',         type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_webauthn_surface', label:'WebAuthn/Passkey Surface', type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_oidc_pkce', label:'OIDC PKCE Posture',             type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_cookie_security', label:'Set-Cookie Hardening',      type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'include_info_findings', label:'Include Informational Findings', type:'select', options:['true','false'], defaultVal:'true' }],
  saml_attack:     [{ key:'metadata_url', label:'Explicit Metadata URL', type:'text', placeholder:'https://idp.example.com/metadata.xml', defaultVal:'' },
                   { key:'metadata_paths', label:'Metadata Paths (one per line)', type:'textarea', placeholder:'/saml/metadata\n/FederationMetadata/2007-06/FederationMetadata.xml', defaultVal:'' },
                   { key:'sso_paths', label:'SSO/ACS Paths (one per line)', type:'textarea', placeholder:'/adfs/ls/\n/saml2/sso', defaultVal:'' },
                   { key:'intensity', label:'Probe Intensity', type:'select', options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'check_metadata', label:'SAML Metadata Discovery', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_relaystate', label:'RelayState Open-Redirect Canary', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_error_disclosure', label:'Verbose Parser Error Disclosure', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_attack_paths', label:'Attack-Path Synthesis', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_xsw_preconditions', label:'XSW Preconditions (multi-ACS/certs)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_slo_exposure', label:'Single Logout (SLO) Exposure', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_ws_federation', label:'WS-Federation Metadata Probe', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_metadata_expiry', label:'Metadata validUntil Expiry', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_binding_posture', label:'HTTP-Redirect Binding Posture', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'emit_agent_guidance', label:'Emit Agent-Required Guidance', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'relaystate_canary', label:'RelayState Canary URL', type:'text', placeholder:'https://weissman-canary.example.net/probe', defaultVal:'https://weissman-canary.example.net/probe' },
                   { key:'cert_expiry_warn_days', label:'Cert Expiry Warn (days)', type:'number', placeholder:'30', defaultVal:'30', min:1, max:365 },
                   { key:'min_cert_bits', label:'Min Signing Key Bits', type:'number', placeholder:'2048', defaultVal:'2048', min:1024, max:8192 },
                   { key:'max_paths', label:'Max Paths to Probe', type:'number', placeholder:'28', defaultVal:'28', min:1, max:200 },
                   { key:'timeout_ms', label:'HTTP Timeout (ms)', type:'number', placeholder:'8000', defaultVal:'8000', min:800, max:30000 },
                   { key:'concurrency', label:'Probe Concurrency', type:'number', placeholder:'16', defaultVal:'16', min:1, max:64 }],
  cicd_pipeline:   [{ key:'probe_api', label:'Probe CI/CD API Exposure', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_config', label:'Probe Pipeline Config Exposure', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_fingerprint', label:'Platform Fingerprint', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_repo', label:'Multi-Vendor Repository Plane', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_workflow_analysis', label:'Workflow Static Analysis (pwn-request, injection)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_secret_scan', label:'Embedded Secret Scan (WZ-SEC-001)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_build_logs', label:'Build Log Exposure', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_artifact_exposure', label:'Artifact Registry Exposure', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_repo_governance', label:'Repo Governance (GitHub/GitLab/Azure DevOps)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_jenkins_console', label:'Jenkins Script Console Probe', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'probe_runner_tokens', label:'Runner Token Detection', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'repo_url', label:'Repository URL', type:'text', placeholder:'https://github.com/org/repo or dev.azure.com/org/proj/_git/repo', defaultVal:'' },
                   { key:'repo_ref', label:'Repo Ref / Branch', type:'text', placeholder:'main', defaultVal:'' },
                   { key:'github_token', label:'GitHub Token (private repos + governance)', type:'password', placeholder:'ghp_…', defaultVal:'' },
                   { key:'gitlab_token', label:'GitLab PRIVATE-TOKEN', type:'password', placeholder:'glpat-…', defaultVal:'' },
                   { key:'azure_devops_pat', label:'Azure DevOps PAT', type:'password', placeholder:'ADO PAT', defaultVal:'' },
                   { key:'platform_filter', label:'Platform Filter (comma-sep)', type:'text', placeholder:'jenkins,gitlab,argocd,azure_devops', defaultVal:'' },
                   { key:'compliance_frameworks', label:'Compliance Frameworks (comma-sep)', type:'text', placeholder:'NIST-SA-12,SOC2-CC8.1', defaultVal:'' },
                   { key:'max_requests', label:'Max HTTP Requests', type:'number', placeholder:'600', defaultVal:'600', min:10, max:3000 },
                   { key:'max_repo_files', label:'Max Repo CI Files', type:'number', placeholder:'32', defaultVal:'32', min:1, max:150 },
                   { key:'intensity', label:'Scan Intensity', type:'select', options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'attack_path_synthesis', label:'Attack-Path Synthesis', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'posture_scoring', label:'Posture Scoring', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'timeout_ms', label:'Per-Request Timeout (ms)', type:'number', placeholder:'10000', defaultVal:'10000', min:1000, max:30000 },
                   { key:'concurrency', label:'Concurrency', type:'number', placeholder:'16', defaultVal:'16', min:1, max:64 },
                   { key:'min_severity', label:'Min Severity', type:'select', options:['info','low','medium','high','critical'], defaultVal:'info' },
                   { key:'dry_run', label:'Dry Run (plan only)', type:'select', options:['false','true'], defaultVal:'false' }],
  container_registry:[{key:'registry',    label:'Registry',                        type:'text',     placeholder:'docker.io', defaultVal:'docker.io' }],
  sbom_analyzer:   [{ key:'format',       label:'SBOM Format',                     type:'select',   options:['auto','spdx','cyclonedx','syft'], defaultVal:'auto' }],
  websocket_attack:[{ key:'intensity',     label:'Scan Intensity',                  type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'paths',         label:'WebSocket Paths (blank = defaults)', type:'textarea', placeholder:'/ws\n/socket.io/?EIO=4&transport=websocket\n/cable', defaultVal:'' },
                   { key:'max_paths',     label:'Max Paths (blank = auto)',         type:'number',   placeholder:'18', defaultVal:'', min:1, max:80 },
                   { key:'check_cswsh',   label:'CSWSH Origin Test',                type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'foreign_origin',label:'Primary Foreign Origin',           type:'text',     placeholder:'https://attacker.example.com', defaultVal:'https://attacker.example.com' },
                   { key:'foreign_origins', label:'Extra Foreign Origins (comma/newline)', type:'textarea', placeholder:'https://evil.example.org\nhttp://127.0.0.1', defaultVal:'' },
                   { key:'check_null_origin', label:'Null-Origin CSWSH (sandboxed iframe)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_missing_origin', label:'Missing-Origin Handshake',  type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_forwarded_bypass', label:'X-Forwarded-* Proxy Bypass', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_host_injection', label:'Host-Header Smuggling on Upgrade', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_ws_version_downgrade', label:'WS Protocol Version Downgrade (8/7)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'cookies',       label:'Session Cookie (authenticated CSWSH)', type:'password', placeholder:'session=abc; csrf=xyz', defaultVal:'' },
                   { key:'bearer_token',  label:'Bearer Token (optional)',          type:'password', placeholder:'eyJ...', defaultVal:'' },
                   { key:'auth_header',   label:'Auth Header (Name: Value)',        type:'text',     placeholder:'Authorization: Bearer ...', defaultVal:'' },
                   { key:'check_subprotocols', label:'Subprotocol Smuggling Test',  type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'subprotocols',  label:'Privileged Subprotocols (comma-sep)', type:'text',  placeholder:'graphql-transport-ws,graphql-ws,v11.stomp', defaultVal:'' },
                   { key:'check_signalr_negotiate', label:'SignalR /negotiate Probe', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'signalr_paths', label:'SignalR Negotiate Paths',          type:'textarea', placeholder:'/negotiate\n/signalr/negotiate', defaultVal:'' },
                   { key:'check_socketio_polling', label:'Socket.IO Polling sid Probe', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_cleartext',label:'Cleartext ws:// Check',           type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_tls_downgrade', label:'TLS Downgrade (http on https origin)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_compression', label:'permessage-deflate Check',     type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'timeout_ms',    label:'Per-Request Timeout (ms)',         type:'number',   placeholder:'8000', defaultVal:'8000', min:500, max:30000 },
                   { key:'concurrency',   label:'Concurrency',                      type:'number',   placeholder:'16', defaultVal:'16', min:1, max:32 },
                   { key:'attack_path_synthesis', label:'Attack-Path Synthesis',    type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'posture_scoring', label:'Posture Scoring',                type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'check_message_probe', label:'Post-Handshake Message Probe', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'message_read_ms', label:'WS Message Read Window (ms)',   type:'number',   placeholder:'3000', defaultVal:'3000', min:500, max:15000 },
                   { key:'max_message_endpoints', label:'Max Endpoints for Message Probe (blank=auto)', type:'number', placeholder:'5', defaultVal:'', min:1, max:20 },
                   { key:'max_ws_messages', label:'Max Incoming WS Frames to Capture', type:'number', placeholder:'12', defaultVal:'12', min:1, max:40 },
                   { key:'check_sensitive_leak', label:'Sensitive Data in WS Frames', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_graphql_subscribe', label:'GraphQL Subscribe Without Auth', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_graphql_introspection', label:'GraphQL Introspection over graphql-ws', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_stomp_connect', label:'STOMP CONNECT Without Auth', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_auth_differential', label:'Auth-Differential Message Probe', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_foreign_origin_messages', label:'Foreign-Origin Live Session Data', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_ws_rate_limit', label:'Rate-Limit Absence Burst', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'ws_burst_count', label:'WS Burst Frame Count (blank=auto)', type:'number', placeholder:'12', defaultVal:'', min:4, max:24 },
                   { key:'check_binary_frames', label:'Binary Frame Acceptance Probe', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_stateful_fuzz', label:'Stateful Conversational Fuzz (state machine)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'stateful_fuzz_rounds', label:'Stateful Fuzz Rounds', type:'number', placeholder:'4', defaultVal:'4', min:1, max:6 },
                   { key:'check_binary_mutation', label:'Binary Protobuf Mutation Probe', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'check_race_conditions', label:'Blind Race Condition Execution', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'race_connections', label:'Race Parallel Connections', type:'number', placeholder:'4', defaultVal:'4', min:2, max:16 },
                   { key:'race_sync_us', label:'Race Sync Window (µs)', type:'number', placeholder:'0', defaultVal:'0', min:0, max:50000 },
                   { key:'race_payload', label:'Race Transactional Frame (JSON)', type:'text', placeholder:'{"type":"subscribe","id":"race-1","payload":{"action":"transfer"}}', defaultVal:'' },
                   { key:'check_cross_protocol_chain', label:'Cross-Protocol Intelligence Bus Chain', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'http_escalation_paths', label:'HTTP Escalation Paths (one per line)', type:'textarea', placeholder:'api/me\napi/v1/user\ngraphql', defaultVal:'' },
                   { key:'check_message_reflection', label:'Message Reflection (DOM XSS)', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'reflection_marker', label:'Reflection Probe Marker', type:'text', placeholder:'weissman_ws_xss_probe_<script>', defaultVal:'' },
                   { key:'check_js_harvest', label:'Harvest WS URLs from Page JS', type:'select', options:['true','false'], defaultVal:'true' },
                   { key:'custom_messages', label:'Custom WS Probe Messages (JSON/text, one per line)', type:'textarea', placeholder:'{"type":"ping"}\n42["event",{}]', defaultVal:'' }],
  typosquatting_monitor:[
                   { key:'scan_profile',  label:'Scan Profile',                    type:'select',   options:['full','domain_only','package_only','homograph','combosquat'], defaultVal:'full' },
                   { key:'intensity',     label:'Intensity',                       type:'select',   options:['light','normal','aggressive'], defaultVal:'normal' },
                   { key:'check_domains', label:'Lookalike Domain Discovery',      type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_packages',label:'Malicious Package Discovery',     type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_mx',      label:'MX Check (phishing-ready)',       type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'check_website', label:'Live Website Check',              type:'select',   options:['auto','on','off'], defaultVal:'auto' },
                   { key:'algorithms',   label:'Permutation Algorithms (comma-sep, blank=all)', type:'text', placeholder:'omission,homoglyph,tld_swap,combosquat', defaultVal:'' },
                   { key:'tld_list',     label:'TLDs to Test (comma-sep)',         type:'text',     placeholder:'com,net,org,io,co', defaultVal:'' },
                   { key:'combo_keywords',label:'Combosquat Keywords (comma-sep)', type:'text',     placeholder:'login,secure,support,pay', defaultVal:'' },
                   { key:'registries',   label:'Package Registries (comma-sep)',   type:'text',     placeholder:'npm,pypi,crates,rubygems', defaultVal:'npm,pypi,crates,rubygems' },
                   { key:'max_permutations', label:'Max Domain Permutations',      type:'number',   placeholder:'90', defaultVal:'90', min:1, max:600 },
                   { key:'max_packages', label:'Max Package Permutations',         type:'number',   placeholder:'25', defaultVal:'25', min:1, max:200 },
                   { key:'timeout_ms',   label:'Per-query Timeout (ms)',           type:'number',   placeholder:'5000', defaultVal:'5000', min:400, max:30000 },
                   { key:'attack_path_synthesis', label:'Attack-Path Synthesis',   type:'select',   options:['true','false'], defaultVal:'true' },
                   { key:'posture_scoring', label:'Brand-Risk Scoring',            type:'select',   options:['true','false'], defaultVal:'true' }],
  spear_phishing_engine:[{key:'campaign_name',label:'Campaign Name',               type:'text',     placeholder:'Red Team Q2', defaultVal:'' },
                   { key:'template',    label:'Template',                           type:'select',   options:['generic','finance','hr','it_support','executive'], defaultVal:'generic' }],
}

const GROUP_PARAMS = {
  recon:        [{ key:'stealth_mode',     label:'Stealth Mode',                   type:'select',   options:['off','low','high'], defaultVal:'low' }],
  web:          [{ key:'cookies',          label:'Session Cookies (optional)',      type:'password', placeholder:'session=abc; token=xyz', defaultVal:'' },
                { key:'stealth_mode',     label:'Stealth Mode',                     type:'select',   options:['off','low','high'], defaultVal:'low' }],
  ai:           [{ key:'llm_base_url',     label:'LLM Base URL',                   type:'text',     placeholder:'http://127.0.0.1:11434/v1', defaultVal:'' },
                { key:'llm_model',        label:'LLM Model',                        type:'text',     placeholder:'llama3', defaultVal:'' }],
  cloud:        [{ key:'stealth_mode',     label:'Stealth Mode',                   type:'select',   options:['off','low','high'], defaultVal:'low' }],
  ot:           [{ key:'protocol_strict',  label:'Protocol Strict Mode',           type:'select',   options:['true','false'], defaultVal:'true' }],
  stealth:      [{ key:'stealth_level',    label:'Stealth Level (1-5)',            type:'number',   placeholder:'3', defaultVal:'3', min:1, max:5 }],
  crypto:       [{ key:'stealth_mode',     label:'Stealth Mode',                   type:'select',   options:['off','low','high'], defaultVal:'low' }],
  network:      [{ key:'stealth_mode',     label:'Stealth Mode',                   type:'select',   options:['off','low','high'], defaultVal:'low' },
                { key:'ports',            label:'Port Range',                       type:'text',     placeholder:'1-1024', defaultVal:'1-1024' }],
  supply_chain: [{ key:'deep_scan',        label:'Deep Scan',                      type:'select',   options:['true','false'], defaultVal:'false' }],
  apt:          [{ key:'stealth_level',    label:'Stealth Level (1-5)',            type:'number',   placeholder:'4', defaultVal:'4', min:1, max:5 },
                { key:'techniques_filter',label:'Techniques Filter (MITRE IDs)',    type:'text',     placeholder:'T1566,T1059', defaultVal:'' }],
  malware:      [{ key:'safe_mode',        label:'Safe Mode (no real execution)',  type:'select',   options:['true','false'], defaultVal:'true' }],
  social:       [{ key:'campaign_name',    label:'Campaign Name',                  type:'text',     placeholder:'Red Team', defaultVal:'' }],
  mobile:       [{ key:'platform',         label:'Platform',                       type:'select',   options:['both','android','ios'], defaultVal:'both' }],
  data:         [{ key:'stealth_mode',     label:'Stealth Mode',                   type:'select',   options:['off','low','high'], defaultVal:'low' }],
}

function getEngineParams(engine) {
  if (!engine) return []
  const idParams = PARAM_DEFS[engine.id] || []
  const grpParams = GROUP_PARAMS[engine.group] || []
  const idKeys = new Set(idParams.map((p) => p.key))
  return [...idParams, ...grpParams.filter((p) => !idKeys.has(p.key))]
}

// ─── Terminal ──────────────────────────────────────────────────────────────────

function Terminal({ lines }) {
  const { t } = useTranslation()
  const termRef = useRef(null)
  useEffect(() => {
    if (termRef.current) {
      termRef.current.scrollTop = termRef.current.scrollHeight
    }
  }, [lines])

  const copyAll = useCallback(() => {
    navigator.clipboard?.writeText(lines.join('\n')).catch(() => {})
  }, [lines])

  return (
    <div className="relative">
      {lines.length > 0 && (
        <button type="button" onClick={copyAll}
          className="absolute top-2 right-2 z-10 text-[10px] font-mono text-white/30 hover:text-cyan-400 bg-black/60 px-2 py-1 rounded border border-white/10 transition-colors">
          Copy
        </button>
      )}
      <div ref={termRef} className="h-80 overflow-auto rounded-xl bg-black/80 border border-white/5 p-3 font-mono text-[11px] leading-relaxed">
        {lines.length === 0 ? (
          <span className="text-white/20">{t('engines.detail_terminal_idle')}</span>
        ) : (
          lines.map((line, i) => (
            <div key={i} className={
              line.includes('[ERROR]') || line.includes('ERROR')
                ? 'text-red-400'
                : line.includes('[WARN]') || line.includes('WARN')
                  ? 'text-yellow-400'
                  : line.includes('Completed') || line.includes('completed') || line.includes('[OK]')
                    ? 'text-[#4ade80]'
                    : line.includes('finding') || line.includes('FINDING')
                      ? 'text-amber-300'
                      : 'text-[#4ade80]/80'
            }>
              {line}
            </div>
          ))
        )}
      </div>
    </div>
  )
}

// ─── Dynamic param field ────────────────────────────────────────────────────────

function ParamField({ def, value, onChange, disabled }) {
  const base = 'bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40 disabled:opacity-50'
  const label = (
    <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">{def.label}</label>
  )
  if (def.type === 'select') {
    return (
      <div>
        {label}
        <select value={value} onChange={(e) => onChange(def.key, e.target.value)} disabled={disabled} className={`${base} w-full`}>
          {def.options.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
      </div>
    )
  }
  if (def.type === 'textarea') {
    return (
      <div>
        {label}
        <textarea value={value} onChange={(e) => onChange(def.key, e.target.value)} placeholder={def.placeholder} disabled={disabled} rows={3} className={`${base} w-full resize-y`} />
      </div>
    )
  }
  if (def.type === 'password') {
    return (
      <div>
        {label}
        <input type="password" autoComplete="off" value={value} onChange={(e) => onChange(def.key, e.target.value)} placeholder={def.placeholder} disabled={disabled} className={`${base} w-full`} />
      </div>
    )
  }
  if (def.type === 'number') {
    return (
      <div>
        {label}
        <input type="number" value={value} onChange={(e) => onChange(def.key, e.target.value)} placeholder={def.placeholder} min={def.min} max={def.max} disabled={disabled} className={`${base} w-36`} />
      </div>
    )
  }
  return (
    <div>
      {label}
      <input type="text" value={value} onChange={(e) => onChange(def.key, e.target.value)} placeholder={def.placeholder} disabled={disabled} className={`${base} w-full`} />
    </div>
  )
}

// ─── Findings panel ────────────────────────────────────────────────────────────

function FindingBadge({ severity }) {
  const s = (severity || 'info').toLowerCase()
  const styles = {
    critical: 'bg-red-900/60 text-red-300 border-red-700/50',
    high:     'bg-orange-900/60 text-orange-300 border-orange-700/50',
    medium:   'bg-yellow-900/60 text-yellow-300 border-yellow-700/50',
    low:      'bg-blue-900/60 text-blue-300 border-blue-700/50',
    info:     'bg-slate-800/60 text-slate-300 border-slate-600/50',
  }
  return (
    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase tracking-wider ${styles[s] || styles.info}`}>{s}</span>
  )
}

function FindingsTable({ findings }) {
  if (!findings.length) return null
  return (
    <div className="space-y-2 max-h-96 overflow-auto">
      {findings.map((f, i) => (
        <div key={i} className="rounded-lg bg-black/40 border border-white/10 p-3 space-y-1">
          <div className="flex items-start justify-between gap-2">
            <span className="text-sm font-semibold text-white/90">{f.title || f.type || 'Finding'}</span>
            <FindingBadge severity={f.severity} />
          </div>
          {f.description && <p className="text-[11px] text-white/55 font-mono leading-relaxed">{f.description}</p>}
          <div className="flex flex-wrap gap-3 mt-1">
            {f.mitre_attack && (
              <a href={`https://attack.mitre.org/techniques/${(f.mitre_attack||'').replace('.','/')}`} target="_blank" rel="noopener noreferrer" className="text-[10px] font-mono text-cyan-400 hover:underline">{f.mitre_attack}</a>
            )}
            {f.url && <span className="text-[10px] font-mono text-white/40 truncate max-w-xs">{f.url}</span>}
            {f.target && <span className="text-[10px] font-mono text-white/40">{f.target}</span>}
          </div>
        </div>
      ))}
    </div>
  )
}

function useFindings() {
  const [findings, setFindings] = useState([])
  const addFinding = useCallback((data) => {
    if (data?.type && (data.title || data.description)) {
      setFindings((prev) => [...prev, data])
    }
  }, [])
  const reset = useCallback(() => setFindings([]), [])
  return { findings, addFinding, reset }
}

// ─── Run history ───────────────────────────────────────────────────────────────

const HISTORY_KEY = (id) => `engine_run_history_${id}`
const MAX_HISTORY = 10

function loadHistory(engineId) {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY(engineId)) || '[]') } catch { return [] }
}

function saveRun(engineId, { target, status, findingsCount, jobId }) {
  const history = loadHistory(engineId)
  history.unshift({ target, status, findingsCount, jobId, ts: new Date().toISOString() })
  localStorage.setItem(HISTORY_KEY(engineId), JSON.stringify(history.slice(0, MAX_HISTORY)))
}

function StatCard({ label, value, sub, accent = '#22d3ee', icon }) {
  return (
    <div
      className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-br from-white/[0.06] to-black/50 backdrop-blur-xl p-4 transition-all duration-300 hover:border-white/15"
      style={{ boxShadow: `inset 0 1px 0 ${accent}15` }}
    >
      <div className="absolute top-0 inset-x-0 h-px opacity-60" style={{ background: `linear-gradient(90deg, transparent, ${accent}50, transparent)` }} />
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[10px] font-mono uppercase tracking-[0.18em] text-white/40 mb-1.5">{label}</p>
          <p className="text-xl font-bold text-white tracking-tight truncate">{value}</p>
          {sub && <p className="text-[10px] font-mono text-white/35 mt-1 truncate">{sub}</p>}
        </div>
        {icon && <span className="text-lg opacity-60 shrink-0">{icon}</span>}
      </div>
    </div>
  )
}

function mapServerHistoryJob(job) {
  return {
    target: job.target || '',
    status: job.status || 'unknown',
    findingsCount: job.findings_count ?? job.findingsCount ?? 0,
    jobId: job.job_id ?? job.jobId ?? '',
    ts: job.created_at ?? job.ts ?? new Date().toISOString(),
    source: job.source || 'server',
  }
}

function RunHistoryPanel({ engineId, emptyLabel }) {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [fromServer, setFromServer] = useState(false)

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      try {
        const r = await apiFetch(`/api/engines/history/${encodeURIComponent(engineId)}?limit=20`)
        const data = await r.json().catch(() => null)
        if (!cancelled && r.ok && Array.isArray(data?.jobs) && data.jobs.length > 0) {
          setHistory(data.jobs.map(mapServerHistoryJob))
          setFromServer(true)
          setLoading(false)
          return
        }
      } catch {
        /* fall through to localStorage */
      }
      if (!cancelled) {
        setHistory(loadHistory(engineId))
        setFromServer(false)
        setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [engineId])

  if (loading) return <p className="text-[11px] font-mono text-white/25">Loading run history…</p>
  if (!history.length) return <p className="text-[11px] font-mono text-white/25">{emptyLabel}</p>
  return (
    <div className="space-y-2">
      {!fromServer && (
        <p className="text-[10px] font-mono text-white/20 mb-2">Showing local browser history (server unavailable).</p>
      )}
      {history.map((r, i) => (
        <div key={i} className="flex items-center gap-3 text-[11px] font-mono text-white/50 flex-wrap">
          <span className={r.status === 'completed' ? 'text-[#4ade80]' : 'text-red-400'}>{r.status}</span>
          <span className="text-white/30">{new Date(r.ts).toLocaleString()}</span>
          {r.target && <span className="text-cyan-400/60 truncate max-w-[200px]">{r.target}</span>}
          {r.findingsCount > 0 && <span className="text-amber-300">{r.findingsCount} finding{r.findingsCount !== 1 ? 's' : ''}</span>}
          {r.jobId && <span className="text-white/20 truncate max-w-[100px]">{r.jobId}</span>}
        </div>
      ))}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function EngineDetail() {
  const { t } = useTranslation()
  const { engineId } = useParams()
  const { isProduction } = useProductionEngines()
  const engine        = ENGINES_BY_ID[engineId] ?? null
  const groupDef      = engine ? ENGINE_GROUPS[engine.group] : null
  const engineType    = getEngineType(engineId || '')
  const engineTypeMeta= ENGINE_TYPE_META[engineType] || ENGINE_TYPE_META.live_probe
  const extraParamDefs= useMemo(() => getEngineParams(engine), [engine])
  const [runHistory, setRunHistory] = useState([])
  const lastHistoryRun= runHistory[0] ?? null

  const [target, setTarget]               = useState('')
  const [timeoutSec, setTimeoutSec]       = useState(120)
  const [extraParams, setExtraParams]     = useState(() =>
    Object.fromEntries(getEngineParams(engine).map((d) => [d.key, d.defaultVal ?? '']))
  )
  const [running, setRunning]             = useState(false)
  const [lines, setLines]                 = useState([])
  const { findings, addFinding, reset: resetFindings } = useFindings()
  const [jobId, setJobId]                 = useState(null)
  const [lastRunStatus, setLastRunStatus] = useState(null)
  const esRef = useRef(null)
  const [clients, setClients]             = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [toast, setToast]                 = useState(null)
  const [activeTab, setActiveTab]         = useState('output')
  const [historyLoading, setHistoryLoading] = useState(false)

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  const reloadHistory = useCallback(async () => {
    if (!engineId) return
    setHistoryLoading(true)
    try {
      const r = await apiFetch(`/api/engines/history/${encodeURIComponent(engineId)}?limit=20`)
      const data = await r.json().catch(() => null)
      if (r.ok && Array.isArray(data?.jobs) && data.jobs.length > 0) {
        setRunHistory(data.jobs.map(mapServerHistoryJob))
        return
      }
      setRunHistory(loadHistory(engineId))
    } catch {
      setRunHistory(loadHistory(engineId))
    } finally {
      setHistoryLoading(false)
    }
  }, [engineId])

  useEffect(() => {
    reloadHistory()
  }, [engineId, lastRunStatus, reloadHistory])

  useEffect(() => {
    if (!selectedClientId) return
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    if (!client) return
    let domains = client.domains
    if (typeof domains === 'string') {
      try { domains = JSON.parse(domains) } catch { domains = [] }
    }
    const first = Array.isArray(domains) ? (domains[0] || '') : ''
    if (first) setTarget(first.startsWith('http') ? first : `https://${first}`)
  }, [selectedClientId, clients])

  useEffect(() => {
    setExtraParams(Object.fromEntries(getEngineParams(engine).map((d) => [d.key, d.defaultVal ?? ''])))
  }, [engine])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 5000)
  }, [])

  const setExtraParam = useCallback((key, val) => {
    setExtraParams((prev) => ({ ...prev, [key]: val }))
  }, [])

  const handleRun = useCallback(async () => {
    if (!isProduction(engineId)) {
      showToast('error', t('engines.catalog_only_run_disabled'))
      return
    }
    if (!selectedClientId) { showToast('error', 'Select a client first'); return }
    if (engine?.requiresTarget && !target.trim()) { showToast('error', 'Enter a target URL'); return }
    setRunning(true)
    setLines([])
    resetFindings()
    setJobId(null)
    setLastRunStatus(null)

    const body = { engine: engineId, client_id: Number(selectedClientId), timeout: timeoutSec }
    if (target.trim()) body.target = target.trim()
    for (const [k, v] of Object.entries(extraParams)) {
      if (v !== '' && v !== null && v !== undefined) body[k] = v
    }
    if (body.stealth_mode) body.stealth = body.stealth_mode
    if (body.llm_base_url) body.ai_endpoint = JSON.stringify({ base_url: body.llm_base_url, model: body.llm_model || '' })

    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        showToast('error', d.detail || d.error || `Scan failed (${r.status})`)
        setRunning(false)
        return
      }
      const jid = d.job_id || ''
      setJobId(jid)
      setLines([`> Job queued: ${jid || '(pending)'}`, `> Connecting to live stream...`])
      if (jid) {
        const streamPath = engineId === 'poe_synthesis'
          ? `/api/poe-scan/stream/${encodeURIComponent(jid)}`
          : `/api/telemetry/stream?job_id=${encodeURIComponent(jid)}`
        const url = await resolveEventSourceUrl(streamPath)
        if (esRef.current) esRef.current.close()
        const es = new EventSource(url, { withCredentials: true })
        esRef.current = es
        es.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data || '{}')
            const line = data.message || data.error || ''
            if (line) setLines((prev) => [...prev.slice(-MAX_LINES_REAL), `> ${line}`])
            if (data.finding) addFinding(data.finding)
            if (data.findings && Array.isArray(data.findings)) data.findings.forEach(addFinding)
            if (data.status === 'completed' || data.status === 'failed') {
              const status = data.status
              setLastRunStatus(status)
              setRunning(false)
              es.close()
              setLines((prev) => [...prev, `> [${status.toUpperCase()}] Job ${jid} finished.`])
            }
          } catch {}
        }
        es.onerror = () => { setRunning(false); es.close(); setLastRunStatus('error') }
      } else {
        setLines((prev) => [...prev, '> (No job stream — check backend logs)'])
        setRunning(false)
        setLastRunStatus('queued')
      }
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
      setRunning(false)
    }
  }, [selectedClientId, target, timeoutSec, engineId, engine, extraParams, showToast, resetFindings, addFinding, isProduction, t])

  const handleStop = useCallback(() => {
    if (esRef.current) { esRef.current.close(); esRef.current = null }
    setRunning(false)
    setLines((prev) => [...prev, '> [Stopped by operator]'])
    setLastRunStatus('stopped')
  }, [])

  useEffect(() => {
    if (lastRunStatus && jobId !== null) {
      saveRun(engineId, { target, status: lastRunStatus, findingsCount: findings.length, jobId: jobId || '' })
    }
  }, [lastRunStatus]) // eslint-disable-line

  useEffect(() => () => { if (esRef.current) esRef.current.close() }, [])

  const handleExport = useCallback(() => {
    const payload = {
      engine: engineId,
      label: engine?.label,
      exported_at: new Date().toISOString(),
      job_id: jobId,
      last_run_status: lastRunStatus,
      findings,
      run_history: runHistory,
    }
    const bytes = new TextEncoder().encode(JSON.stringify(payload, null, 2))
    downloadBytes(bytes, `${engineId}-export.json`, 'application/json')
    showToast('info', 'Export downloaded')
  }, [engineId, engine?.label, jobId, lastRunStatus, findings, runHistory, showToast])

  const exportFindingsCsv = useCallback(() => {
    if (!findings.length) return
    exportStandardFindingsCsv(findings, `${engineId}-findings`)
  }, [findings, engineId])

  const {
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    filteredFindings: filteredSessionFindings,
    counts: findingCounts,
  } = useFindingsWorkbench(findings, { csvPrefix: `${engineId}-findings` })

  const engineRunnable = isProduction(engineId)
  const healthLabel = engineRunnable
    ? t('engines.detail_health_live')
    : t('engines.detail_health_catalog')
  const healthAccent = isProduction(engineId) ? '#4ade80' : '#9ca3af'
  const lastRunDisplay = lastHistoryRun
    ? new Date(lastHistoryRun.ts).toLocaleString()
    : t('engines.detail_never_run')
  const totalFindings = findings.length || (lastHistoryRun?.findingsCount ?? 0)

  if (!engine) {
    return (
      <div className="min-h-[100dvh] flex flex-col items-center justify-center bg-[#030712] text-slate-300 font-mono p-8">
        <p className="text-red-400 text-lg mb-4">{t('engines.detail_unknown')}: <code>{engineId}</code></p>
        <Link to="/engines" className="text-cyan-400 hover:underline">{t('engines.detail_back_matrix')}</Link>
      </div>
    )
  }

  return (
    <div
      className="min-h-[100dvh] text-slate-100"
      style={{ background: 'radial-gradient(ellipse 120% 80% at 50% -5%, #1e293b 0%, #0f172a 40%, #020617 70%, #000 100%)' }}
    >
      <header className="sticky top-0 z-20 border-b border-white/[0.08] bg-black/65 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-3 flex-wrap min-w-0">
          <Link to="/engines" className="text-white/40 hover:text-white/70 text-xs font-mono transition-colors">
            {t('engines.detail_back_matrix')}
          </Link>
          <span className="text-white/15 text-xs">|</span>
          {groupDef && (
            <span
              className="text-[10px] font-mono px-2 py-0.5 rounded-md uppercase tracking-widest border"
              style={{ color: groupDef.color, borderColor: `${groupDef.color}40`, backgroundColor: `${groupDef.color}10` }}
            >
              {groupDef.label}
            </span>
          )}
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded-md uppercase tracking-widest border ${engineTypeMeta.bg} ${engineTypeMeta.border}`} style={{ color: engineTypeMeta.color }}>
            {engineTypeMeta.icon} {engineTypeMeta.label}
          </span>
          {isTopTierEngine(engineId) && (
            <Link to={`/engines/top-tier/${engineId}`} className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-rose-500/40 text-rose-300 hover:bg-rose-500/10">Top-Tier</Link>
          )}
          {engineId === 'nexus_sovereign_swarm' && (
            <Link to="/nexus-swarm" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-violet-500/40 text-violet-300 hover:bg-violet-500/10">Swarm Command Center</Link>
          )}
          {engineId === 'graphql_attack' && (
            <Link to="/graphql-security" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-pink-500/40 text-pink-300 hover:bg-pink-500/10">API Security Command Center</Link>
          )}
          {engineId === 'websocket_attack' && (
            <Link to="/websocket-security" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10">WebSocket Security Command Center</Link>
          )}
          {engineId === 'iac_misconfig' && (
            <Link to="/iac-security" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10">IaC Security Center</Link>
          )}
          {engineId === 'oauth_oidc' && (
            <Link to="/identity-security" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10">Identity Security Center</Link>
          )}
          {engineId === 'http_smuggling' && (
            <Link to="/http-smuggling" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-orange-500/40 text-orange-300 hover:bg-orange-500/10">HTTP Desync Posture</Link>
          )}
          {engineId === 'cache_poisoning' && (
            <Link to="/cache-posture" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-rose-500/40 text-rose-300 hover:bg-rose-500/10">Web Cache Posture</Link>
          )}
          {engineId === 'cloud_posture' && (
            <Link to="/cloud-posture" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-orange-500/40 text-orange-300 hover:bg-orange-500/10">CSPM Command Center</Link>
          )}
          {engineId === 'email_dns_posture' && (
            <Link to="/email-posture" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10">Email Trust Posture</Link>
          )}
          {engineId === 'smb_netbios' && (
            <Link to="/smb-netbios" className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-blue-500/40 text-blue-300 hover:bg-blue-500/10">SMB Command Center</Link>
          )}
          {DEDICATED_ENGINE_IDS.has(engineId) && (
            <Link to={`/engines/business/${engineId}`} className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10">Business Profile</Link>
          )}
          </div>
          <ShellScanActions
            onRefresh={reloadHistory}
            onExport={exportFindingsCsv}
            refreshLoading={historyLoading}
            exportDisabled={!findings.length}
          />
        </div>
      </header>

      {/* ── Toast ──────────────────────────────────────────────────────────── */}
      <AnimatePresence>
        {toast && (
          <motion.div key={toast.id} initial={{ opacity:0, y:-10 }} animate={{ opacity:1, y:0 }} exit={{ opacity:0, y:-10 }}
            className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${
              toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-cyan-500/30 text-cyan-200'
            }`}>
            {toast.msg}
          </motion.div>
        )}
      </AnimatePresence>

      <main className="max-w-6xl mx-auto px-4 py-8 space-y-6">
        <EvidenceNotice>{t('pages.engineDetail.evidence_notice')}</EvidenceNotice>

        {/* ── Hero header ─────────────────────────────────────────────────── */}
        <motion.section
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          className="relative overflow-hidden rounded-3xl border border-white/[0.08] bg-gradient-to-br from-white/[0.07] via-black/45 to-black/70 backdrop-blur-xl p-6 md:p-8"
        >
          <div
            className="absolute inset-x-0 top-0 h-px"
            style={{ background: `linear-gradient(90deg, transparent, ${groupDef?.color ?? '#22d3ee'}70, transparent)` }}
          />
          <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6">
            <div className="space-y-4 min-w-0 flex-1">
              <div className="flex items-center gap-3 flex-wrap">
                <h1 className="text-3xl md:text-4xl font-bold text-white tracking-tight">{engine.label}</h1>
                <code className="text-[11px] font-mono text-white/35 bg-black/40 px-2 py-0.5 rounded-md border border-white/[0.08]">{engine.id}</code>
                {running && (
                  <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2.5 py-1 rounded-md bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 animate-pulse">
                    ⟳ {t('engines.running')}
                  </span>
                )}
                {lastRunStatus && !running && (
                  <span className={`text-[10px] font-mono px-2.5 py-1 rounded-md border ${
                    lastRunStatus === 'completed' ? 'bg-green-500/10 border-green-500/30 text-green-400'
                    : lastRunStatus === 'stopped'  ? 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400'
                    : 'bg-red-500/10 border-red-500/30 text-red-400'}`}>
                    {lastRunStatus.toUpperCase()}
                  </span>
                )}
              </div>
              <p className="text-sm md:text-base text-white/55 leading-relaxed max-w-3xl">{engine.description}</p>
              <div className="flex flex-wrap gap-2">
                {engine.requiresTarget && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-white/10 text-white/40 bg-white/[0.04]">
                    {t('engines.detail_requires_target')}
                  </span>
                )}
                {engine.mitre && (
                  <a
                    href={`https://attack.mitre.org/techniques/${engine.mitre.replace('.', '/')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-white/10 text-cyan-400/80 hover:text-cyan-300 bg-cyan-500/[0.04]"
                  >
                    {engine.mitre}
                  </a>
                )}
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={handleRun}
                disabled={running || !engineRunnable}
                title={!engineRunnable ? t('engines.catalog_only_run_disabled') : undefined}
                className="px-5 py-2.5 rounded-xl font-mono text-sm font-semibold bg-cyan-500/20 border border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/30 hover:shadow-[0_0_24px_rgba(34,211,238,0.15)] disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                {running ? t('engines.running') : `▶ ${t('engines.detail_run_engine')}`}
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('history')}
                className="px-4 py-2.5 rounded-xl font-mono text-sm border border-white/12 text-white/55 hover:text-white/85 hover:border-white/25 hover:bg-white/[0.04] transition-all"
              >
                {t('engines.detail_view_history')}
              </button>
              <button
                type="button"
                onClick={handleExport}
                className="px-4 py-2.5 rounded-xl font-mono text-sm border border-emerald-500/30 text-emerald-300/90 hover:bg-emerald-500/10 hover:border-emerald-400/40 transition-all"
              >
                ↓ {t('engines.detail_export')}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-8">
            <StatCard
              label={t('engines.detail_stat_last_run')}
              value={lastRunDisplay}
              sub={lastHistoryRun?.status ? String(lastHistoryRun.status) : (jobId ? `Job ${jobId}` : undefined)}
              accent="#a78bfa"
              icon="⏱"
            />
            <StatCard
              label={t('engines.detail_stat_findings')}
              value={String(totalFindings)}
              sub={findings.length > 0 ? `${findings.length} this session` : undefined}
              accent="#f59e0b"
              icon="⚠"
            />
            <StatCard
              label={t('engines.detail_stat_health')}
              value={healthLabel}
              sub={isProduction(engineId) ? 'GET /api/engines/production' : 'Registry entry'}
              accent={healthAccent}
              icon={isProduction(engineId) ? '●' : '○'}
            />
          </div>
        </motion.section>

        {/* ── Run configuration ─────────────────────────────────────────── */}
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/[0.08] p-6 space-y-5"
        >
          <h2 className="text-xs font-mono text-white/50 uppercase tracking-widest">{t('engines.detail_run_config')}</h2>

          {/* Client */}
          <div>
            <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">Client</label>
            <select
              value={selectedClientId ?? ''}
              onChange={(e) => setSelectedClientId(e.target.value || null)}
              disabled={running}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/80 font-mono focus:outline-none focus:border-cyan-500/40"
            >
              <option value="">{t('engines.select_client')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>

          {/* Target */}
          <div>
            <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">
              {t('engines.detail_target_optional')}
            </label>
            <input type="text" value={target} onChange={(e) => setTarget(e.target.value)}
              placeholder={engine.requiresTarget ? 'https://target.com' : 'Optional — uses client scope'}
              disabled={running}
              className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40 disabled:opacity-50" />
          </div>

          {/* Timeout */}
          <div>
            <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">{t('engines.detail_timeout')}</label>
            <input type="number" value={timeoutSec} onChange={(e) => setTimeoutSec(Number(e.target.value))}
              min={10} max={3600} disabled={running}
              className="w-36 bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono focus:outline-none focus:border-cyan-500/40 disabled:opacity-50" />
          </div>

          {/* Dynamic engine parameters */}
          {extraParamDefs.length > 0 && (
            <div className="border-t border-white/5 pt-4 space-y-4">
              <div className="text-[10px] font-mono text-white/30 uppercase tracking-widest">{t('engines.detail_engine_params')}</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {extraParamDefs.map((def) => (
                  <ParamField key={def.key} def={def}
                    value={extraParams[def.key] ?? def.defaultVal ?? ''}
                    onChange={setExtraParam} disabled={running} />
                ))}
              </div>
            </div>
          )}

          {/* Action buttons */}
          <div className="flex items-center gap-3 pt-1">
            <button
              type="button"
              onClick={handleRun}
              disabled={running || !engineRunnable}
              title={!engineRunnable ? t('engines.catalog_only_run_disabled') : undefined}
              className="px-5 py-2 rounded-xl font-mono text-sm font-semibold bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {running ? t('engines.running') : `▶ ${t('engines.run_engine')}`}
            </button>
            {running && (
              <button
                type="button"
                onClick={handleStop}
                className="px-4 py-2 rounded-xl font-mono text-sm border border-red-500/30 text-red-300 hover:bg-red-950/30 transition-all"
              >
                ⏹ {t('engines.stop')}
              </button>
            )}
            {lines.length > 0 && !running && (
              <button type="button" onClick={() => { setLines([]); resetFindings(); setLastRunStatus(null) }}
                className="px-3 py-2 rounded-xl font-mono text-xs border border-white/10 text-white/30 hover:text-white/60 transition-all">
                {t('engines.detail_clear')}
              </button>
            )}
          </div>
        </motion.section>

        {/* ── Output / Findings / History tabs ─────────────────────────── */}
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 overflow-hidden"
        >
          <div className="flex border-b border-white/10">
            {[
              { id:'output',   label: t('engines.live_output'),  badge: lines.length > 0 ? lines.length : null },
              { id:'findings', label: t('engines.findings_tab'), badge: findings.length > 0 ? findings.length : null },
              { id:'history',  label: t('engines.run_history'),  badge: runHistory.length > 0 ? runHistory.length : null },
            ].map((tab) => (
              <button key={tab.id} type="button" onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-3 text-[11px] font-mono uppercase tracking-widest transition-colors flex items-center gap-2 ${
                  activeTab === tab.id ? 'text-cyan-400 border-b-2 border-cyan-500 bg-cyan-500/5' : 'text-white/40 hover:text-white/60'
                }`}>
                {tab.label}
                {tab.badge !== null && (
                  <span className={`px-1.5 py-0.5 rounded text-[9px] ${tab.id === 'findings' ? 'bg-amber-500/20 text-amber-300' : 'bg-white/10 text-white/40'}`}>
                    {tab.badge}
                  </span>
                )}
              </button>
            ))}
          </div>
          <div className="p-5">
            {activeTab === 'output'   && <Terminal lines={lines} />}
            {activeTab === 'findings' && (
              findings.length > 0
                ? (
                  <WeissmanFindingsPanel
                    findings={findings}
                    filteredFindings={filteredSessionFindings}
                    counts={findingCounts}
                    total={findings.length}
                    searchQuery={searchQuery}
                    onSearchChange={setSearchQuery}
                    severityFilter={severityFilter}
                    onSeverityChange={setSeverityFilter}
                    accent={groupDef?.color ?? '#22d3ee'}
                    title={t('engines.findings_tab')}
                    renderFinding={(f, i) => (
                      <div key={i} className="rounded-lg bg-black/40 border border-white/10 p-3 space-y-1">
                        <div className="flex items-start justify-between gap-2">
                          <span className="text-sm font-semibold text-white/90">{f.title || f.type || 'Finding'}</span>
                          <FindingBadge severity={f.severity} />
                        </div>
                        {f.description && <p className="text-[11px] text-white/55 font-mono leading-relaxed">{f.description}</p>}
                      </div>
                    )}
                  />
                )
                : <p className="text-[11px] font-mono text-white/25">{t('engines.detail_no_findings')}</p>
            )}
            {activeTab === 'history'  && <RunHistoryPanel engineId={engineId} emptyLabel={t('engines.detail_no_history')} />}
          </div>
        </motion.section>

        {/* ── Metadata + API reference ──────────────────────────────────── */}
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.14 }}
          className="grid grid-cols-1 sm:grid-cols-2 gap-4"
        >
          <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
            <h3 className="text-[10px] font-mono text-white/40 uppercase tracking-widest">{t('engines.detail_metadata')}</h3>
            <table className="w-full text-[12px] font-mono">
              <tbody className="divide-y divide-white/5">
                {[
                  ['ID', engine.id],
                  ['Group', groupDef?.label || engine.group || '—'],
                  ['Type', `${engineTypeMeta.icon} ${engineTypeMeta.label}`],
                  ['MITRE', engine.mitre || '—'],
                  ['Requires Target', engine.requiresTarget ? 'Yes' : 'Optional'],
                  ['Parameters', extraParamDefs.length > 0 ? `${extraParamDefs.length} configurable` : 'Standard only'],
                ].map(([k, v]) => (
                  <tr key={k}>
                    <td className="py-1.5 pr-4 text-white/35 w-40">{k}</td>
                    <td className="py-1.5 text-white/75">{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
            <h3 className="text-[10px] font-mono text-white/40 uppercase tracking-widest">{t('engines.detail_api_ref')}</h3>
            <p className="text-[10px] font-mono text-white/30">Trigger via REST API:</p>
            <pre className="text-[10px] font-mono text-cyan-300/80 bg-black/50 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap border border-white/5">{`POST /api/command-center/scan
{
  "engine": "${engine.id}",
  "client_id": 1,
  "target": "https://target.com"${extraParamDefs.length > 0 ? '\n  // + engine params above' : ''}
}`}</pre>
            <p className="text-[10px] font-mono text-white/30 mt-2">Stream output:</p>
            <pre className="text-[10px] font-mono text-cyan-300/80 bg-black/50 rounded-lg p-2 overflow-x-auto border border-white/5">{`GET /api/telemetry/stream?job_id={id}`}</pre>
          </div>
        </motion.section>

      </main>
    </div>
  )
}
