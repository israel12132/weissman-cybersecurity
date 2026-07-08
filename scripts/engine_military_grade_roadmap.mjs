#!/usr/bin/env node
/**
 * Military-grade engine improvement roadmap — 564 engines in phased batches.
 * Tracks depth tier targets and acceptance criteria per batch.
 *
 * Usage:
 *   node scripts/engine_military_grade_roadmap.mjs
 *   node scripts/engine_military_grade_roadmap.mjs --batch web
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const { ENGINES_REGISTRY } = await import(
  `file://${path.join(ROOT, 'frontend/src/lib/enginesRegistry.js')}`
)

/** Depth tiers — every engine must reach T4 (military) */
const TIERS = {
  T0: 'no_path / stub',
  T1: 'pure delegate (alias only)',
  T2: 'single-vector shallow (header-only / one GET)',
  T3: 'multi-path live probes (3+ vectors, honest empty_ok)',
  T4: 'military — parallel probes, toxic-chain synthesis, agent+remote corroboration',
}

const BATCHES = [
  {
    id: 'web',
    wave: 1,
    files: ['fingerprint_engine/src/advanced_web_engines.rs'],
    canonical_ids: [
      'graphql_deep_attack', 'grpc_reflection_attack', 'cors_misconfiguration',
      'http2_attack', 'swagger_abuse', 'soap_injection', 'template_injection_adv',
      'file_inclusion_rfi', 'deserialization_net', 'nosql_deep_injection',
      'subdomain_takeover', 'odata_injection', 'web_cache_poison_adv',
      'clickjacking_engine', 'css_injection', 'http_parameter_pollution',
      'api_mass_assignment', 'graphql_subscription_attack', 'webrtc_attack',
      'web3_dapp_attack', 'api_gateway_bypass', 'browser_extension_attack',
      'api_rate_limit_bypass', 'jwt_advanced_attack', 'idor_advanced',
    ],
    acceptance: '≥5 probe vectors OR delegate to deep canonical; parallel path crawl; no header-only positives',
    target_tier: 'T4',
  },
  {
    id: 'cloud',
    wave: 2,
    files: ['fingerprint_engine/src/advanced_cloud_engines.rs'],
    canonical_ids: [
      'cloud_metadata_ssrf', 's3_bucket_attack', 'lambda_escape',
      'kubernetes_rbac_escape', 'secrets_manager_attack', 'terraform_state_attack',
      'cloudformation_injection', 'azure_devops_attack', 'service_mesh_attack',
      'cloud_audit_evasion', 'multi_cloud_pivot', 'cloud_iam_escalation',
      'gcp_privilege_attack', 'ecr_registry_attack', 'cloud_worm_propagation',
      'serverless_injection', 'cloud_data_exfil', 'eks_attack',
      'cloud_network_attack', 'cloud_privilege_persistence',
    ],
    acceptance: 'IMDSv2 POST+header SSRF; multi-cloud enumeration; K8s RBAC depth; no thin wrapper delegates',
    target_tier: 'T4',
  },
  {
    id: 'crypto',
    wave: 3,
    files: ['fingerprint_engine/src/advanced_crypto_engines.rs'],
    canonical_ids: [
      'padding_oracle_attack', 'hash_extension_attack', 'mfa_bypass_engine',
      'zero_trust_bypass', 'session_fixation_adv', 'ecdsa_nonce_bias',
      'rsa_timing_attack', 'credential_stuffing', 'kerberos_attack_suite',
      'pki_hierarchy_attack', 'password_hash_crack', 'oauth_advanced_attack',
      'saml_advanced_attack', 'quantum_key_attack', 'password_spray_advanced',
    ],
    acceptance: 'Dedicated advanced-layer probes for former delegates; MFA/ZTNA multi-vector; timing oracles',
    target_tier: 'T4',
  },
  {
    id: 'recon',
    wave: 4,
    files: ['fingerprint_engine/src/advanced_recon_engines.rs'],
    canonical_ids: [
      'threat_intel_fusion', 'attack_surface_quantify', 'passive_dns_forensics',
      'dark_web_monitor', 'darkweb_intel', 'github_secret_scan',
      'satellite_recon', 'financial_osint', 'blockchain_trace', 'metadata_harvest',
      'patent_recon', 'telecom_osint', 'job_posting_osint',
      'adversarial_threat_emulation',
    ],
    acceptance: 'Parallel multi-source intel; passive DNS history; quantified ASM scoring',
    target_tier: 'T4',
  },
  {
    id: 'stealth_agent',
    wave: 5,
    files: [
      'fingerprint_engine/src/advanced_stealth_engines.rs',
      'fingerprint_engine/src/agent_remote_surface.rs',
    ],
    canonical_ids: [
      'living_off_land', 'dns_tunneling_c2', 'https_c2_masquerade', 'icmp_covert',
      'log_tampering_engine', 'process_hollowing', 'dll_hijacking_engine',
      'av_bypass_engine', 'rootkit_surface_probe', 'memory_forensics_evasion',
      'anti_debug_evasion', 'steganography_c2',
    ],
    acceptance: 'Agent hybrid remote = real protocol probes; fix misaligned ICMP/log probes; no EDR-header-only rootkit',
    target_tier: 'T4',
  },
  {
    id: 'network_ot_supply',
    wave: 6,
    files: [
      'fingerprint_engine/src/advanced_network_engines.rs',
      'fingerprint_engine/src/advanced_ot_engines.rs',
      'fingerprint_engine/src/advanced_supply_chain_engines.rs',
    ],
    acceptance: 'Protocol-specific binary probes; OT port fingerprints; registry typosquat depth',
    target_tier: 'T4',
  },
  {
    id: 'social_mobile_malware',
    wave: 7,
    files: [
      'fingerprint_engine/src/advanced_social_engines.rs',
      'fingerprint_engine/src/advanced_mobile_engines.rs',
      'fingerprint_engine/src/advanced_malware_engines.rs',
    ],
    acceptance: 'Live OSINT + HTTP surface; mobile API paths; C2 fingerprint depth',
    target_tier: 'T4',
  },
  {
    id: 'fusion_synthesis',
    wave: 8,
    files: ['fingerprint_engine/src/engine_fusion/'],
    canonical_ids: [
      'external_exposure_supreme', 'fair_exposure_fusion',
      'threat_surface_intelligence_fusion', 'identity_attack_chain',
      'pipeline_to_runtime_risk', 'risk_superposition_collapse',
      'sovereign_active_defense_fusion',
    ],
    acceptance: '≥2 evidence domains; toxic-chain synthesis; grade roll-up',
    target_tier: 'T4',
  },
  {
    id: 'dedicated_modules',
    wave: 9,
    files: ['fingerprint_engine/src/*_engine.rs'],
    acceptance: 'Every standalone engine module: ≥3 live probe vectors, MITRE-mapped evidence',
    target_tier: 'T4',
  },
]

const batchArg = process.argv.find((a) => a.startsWith('--batch='))?.split('=')[1]
  ?? (process.argv.includes('--batch') ? process.argv[process.argv.indexOf('--batch') + 1] : null)

const registryIds = new Set(ENGINES_REGISTRY.map((e) => e.id))
const cataloged = ENGINES_REGISTRY.length

const batchReport = BATCHES.filter((b) => !batchArg || b.id === batchArg).map((b) => {
  const ids = b.canonical_ids ?? []
  const inRegistry = ids.filter((id) => registryIds.has(id))
  return {
    batch: b.id,
    wave: b.wave,
    target_tier: b.target_tier,
    acceptance: b.acceptance,
    canonical_count: ids.length || 'all_in_file',
    wired_in_registry: inRegistry.length,
    files: b.files,
  }
})

const allCanonical = new Set(BATCHES.flatMap((b) => b.canonical_ids ?? []))
const uncovered = [...registryIds].filter((id) => !allCanonical.has(id))

const plan = {
  vision: 'חבת וייסמן — כל 564 מנועים ברמת T4 צבאית: live-only, multi-vector, zero stubs',
  tiers: TIERS,
  catalog_engines: cataloged,
  batches: batchReport,
  waves_total: BATCHES.length,
  engines_in_named_batches: allCanonical.size,
  engines_remaining_wave9: uncovered.length,
  execution_order: BATCHES.map((b) => `Wave ${b.wave}: ${b.id}`),
  verify_after_each_wave: [
    'node scripts/engine_depth_audit.mjs',
    'node scripts/engine_quality_audit.mjs',
    'node scripts/engine_intelligence_audit.mjs',
    'node scripts/verify_engine_wiring.mjs',
    'cargo check -p fingerprint_engine',
  ],
  generated_at: new Date().toISOString(),
}

console.log(JSON.stringify(plan, null, 2))
