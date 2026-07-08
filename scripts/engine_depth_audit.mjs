#!/usr/bin/env node
/**
 * Engine depth audit — fails if military-grade deepening regresses.
 *
 * Usage: node scripts/engine_depth_audit.mjs
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8')
}

const failures = []

const probes = read('fingerprint_engine/src/engine_probes.rs')
const web = read('fingerprint_engine/src/advanced_web_engines.rs')
const crypto = read('fingerprint_engine/src/advanced_crypto_engines.rs')
const cloud = read('fingerprint_engine/src/advanced_cloud_engines.rs')
const stealth = read('fingerprint_engine/src/advanced_stealth_engines.rs')
const agent = read('fingerprint_engine/src/agent_remote_surface.rs')
const recon = read('fingerprint_engine/src/advanced_recon_engines.rs')

// Shared infrastructure
if (!probes.includes('icmp_echo_reachable')) {
  failures.push('engine_probes.rs missing icmp_echo_reachable live probe')
}
if (!web.includes('fn web_finding_sync') || !web.includes('"correlation_hints"')) {
  failures.push('advanced_web_engines missing web_finding_sync / correlation_hints')
}
if (!web.includes('publish_http_surface')) {
  failures.push('ws_intelligence_bus or web engines missing publish_http_surface integration')
}
if (!cloud.includes('fn cloud_finding_sync') || !cloud.includes('"correlation_hints"')) {
  failures.push('advanced_cloud_engines missing cloud_finding_sync / correlation_hints')
}

// Web — military vectors (Wave 1 complete — all 25 canonical web engines)
const webChecks = [
  ['http2_attack', ['http1_client', 'http2_client', 'Connection']],
  [
    'api_gateway_bypass',
    [
      'probe_paths_concurrent',
      'X-Original-URL',
      'X-Forwarded-Prefix',
      'toxic_chain',
      'run_api_gateway_bypass_result_ctx',
      'http_surface_gateway',
    ],
  ],
  [
    'api_rate_limit_bypass',
    [
      'X-Forwarded-For',
      'True-Client-IP',
      'toxic_chain',
      'run_api_rate_limit_bypass_result_ctx',
      'GraphQL batching',
      'http_surface_rate_limit',
    ],
  ],
  [
    'web_cache_poison_adv',
    [
      'toxic_chain',
      'run_web_cache_poison_adv_result_ctx',
      'synthesize_cache_poison_vectors',
      'synthetic_zero_day',
      'probe_cache_poison_vectors_concurrent',
      'categories_hit',
    ],
  ],
  ['browser_extension_attack', ['manifest.json', 'connect-src']],
  [
    'graphql_deep_attack',
    [
      'probe_paths_concurrent',
      'depth_bomb',
      'introspection over GET',
      'Auth differential',
      'graphql-transport-ws',
      'toxic_chain',
      'persistedQuery',
      'run_graphql_deep_attack_result_ctx',
    ],
  ],
  ['grpc_reflection_attack', ['synthesize_grpc_reflection_vectors', 'toxic_chain', 'run_grpc_reflection_attack_result_ctx', 'grpc-web', 'Connect-RPC']],
  ['cors_misconfiguration', ['OPTIONS', 'null', 'toxic_chain', 'run_cors_misconfiguration_result_ctx']],
  [
    'swagger_abuse',
    [
      'synthesize_swagger_abuse_vectors',
      'toxic_chain',
      'run_swagger_abuse_result_ctx',
      'probe_openapi_operations',
      'documented_auth_bypass',
      'alternate_server_spec',
    ],
  ],
  [
    'soap_injection',
    [
      'synthesize_soap_injection_vectors',
      'toxic_chain',
      'run_soap_injection_result_ctx',
      'probe_wsdl_operations',
      'xxe_reflected',
    ],
  ],
  ['odata_injection', ['$filter', 'probe_paths_concurrent']],
  ['css_injection', ['weissman_css_probe', 'style-src']],
  ['template_injection_adv', ['<%= 7*7 %>', '*{7*7}']],
  ['http_parameter_pollution', ['semicolon', 'duplicate key']],
  ['api_mass_assignment', ['permissions', 'scope']],
  ['clickjacking_engine', ['/login', 'frame-ancestors']],
  ['subdomain_takeover', ['Shopify', 'Netlify']],
  ['graphql_subscription_attack', ['Upgrade', 'websocket']],
  ['webrtc_attack', ['iceServers', 'probe_paths_concurrent']],
  ['web3_dapp_attack', ['WalletConnect', 'probe_paths_concurrent']],
]
for (const [engine, needles] of webChecks) {
  const fnCtx = `pub async fn run_${engine}_result_ctx`
  const fnBase = `pub async fn run_${engine}_result`
  let idx = web.indexOf(fnCtx)
  if (idx < 0) {
    idx = web.indexOf(fnBase)
  }
  if (idx < 0) {
    failures.push(`web engine ${engine} missing from advanced_web_engines.rs`)
    continue
  }
  const nextSection = web.indexOf('// ──', idx + 40)
  const block =
    nextSection > idx ? web.slice(idx, nextSection) : web.slice(idx, idx + 25000)
  for (const n of needles) {
    if (!block.includes(n)) {
      failures.push(`${engine} missing military probe pattern: ${n}`)
    }
  }
}

// Strong engines — must use web_finding depth marker or delegate to deep canonical
const webStrong = ['file_inclusion_rfi', 'deserialization_net', 'nosql_deep_injection']
for (const engine of webStrong) {
  const block = web.slice(web.indexOf(`run_${engine}_result`))
  if (!block.includes('web_finding') && !block.includes('canary') && !block.includes('nosql_bypass')) {
    failures.push(`${engine} missing deep probe markers`)
  }
}

// Crypto
const cryptoChecks = [
  ['mfa_bypass_engine', ['otp', 'totp', 'verification_code']],
  ['zero_trust_bypass', ['X-Forwarded-For', '/internal']],
  ['session_fixation_adv', ['Set-Cookie', 'samesite']],
]
for (const [engine, needles] of cryptoChecks) {
  const block = crypto.slice(crypto.indexOf(`run_${engine}_result`))
  for (const n of needles) {
    if (!block.toLowerCase().includes(n.toLowerCase())) {
      failures.push(`${engine} missing military probe pattern: ${n}`)
    }
  }
}

// Cloud
const ssrfBlock = cloud.slice(cloud.indexOf('try_ssrf_metadata_ctx'))
if (!ssrfBlock.includes('http_post_json')) {
  failures.push('cloud_metadata_ssrf missing POST-body SSRF vectors')
}
const cloudMetaIdx = cloud.indexOf('try_ssrf_metadata_ctx')
const cloudMetaEnd = cloud.indexOf('// ── s3_bucket_attack')
const cloudMetaBlock =
  cloudMetaIdx >= 0 && cloudMetaEnd > cloudMetaIdx
    ? cloud.slice(cloudMetaIdx, cloudMetaEnd)
    : cloud.slice(cloud.indexOf('run_cloud_metadata_ssrf_result_ctx'))

// Cache poison synthesis module
const cacheSynth = read('fingerprint_engine/src/web_cache_poison_synthesis.rs')
if (!cacheSynth.includes('fn synthesize_cache_poison_vectors')) {
  failures.push('web_cache_poison_synthesis missing synthesize_cache_poison_vectors')
}
for (const n of ['host_override', 'url_override', 'fat_get_truncation', 'synthetic_dual_stack', 'query_unkeyed', 'accept_unkeyed', 'cdn_vendor']) {
  if (!cacheSynth.includes(n)) {
    failures.push(`web_cache_poison_synthesis missing poison category: ${n}`)
  }
}
if (!cacheSynth.includes('MAX_VECTORS_PER_URL') || !cacheSynth.includes('220')) {
  failures.push('web_cache_poison_synthesis missing high vector cap')
}
if (!cacheSynth.includes('X-Forwarded-Host')) {
  failures.push('web_cache_poison_synthesis missing X-Forwarded-Host catalog')
}
const paramPushCount = (cacheSynth.match(/push_param\(/g) ?? []).length
if (paramPushCount < 4) {
  failures.push(`web_cache_poison_synthesis param catalog too small (${paramPushCount})`)
}

// gRPC reflection synthesis module
const grpcSynth = read('fingerprint_engine/src/grpc_reflection_synthesis.rs')
if (!grpcSynth.includes('fn synthesize_grpc_reflection_vectors')) {
  failures.push('grpc_reflection_synthesis missing synthesize_grpc_reflection_vectors')
}
for (const n of [
  'reflection_v1',
  'grpc_web_proto',
  'connect_proto',
  'envoy_auth',
  'synthetic_bus_artifact',
  'reflection_list_services_frame',
  'MAX_VECTORS_PER_BASE',
]) {
  if (!grpcSynth.includes(n)) {
    failures.push(`grpc_reflection_synthesis missing: ${n}`)
  }
}
if (!grpcSynth.includes('200')) {
  failures.push('grpc_reflection_synthesis missing 200 vector cap')
}

// Swagger abuse synthesis module
const swaggerSynth = read('fingerprint_engine/src/swagger_abuse_synthesis.rs')
if (!swaggerSynth.includes('fn synthesize_swagger_abuse_vectors')) {
  failures.push('swagger_abuse_synthesis missing synthesize_swagger_abuse_vectors')
}
for (const n of [
  'spring_v3',
  'swagger_ui',
  'synthetic_bus_artifact',
  'extract_sample_paths',
  'extract_operations',
  'probe_openapi_operations',
  'probe_alternate_servers',
  'knife4j_ui',
  'postman_export',
  'MAX_VECTORS_PER_BASE',
  'analyze_openapi_body',
]) {
  if (!swaggerSynth.includes(n)) {
    failures.push(`swagger_abuse_synthesis missing: ${n}`)
  }
}
if (!swaggerSynth.includes('280')) {
  failures.push('swagger_abuse_synthesis missing 280 vector cap')
}

// SOAP injection synthesis module
const soapSynth = read('fingerprint_engine/src/soap_injection_synthesis.rs')
if (!soapSynth.includes('fn synthesize_soap_injection_vectors')) {
  failures.push('soap_injection_synthesis missing synthesize_soap_injection_vectors')
}
for (const n of [
  'xxe_doctype',
  'ws_security',
  'axis2_list',
  'probe_wsdl_operations',
  'extract_wsdl_operations',
  'synthetic_bus_artifact',
  'MAX_VECTORS_PER_BASE',
]) {
  if (!soapSynth.includes(n)) {
    failures.push(`soap_injection_synthesis missing: ${n}`)
  }
}
if (!soapSynth.includes('260')) {
  failures.push('soap_injection_synthesis missing 260 vector cap')
}
for (const n of [
  'toxic_chain',
  'X-Forwarded-Host',
  'run_cloud_metadata_ssrf_result_ctx',
  'http_surface_metadata',
]) {
  if (!cloudMetaBlock.includes(n)) {
    failures.push(`cloud_metadata_ssrf missing military probe pattern: ${n}`)
  }
}
if (!cloud.slice(cloud.indexOf('run_lambda_escape_result')).includes('2015-03-31')) {
  failures.push('lambda_escape missing Lambda runtime API path probes')
}

// Stealth — fixed misaligned probes
if (stealth.includes('missing_header_finding') && stealth.includes('run_icmp_covert_result')) {
  const icmpBlock = stealth.slice(
    stealth.indexOf('run_icmp_covert_result'),
    stealth.indexOf('run_rop_chain_engine_result'),
  )
  if (icmpBlock.includes('missing_header_finding')) {
    failures.push('icmp_covert still uses wrong missing-header probe')
  }
}
if (!stealth.slice(stealth.indexOf('run_log_tampering_engine_result')).includes('/kibana')) {
  failures.push('log_tampering_engine missing SIEM path crawl')
}

// Agent remote — military hybrid
const agentChecks = [
  ['probe_icmp_covert_surface', ['icmp_echo_reachable']],
  ['probe_rootkit_surface', ['/proc']],
  ['probe_memory_forensics_surface', ['pprof', 'core']],
  ['probe_edr_av_surface', ['crowdstrike', 'x-waf', 'x-cdn']],
]
for (const [fn, needles] of agentChecks) {
  const block = agent.slice(agent.indexOf(`async fn ${fn}`))
  for (const n of needles) {
    if (!block.includes(n)) {
      failures.push(`${fn} missing military pattern: ${n}`)
    }
  }
}

// Recon — passive DNS depth
if (!recon.slice(recon.indexOf('run_passive_dns_forensics_result')).includes('dns_ns')) {
  failures.push('passive_dns_forensics missing NS/SOA depth')
}

const summary = {
  ok: failures.length === 0,
  failures,
  policy: 'Military-grade minimum probe depth per wave-1..5 canonical engines',
  checked_at: new Date().toISOString(),
}

console.log(JSON.stringify(summary, null, 2))
process.exit(failures.length === 0 ? 0 : 1)
