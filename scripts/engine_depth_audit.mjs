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

// Web — military vectors
const webChecks = [
  ['http2_attack', ['http1_client', 'http2_client', 'Connection']],
  ['api_gateway_bypass', ['probe_paths_concurrent', 'X-Original-URL']],
  ['api_rate_limit_bypass', ['X-Forwarded-For']],
  ['web_cache_poison_adv', ['X-Forwarded-Host']],
  ['browser_extension_attack', ['manifest.json', 'connect-src']],
]
for (const [engine, needles] of webChecks) {
  const block = web.slice(web.indexOf(`run_${engine}_result`))
  for (const n of needles) {
    if (!block.includes(n)) {
      failures.push(`${engine} missing military probe pattern: ${n}`)
    }
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
const ssrfBlock = cloud.slice(cloud.indexOf('try_ssrf_metadata'))
if (!ssrfBlock.includes('http_post_json') && !ssrfBlock.includes('POST body')) {
  failures.push('cloud_metadata_ssrf missing POST-body SSRF vectors')
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
