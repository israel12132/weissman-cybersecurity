#!/usr/bin/env node
/**
 * Engine intelligence & optimization audit — fusion catalog, pooled HTTP, multi-source intel.
 *
 * Usage: node scripts/engine_intelligence_audit.mjs
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

const fusionMod = fs.readFileSync(
  path.join(ROOT, 'fingerprint_engine/src/engine_fusion/mod.rs'),
  'utf8',
)
const probes = fs.readFileSync(
  path.join(ROOT, 'fingerprint_engine/src/engine_probes.rs'),
  'utf8',
)
const recon = fs.readFileSync(
  path.join(ROOT, 'fingerprint_engine/src/advanced_recon_engines.rs'),
  'utf8',
)
const engineRs = fs.readFileSync(
  path.join(ROOT, 'backend/weissman-core/src/models/engine.rs'),
  'utf8',
)
const dispatch = fs.readFileSync(
  path.join(ROOT, 'fingerprint_engine/src/engine_dispatch.rs'),
  'utf8',
)

const fusionIds = [...fusionMod.matchAll(/"([a-z0-9_]+)"/g)]
  .map((m) => m[1])
  .filter((id) => id.includes('_') && !id.startsWith('fusion'))

const uniqueFusion = [...new Set(
  fusionMod
    .match(/pub const FUSION_ENGINE_IDS[^[]*\[([\s\S]*?)\];/)?.[1]
    ?.matchAll(/"([^"]+)"/g)
    ?.map((m) => m[1]) ?? [],
)]

const failures = []

if (!probes.includes('static HTTP_CLIENT: OnceLock<Client>')) {
  failures.push('engine_probes.rs must use shared OnceLock HTTP client pool')
}
if (!probes.includes('pool_max_idle_per_host')) {
  failures.push('engine_probes.rs must configure connection pool idle limits')
}

if (!recon.includes('probe_urlhaus_host')) {
  failures.push('threat_intel_fusion missing URLhaus probe helper')
}
if (!recon.includes('probe_threatfox_domain')) {
  failures.push('threat_intel_fusion missing ThreatFox probe helper')
}
if (!recon.includes('probe_crt_sh_footprint')) {
  failures.push('threat_intel_fusion missing CT footprint probe helper')
}
if (!recon.includes('tokio::join!')) {
  failures.push('threat_intel_fusion must run intel sources in parallel (tokio::join!)')
}

if (!uniqueFusion.includes('threat_surface_intelligence_fusion')) {
  failures.push('threat_surface_intelligence_fusion missing from FUSION_ENGINE_IDS')
}
if (uniqueFusion.length < 7) {
  failures.push(`expected >=7 fusion engines, got ${uniqueFusion.length}`)
}

for (const id of uniqueFusion) {
  if (!engineRs.includes(`"${id}"`)) {
    failures.push(`fusion engine ${id} missing from PRODUCTION_ENGINE_IDS`)
  }
  if (!dispatch.includes(`"${id}"`)) {
    failures.push(`fusion engine ${id} missing from engine_dispatch.rs`)
  }
}

const summary = {
  ok: failures.length === 0,
  fusion_engine_count: uniqueFusion.length,
  fusion_engine_ids: uniqueFusion,
  failures,
  policy:
    'Fusion catalog wired to production; threat intel multi-source parallel; shared HTTP pool',
  checked_at: new Date().toISOString(),
}

console.log(JSON.stringify(summary, null, 2))
process.exit(failures.length === 0 ? 0 : 1)
