#!/usr/bin/env node
/**
 * CI safeguard: stealthy_persistence_evasion catalog is 500 checks,
 * wired in production + dispatch + frontend, assessment-only (no payload keywords).
 */
import fs from 'node:fs'
import path from 'node:path'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const catalog = fs.readFileSync(
  path.join(root, 'fingerprint_engine/src/stealthy_persistence_evasion/catalog.rs'),
  'utf8',
)
const engineRs = fs.readFileSync(
  path.join(root, 'backend/weissman-core/src/models/engine.rs'),
  'utf8',
)
const dispatch = fs.readFileSync(
  path.join(root, 'fingerprint_engine/src/engine_dispatch.rs'),
  'utf8',
)
const registry = fs.readFileSync(
  path.join(root, 'frontend/src/lib/enginesRegistry.js'),
  'utf8',
)
const host = fs.readFileSync(
  path.join(root, 'fingerprint_engine/src/stealthy_persistence_evasion/mod.rs'),
  'utf8',
)

const titlesChunk = catalog.slice(catalog.indexOf('const TITLES'))
const titles = [...titlesChunk.matchAll(/"T\d+(?:\.\d+)?"/g)]
if (titles.length !== 500) {
  console.error(`catalog titles: expected 500, got ${titles.length}`)
  process.exit(1)
}
if (!engineRs.includes('"stealthy_persistence_evasion"')) {
  console.error('engine.rs missing stealthy_persistence_evasion')
  process.exit(1)
}
if (!dispatch.includes('"stealthy_persistence_evasion"')) {
  console.error('engine_dispatch.rs missing arm')
  process.exit(1)
}
if (!registry.includes("id: 'stealthy_persistence_evasion'")) {
  console.error('enginesRegistry.js missing engine')
  process.exit(1)
}
const forbidden = ['syscall stub payload', 'amsi patch bytes', 'etw patch bytes', 'lsass dump']
for (const k of forbidden) {
  if (host.toLowerCase().includes(k)) {
    console.error(`forbidden payload keyword in engine: ${k}`)
    process.exit(1)
  }
}
if (!host.includes('assessment')) {
  console.error('engine must declare assessment-only mode')
  process.exit(1)
}
if (!fs.existsSync(path.join(root, 'fingerprint_engine/src/stealthy_persistence_evasion/kernel.rs'))) {
  console.error('missing kernel.rs sensors')
  process.exit(1)
}
const bulk = fs.readFileSync(path.join(root, 'crates/weissman-db/src/bulk_copy.rs'), 'utf8')
if (!bulk.includes('ON CONFLICT')) {
  console.error('bulk_copy.rs must UPSERT with ON CONFLICT')
  process.exit(1)
}
const ring = fs.readFileSync(path.join(root, 'crates/weissman-agent/src/transport/encrypted_ring.rs'), 'utf8')
if (!ring.includes('shrink_to_fit') || !ring.includes('zeroize')) {
  console.error('encrypted_ring fail-safe must zeroize and shrink_to_fit')
  process.exit(1)
}

console.log(
  JSON.stringify(
    {
      catalog_len: titles.length,
      wired: true,
      assessment_only: true,
    },
    null,
    2,
  ),
)
