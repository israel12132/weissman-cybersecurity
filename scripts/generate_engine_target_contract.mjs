#!/usr/bin/env node
/**
 * Single requiresTarget contract: enginesRegistry.js → shared JSON consumed by
 * Rust scan enqueue (`engine_target_contract.rs`) and the wiring gate.
 *
 * Run: node scripts/generate_engine_target_contract.mjs
 * Check: node scripts/generate_engine_target_contract.mjs --check
 */
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')

function extractArray(name, text) {
  const m = text.match(new RegExp(`pub const ${name}: &\\[&str\\]\\s*=\\s*&\\[(.*?)\\];`, 's'))
  if (!m) throw new Error(`Missing array: ${name}`)
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1])
}

const engineRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine.rs'), 'utf8')
const scanRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/scan_routing.rs'), 'utf8')
const { ENGINES_REGISTRY } = await import(
  pathToFileURL(path.join(root, 'frontend/src/lib/enginesRegistry.js')).href
)

const productionIds = extractArray('PRODUCTION_ENGINE_IDS', engineRs)
const extraIds = extractArray('EXTRA_SCAN_ENGINE_IDS', scanRs)

const registryById = Object.fromEntries(ENGINES_REGISTRY.map((e) => [e.id, e]))

/** Extra scan IDs that are not in the frontend registry. */
const EXTRA_REQUIRES_TARGET = {
  ollama_fuzz: true,
  zero_day_radar: false,
  pipeline: true,
  poe_synthesis: true,
}

const requiresTarget = {}
const targetless = []

for (const id of productionIds) {
  const flag = registryById[id]?.requiresTarget !== false
  requiresTarget[id] = flag
  if (!flag) targetless.push(id)
}

for (const id of extraIds) {
  if (Object.prototype.hasOwnProperty.call(requiresTarget, id)) continue
  const fromRegistry = registryById[id]
  const flag =
    fromRegistry && typeof fromRegistry.requiresTarget === 'boolean'
      ? fromRegistry.requiresTarget
      : EXTRA_REQUIRES_TARGET[id] !== false
  requiresTarget[id] = flag
  if (!flag) targetless.push(id)
}

targetless.sort()

const missingFromRegistry = productionIds.filter((id) => !registryById[id])
if (missingFromRegistry.length) {
  console.error(`PRODUCTION_ENGINE_IDS missing from enginesRegistry.js: ${missingFromRegistry.join(', ')}`)
  process.exit(1)
}

const extraUnknown = extraIds.filter(
  (id) => !registryById[id] && !Object.prototype.hasOwnProperty.call(EXTRA_REQUIRES_TARGET, id),
)
if (extraUnknown.length) {
  console.error(`EXTRA_SCAN_ENGINE_IDS need an explicit requiresTarget: ${extraUnknown.join(', ')}`)
  process.exit(1)
}

const out = {
  version: 1,
  source: 'frontend/src/lib/enginesRegistry.js#requiresTarget',
  production_engine_count: productionIds.length,
  requires_target_count: productionIds.filter((id) => requiresTarget[id]).length,
  targetless_count: targetless.length,
  targetless_ids: targetless,
  extra_scan_ids: extraIds.filter((id) => !productionIds.includes(id)),
}

const body = `${JSON.stringify(out, null, 2)}\n`
const outPath = path.join(root, 'shared/engine_target_contract.json')

if (process.argv.includes('--check')) {
  const existing = fs.existsSync(outPath) ? fs.readFileSync(outPath, 'utf8') : ''
  if (existing !== body) {
    console.error(
      `✖ ${path.relative(root, outPath)} is out of date vs enginesRegistry.js requiresTarget.\n` +
        '  Run: node scripts/generate_engine_target_contract.mjs  (and commit the result).',
    )
    process.exit(1)
  }
  console.log(
    `✓ ${path.relative(root, outPath)} is up to date (${out.targetless_count} targetless / ${out.requires_target_count} require target)`,
  )
  process.exit(0)
}

fs.mkdirSync(path.dirname(outPath), { recursive: true })
fs.writeFileSync(outPath, body)
console.log(
  `Wrote ${outPath} (${out.production_engine_count} production, ${out.targetless_count} targetless, ${out.requires_target_count} require target)`,
)
