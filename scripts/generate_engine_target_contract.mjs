#!/usr/bin/env node
/**
 * Generate shared/engine_target_contract.json from frontend/src/lib/enginesRegistry.js.
 *
 * Rust scan enqueue (`engine_target_contract.rs`) include_str!'s this file so the
 * Command Center `requiresTarget` flags and HTTP 400s cannot drift.
 *
 *   node scripts/generate_engine_target_contract.mjs
 *   node scripts/generate_engine_target_contract.mjs --check
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const REGISTRY = join(ROOT, 'frontend/src/lib/enginesRegistry.js')
const OUT = join(ROOT, 'shared/engine_target_contract.json')

function parseRegistry(src) {
  const entries = []
  const re =
    /id:\s*'([^']+)'[\s\S]*?requiresTarget:\s*(true|false)/g
  let m
  while ((m = re.exec(src))) {
    entries.push({ id: m[1], requiresTarget: m[2] === 'true' })
  }
  return entries
}

function main() {
  const src = readFileSync(REGISTRY, 'utf8')
  const entries = parseRegistry(src)
  if (entries.length < 100) {
    console.error(`engine target contract: parsed only ${entries.length} engines from registry`)
    process.exit(2)
  }
  const extraTargetless = new Set([
    // Scan-only aliases not listed in enginesRegistry.js (EXTRA_SCAN_ENGINE_IDS).
    // zero_day_radar is intel-only — RouteDef requires: [].
    'zero_day_radar',
  ])
  const targetless_ids = [
    ...new Set([
      ...entries.filter((e) => !e.requiresTarget).map((e) => e.id),
      ...extraTargetless,
    ]),
  ]
  targetless_ids.sort()
  const payload = {
    generated_by: 'scripts/generate_engine_target_contract.mjs',
    engine_count: entries.length,
    targetless_ids,
  }
  const rendered = `${JSON.stringify(payload, null, 2)}\n`
  if (process.argv.includes('--check')) {
    const current = readFileSync(OUT, 'utf8')
    if (current !== rendered) {
      console.error('shared/engine_target_contract.json is stale. Run: node scripts/generate_engine_target_contract.mjs')
      process.exit(1)
    }
    console.log(`ok: ${entries.length} engines, ${targetless_ids.length} targetless`)
    return
  }
  writeFileSync(OUT, rendered)
  console.log(`wrote ${OUT} (${entries.length} engines, ${targetless_ids.length} targetless)`)
}

main()
