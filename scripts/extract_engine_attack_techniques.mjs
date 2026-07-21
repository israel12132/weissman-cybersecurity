#!/usr/bin/env node
/**
 * Code-grounded ATT&CK extraction report. Every engine implementation tags the findings it emits
 * with `mitre: "Txxxx"`; those are the techniques the engine ACTUALLY performs. This reports the
 * per-tactic coverage impact of counting those code-grounded techniques (beyond each engine's
 * single primary registry mapping). Shared logic lives in scripts/lib/engine_attack_techniques.mjs.
 *
 *   node scripts/extract_engine_attack_techniques.mjs          # per-tactic impact report
 *   node scripts/extract_engine_attack_techniques.mjs --json    # machine-readable {id: [extra...]}
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { codeGroundedExtras } from './lib/engine_attack_techniques.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const idx = JSON.parse(fs.readFileSync(path.join(ROOT, 'scripts/data/attack_technique_index.json'), 'utf8'))
const registry = (
  await import(pathToFileURL(path.join(ROOT, 'frontend/src/lib/enginesRegistry.js')).href)
).ENGINES_REGISTRY

const { perEngine } = codeGroundedExtras(ROOT, idx, registry)

if (process.argv.includes('--json')) {
  console.log(JSON.stringify(perEngine, null, 2))
  process.exit(0)
}

const primary = new Set(registry.map((e) => e.mitre).filter(Boolean))
const withExtra = new Set(primary)
for (const list of Object.values(perEngine)) for (const t of list) withExtra.add(t)

function tacticCounts(set) {
  const c = {}
  for (const id of set) {
    const t = idx.techniques[id]
    if (!t) continue
    for (const ns of t.tactics) {
      const k = ns.split(':')[1]
      c[k] = (c[k] || 0) + 1
    }
  }
  return c
}
const before = tacticCounts(primary)
const after = tacticCounts(withExtra)

console.log(`Engines with code-grounded extra techniques: ${Object.keys(perEngine).length}`)
console.log(`Distinct techniques: primary ${primary.size} → with code-grounded extras ${withExtra.size}`)
console.log('\nPer-tactic distinct-technique delta (primary → +code):')
for (const k of Object.keys(after).sort((a, b) => after[b] - after[a])) {
  const d = (after[k] || 0) - (before[k] || 0)
  console.log(`  ${k.padEnd(24)} ${String(before[k] || 0).padStart(3)} → ${String(after[k]).padStart(3)}  ${d > 0 ? `(+${d})` : ''}`)
}
