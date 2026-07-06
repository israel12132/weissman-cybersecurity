#!/usr/bin/env node
/**
 * Generate a machine-readable engine catalog snapshot from canonical Rust + JS sources.
 * Used by CI and auditors to verify frontend ↔ production registry parity without estimates.
 */
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const outPath = path.join(root, 'shared/engine_catalog.snapshot.json')

function extractArray(name, text) {
  const m = text.match(new RegExp(`pub const ${name}: &\\[&str\\] = &\\[(.*?)\\];`, 's'))
  if (!m) throw new Error(`Missing array: ${name}`)
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1])
}

const engineRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine.rs'), 'utf8')
const agentRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine_agent.rs'), 'utf8')
const { ENGINES_REGISTRY } = await import(pathToFileURL(path.join(root, 'frontend/src/lib/enginesRegistry.js')).href)

const productionIds = extractArray('PRODUCTION_ENGINE_IDS', engineRs)
const agentRequired = extractArray('AGENT_REQUIRED_ENGINES', agentRs)
const frontendIds = ENGINES_REGISTRY.map((e) => e.id)

const groups = {}
for (const e of ENGINES_REGISTRY) {
  groups[e.group] = (groups[e.group] || 0) + 1
}

const snapshot = {
  generated_at: new Date().toISOString(),
  source: {
    production: 'backend/weissman-core/src/models/engine.rs',
    agent_required: 'backend/weissman-core/src/models/engine_agent.rs',
    frontend: 'frontend/src/lib/enginesRegistry.js',
  },
  counts: {
    production: productionIds.length,
    frontend: frontendIds.length,
    agent_required: agentRequired.length,
    groups: Object.keys(groups).length,
  },
  groups,
  agent_required_ids: agentRequired,
  parity: {
    frontend_subset_of_production: frontendIds.every((id) => productionIds.includes(id)),
    production_subset_of_frontend: productionIds.every((id) => frontendIds.includes(id)),
    counts_match: productionIds.length === frontendIds.length,
  },
}

fs.mkdirSync(path.dirname(outPath), { recursive: true })
fs.writeFileSync(outPath, `${JSON.stringify(snapshot, null, 2)}\n`)
console.log(JSON.stringify({ ok: true, path: outPath, counts: snapshot.counts, parity: snapshot.parity }, null, 2))

if (!snapshot.parity.counts_match || !snapshot.parity.frontend_subset_of_production) {
  process.exit(1)
}
