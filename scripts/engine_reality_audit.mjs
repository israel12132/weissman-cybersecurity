// Engine reality audit — derives, directly from source, exactly what each catalog engine ID is:
//   real_probe       : canonical engine with a live dispatch arm (real network/host I/O)
//   alias            : retag that resolves to another canonical engine (same detection logic)
//   agent_required   : remote-impossible; returns an info finding pointing to the endpoint agent
//   special          : poe_synthesis (routed via the async job path, not the dispatch match)
//   no_path          : in the catalog but with no execution path (should be ZERO; CI-gated)
//
// It also maps every dispatch arm to its implementation function so duplicate IDs sharing one
// implementation (delegates) are counted precisely. No estimates — everything is parsed from code.

import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const engineRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine.rs'), 'utf8')
const dispatchRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/engine_dispatch.rs'), 'utf8')
const agentDispatchRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/engine_dispatch_agent.rs'), 'utf8')
const aliasRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/alias_engine_runner.rs'), 'utf8')
const criticalInfraRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/critical_infra/mod.rs'), 'utf8')
const frontendModule = await import(pathToFileURL(path.join(root, 'frontend/src/lib/enginesRegistry.js')).href)

const SPECIAL = new Set([])

function extractCriticalInfraIds(text) {
  const match = text.match(/pub const ENGINE_IDS: &\[&str\] = &\[(.*?)\];/s)
  if (!match) return new Set()
  return new Set([...match[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]))
}

function extractArray(name, text) {
  const m = text.match(new RegExp(`pub const ${name}: &\\[&str\\] = &\\[(.*?)\\];`, 's'))
  if (!m) throw new Error(`Missing array: ${name}`)
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1])
}

function extractResolveMap(text) {
  const start = text.indexOf('pub fn resolve_engine_id')
  const end = text.indexOf('pub fn is_engine_alias', start)
  const chunk = text.slice(start, text.lastIndexOf('}', end) + 1)
  const map = new Map()
  const pattern = /"([^"]+)"((?:\s*\|\s*"[^"]+")*)\s*=>\s*(?:\{\s*)?"([^"]+)"/gs
  for (const m of chunk.matchAll(pattern)) {
    map.set(m[1], m[3])
    for (const a of m[2].matchAll(/"([^"]+)"/g)) map.set(a[1], m[3])
  }
  return map
}

// Map each dispatch id -> implementation function (module::fn). Arms may union several ids.
function extractDispatchImpl(text) {
  const start = text.indexOf('match canonical {')
  const end = text.lastIndexOf('_ => EngineResult::')
  const chunk = text.slice(start, end)
  const armStart = /\n\s*"([^"]+)"((?:\s*\|\s*"[^"]+")*)\s*=>/g
  const matches = [...chunk.matchAll(armStart)]
  const idToImpl = new Map()
  for (let i = 0; i < matches.length; i += 1) {
    const m = matches[i]
    const ids = [m[1], ...[...m[2].matchAll(/"([^"]+)"/g)].map((a) => a[1])]
    const bodyStart = m.index + m[0].length
    const bodyEnd = i + 1 < matches.length ? matches[i + 1].index : chunk.length
    const body = chunk.slice(bodyStart, bodyEnd)
    const fn = body.match(/crate::([A-Za-z0-9_]+)::([A-Za-z0-9_]+)/)
    const impl = fn ? `${fn[1]}::${fn[2]}` : '(inline)'
    for (const id of ids) idToImpl.set(id, impl)
  }
  return idToImpl
}

const productionIds = extractArray('PRODUCTION_ENGINE_IDS', engineRs)
const agentRequired = new Set(extractArray('AGENT_REQUIRED_ENGINES', agentDispatchRs))
const resolveMap = extractResolveMap(engineRs)
const dispatchImpl = extractDispatchImpl(dispatchRs)
const dispatchIds = new Set(dispatchImpl.keys())
const criticalInfraIds = extractCriticalInfraIds(criticalInfraRs)
const frontendIds = frontendModule.ENGINES_REGISTRY.map((e) => e.id)

function classify(id) {
  if (agentRequired.has(id)) return 'agent_required'
  const canon = resolveMap.get(id) || id
  if (canon !== id) return 'alias'
  if (criticalInfraIds.has(id)) return 'real_probe'
  if (dispatchIds.has(id)) return 'real_probe'
  if (SPECIAL.has(id)) return 'special'
  return 'no_path'
}

function tally(ids) {
  const buckets = { real_probe: [], alias: [], agent_required: [], special: [], no_path: [] }
  for (const id of ids) buckets[classify(id)].push(id)
  return buckets
}

const prod = tally(productionIds)
const fe = tally(frontendIds)

// Distinct real implementations behind the real_probe IDs (delegates share one impl fn).
const implCount = new Map()
for (const id of prod.real_probe) {
  const impl = criticalInfraIds.has(id)
    ? 'critical_infra::dispatch'
    : dispatchImpl.get(id) || '(unknown)'
  implCount.set(impl, (implCount.get(impl) || 0) + 1)
}
const distinctImpls = implCount.size
const sharedImpls = [...implCount.entries()]
  .filter(([, n]) => n > 1)
  .sort((a, b) => b[1] - a[1])

// Which canonical engines absorb the most aliases.
const aliasByCanonical = new Map()
for (const id of prod.alias) {
  const canon = resolveMap.get(id)
  aliasByCanonical.set(canon, (aliasByCanonical.get(canon) || 0) + 1)
}
const topAliasCanonicals = [...aliasByCanonical.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15)

const out = {
  production: {
    total: productionIds.length,
    real_probe: prod.real_probe.length,
    distinct_real_implementations: distinctImpls,
    alias: prod.alias.length,
    agent_required: prod.agent_required.length,
    special: prod.special.length,
    no_path: prod.no_path.length,
  },
  frontend_catalog: {
    total: frontendIds.length,
    real_probe: fe.real_probe.length,
    alias: fe.alias.length,
    agent_required: fe.agent_required.length,
    special: fe.special.length,
    no_path: fe.no_path.length,
  },
  delegates_sharing_one_impl: sharedImpls.slice(0, 20).map(([impl, n]) => ({ impl, ids: n })),
  delegate_id_count: sharedImpls.reduce((s, [, n]) => s + (n - 1), 0),
  top_alias_absorbers: topAliasCanonicals.map(([canon, n]) => ({ canonical: canon, aliases: n })),
  agent_required_ids: [...agentRequired].filter((id) => productionIds.includes(id)).sort(),
  no_path_ids: prod.no_path,
}

console.log(JSON.stringify(out, null, 2))

if (prod.no_path.length > 0) {
  process.exit(1)
}
