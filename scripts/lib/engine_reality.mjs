// Shared engine-reality classification — the single source of truth for "what each catalog
// engine ID actually is", derived directly from source (no estimates). Both
// `engine_reality_audit.mjs` (the CI reality gate) and `engine_coverage_accuracy_report.mjs`
// (the breadth + accuracy proof) consume this module so the two can never disagree.
//
// Classification buckets:
//   real_probe       : canonical engine with a live dispatch arm (real network/host I/O)
//   alias            : retag that resolves to another canonical engine (same detection logic)
//   agent_required   : remote-impossible; queued on endpoint_agent_tasks until an agent is online
//   special          : routed via a non-dispatch path (async job / synthesis)
//   no_path          : in the catalog but with no execution path (must be ZERO; CI-gated)

import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

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

/**
 * Load and classify every engine directly from source.
 * @param {string} root Repository root.
 * @returns classification handles: id sets/maps plus `classify(id)`, `implFor(id)`,
 *          and the frontend registry (with group/mitre metadata).
 */
export async function loadEngineReality(root) {
  const engineRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine.rs'), 'utf8')
  const dispatchRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/engine_dispatch.rs'), 'utf8')
  const agentAgentRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine_agent.rs'), 'utf8')
  const criticalInfraRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/critical_infra/mod.rs'), 'utf8')
  const frontendModule = await import(
    pathToFileURL(path.join(root, 'frontend/src/lib/enginesRegistry.js')).href
  )

  const productionIds = extractArray('PRODUCTION_ENGINE_IDS', engineRs)
  const agentRequired = new Set(extractArray('AGENT_REQUIRED_ENGINES', agentAgentRs))
  const resolveMap = extractResolveMap(engineRs)
  const dispatchImpl = extractDispatchImpl(dispatchRs)
  const dispatchIds = new Set(dispatchImpl.keys())
  const criticalInfraIds = extractCriticalInfraIds(criticalInfraRs)
  const registry = frontendModule.ENGINES_REGISTRY
  const frontendIds = registry.map((e) => e.id)

  function classify(id) {
    if (agentRequired.has(id)) return 'agent_required'
    const canon = resolveMap.get(id) || id
    if (canon !== id) return 'alias'
    if (criticalInfraIds.has(id)) return 'real_probe'
    if (dispatchIds.has(id)) return 'real_probe'
    if (SPECIAL.has(id)) return 'special'
    return 'no_path'
  }

  function implFor(id) {
    return criticalInfraIds.has(id)
      ? 'critical_infra::dispatch'
      : dispatchImpl.get(id) || '(unknown)'
  }

  function tally(ids) {
    const buckets = { real_probe: [], alias: [], agent_required: [], special: [], no_path: [] }
    for (const id of ids) buckets[classify(id)].push(id)
    return buckets
  }

  return {
    productionIds,
    frontendIds,
    registry,
    agentRequired,
    resolveMap,
    dispatchImpl,
    dispatchIds,
    criticalInfraIds,
    classify,
    implFor,
    tally,
  }
}
