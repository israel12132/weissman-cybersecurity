import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const frontendModule = await import(pathToFileURL(path.join(root, 'frontend/src/lib/enginesRegistry.js')).href)
const engineRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine.rs'), 'utf8')
const dispatchRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/engine_dispatch.rs'), 'utf8')

const SPECIAL_RUNNABLE_IDS = new Set(['poe_synthesis'])

function extractArray(name, text) {
  const match = text.match(new RegExp(`pub const ${name}: &\\[&str\\] = &\\[(.*?)\\];`, 's'))
  if (!match) throw new Error(`Missing array: ${name}`)
  return [...match[1].matchAll(/"([^"]+)"/g)].map((item) => item[1])
}

function extractResolveMap(text) {
  const start = text.indexOf('pub fn resolve_engine_id')
  const end = text.indexOf('\n}\n\n#[must_use]\npub fn is_production_engine_id', start)
  if (start === -1 || end === -1) throw new Error('Could not locate resolve_engine_id')
  const chunk = text.slice(start, end + 2)
  const pairs = []
  const pattern = /"([^"]+)"((?:\s*\|\s*"[^"]+")*)\s*=>\s*(?:\{\s*)?"([^"]+)"/gs
  for (const match of chunk.matchAll(pattern)) {
    pairs.push([match[1], match[3]])
    for (const alias of match[2].matchAll(/"([^"]+)"/g)) {
      pairs.push([alias[1], match[3]])
    }
  }
  return new Map(pairs)
}

function extractDispatchIds(text) {
  const start = text.indexOf('match canonical {')
  const end = text.lastIndexOf('_ => EngineResult::ok(')
  if (start === -1 || end === -1) throw new Error('Could not locate engine dispatch match')
  const chunk = text.slice(start, end)
  const ids = []
  const pattern = /\n\s*"([^"]+)"((?:\s*\|\s*"[^"]+")*)\s*=>/g
  for (const match of chunk.matchAll(pattern)) {
    ids.push(match[1])
    for (const alias of match[2].matchAll(/"([^"]+)"/g)) {
      ids.push(alias[1])
    }
  }
  return new Set(ids)
}

const frontendIds = frontendModule.ENGINES_REGISTRY.map((engine) => engine.id)
const productionIds = new Set(extractArray('PRODUCTION_ENGINE_IDS', engineRs))
const resolveMap = extractResolveMap(engineRs)
const dispatchIds = extractDispatchIds(dispatchRs)

const unresolvedFrontend = []
for (const id of frontendIds) {
  const canonical = resolveMap.get(id) || id
  const runnable = productionIds.has(canonical) || SPECIAL_RUNNABLE_IDS.has(canonical)
  if (!runnable) {
    unresolvedFrontend.push({ id, canonical })
  }
}

const productionWithoutExecutionPath = []
for (const id of productionIds) {
  if (!dispatchIds.has(id) && !SPECIAL_RUNNABLE_IDS.has(id)) {
    productionWithoutExecutionPath.push(id)
  }
}

const summary = {
  frontendTotal: frontendIds.length,
  productionTotal: productionIds.size,
  aliasTotal: resolveMap.size,
  specialRunnableTotal: SPECIAL_RUNNABLE_IDS.size,
  unresolvedFrontendCount: unresolvedFrontend.length,
  productionWithoutExecutionPathCount: productionWithoutExecutionPath.length,
}

console.log(JSON.stringify({ summary, unresolvedFrontend, productionWithoutExecutionPath }, null, 2))

if (unresolvedFrontend.length > 0 || productionWithoutExecutionPath.length > 0) {
  process.exit(1)
}