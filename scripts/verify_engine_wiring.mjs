import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const frontendModule = await import(pathToFileURL(path.join(root, 'frontend/src/lib/enginesRegistry.js')).href)
const engineRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine.rs'), 'utf8')
const dispatchRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/engine_dispatch.rs'), 'utf8')
const aliasRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/alias_engine_runner.rs'), 'utf8')

const SPECIAL_RUNNABLE_IDS = new Set(['poe_synthesis'])

function extractArray(name, text) {
  const match = text.match(new RegExp(`pub const ${name}: &\\[&str\\] = &\\[(.*?)\\];`, 's'))
  if (!match) throw new Error(`Missing array: ${name}`)
  return [...match[1].matchAll(/"([^"]+)"/g)].map((item) => item[1])
}

function extractResolveMap(text) {
  const start = text.indexOf('pub fn resolve_engine_id')
  const end = text.indexOf('pub fn is_engine_alias', start)
  if (start === -1 || end === -1) throw new Error('Could not locate resolve_engine_id')
  const chunk = text.slice(start, text.lastIndexOf('}', end) + 1)
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
  const end = text.lastIndexOf('_ => EngineResult::')
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

function extractAliasRunnerIds(text) {
  const start = text.indexOf('match engine_id.trim() {')
  const end = text.indexOf('\n        _ => run_alias_probe(', start)
  if (start === -1 || end === -1) throw new Error('Could not locate alias_engine_runner match')
  const chunk = text.slice(start, end)
  const ids = []
  const pattern = /"([^"]+)"\s*=>/g
  for (const match of chunk.matchAll(pattern)) {
    ids.push(match[1])
  }
  return new Set(ids)
}

function isAliasEngine(id, resolveMap) {
  const canonical = resolveMap.get(id) || id
  return canonical !== id
}

const frontendIds = frontendModule.ENGINES_REGISTRY.map((engine) => engine.id)
const productionIds = new Set(extractArray('PRODUCTION_ENGINE_IDS', engineRs))
const resolveMap = extractResolveMap(engineRs)
const dispatchIds = extractDispatchIds(dispatchRs)
const aliasRunnerIds = extractAliasRunnerIds(aliasRs)

const missingFromProduction = frontendIds.filter((id) => !productionIds.has(id))

const unresolvedFrontend = []
for (const id of frontendIds) {
  const canonical = resolveMap.get(id) || id
  const runnable =
    productionIds.has(id) ||
    productionIds.has(canonical) ||
    SPECIAL_RUNNABLE_IDS.has(id) ||
    SPECIAL_RUNNABLE_IDS.has(canonical)
  if (!runnable) {
    unresolvedFrontend.push({ id, canonical })
  }
}

const aliasWithoutRunner = []
for (const id of frontendIds) {
  if (!isAliasEngine(id, resolveMap)) continue
  if (!aliasRunnerIds.has(id)) {
    aliasWithoutRunner.push(id)
  }
}

const productionWithoutExecutionPath = []
for (const id of productionIds) {
  if (SPECIAL_RUNNABLE_IDS.has(id)) continue
  if (dispatchIds.has(id)) continue
  if (isAliasEngine(id, resolveMap) && aliasRunnerIds.has(id)) continue
  productionWithoutExecutionPath.push(id)
}

const summary = {
  frontendTotal: frontendIds.length,
  productionTotal: productionIds.size,
  aliasTotal: resolveMap.size,
  aliasRunnerArms: aliasRunnerIds.size,
  specialRunnableTotal: SPECIAL_RUNNABLE_IDS.size,
  missingFromProductionCount: missingFromProduction.length,
  unresolvedFrontendCount: unresolvedFrontend.length,
  aliasWithoutRunnerCount: aliasWithoutRunner.length,
  productionWithoutExecutionPathCount: productionWithoutExecutionPath.length,
}

console.log(
  JSON.stringify(
    { summary, missingFromProduction, unresolvedFrontend, aliasWithoutRunner, productionWithoutExecutionPath },
    null,
    2,
  ),
)

if (
  missingFromProduction.length > 0 ||
  unresolvedFrontend.length > 0 ||
  aliasWithoutRunner.length > 0 ||
  productionWithoutExecutionPath.length > 0
) {
  process.exit(1)
}
