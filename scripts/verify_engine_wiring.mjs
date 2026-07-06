import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')

const gen = spawnSync('node', ['scripts/generate_engine_param_defs.mjs'], { cwd: root, encoding: 'utf8' })
if (gen.status !== 0) {
  console.error(gen.stderr || gen.stdout || 'generate_engine_param_defs.mjs failed')
  process.exit(gen.status ?? 1)
}
const frontendModule = await import(pathToFileURL(path.join(root, 'frontend/src/lib/enginesRegistry.js')).href)
const engineRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine.rs'), 'utf8')
const dispatchRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/engine_dispatch.rs'), 'utf8')
const agentAgentRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine_agent.rs'), 'utf8')
const aliasRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/alias_engine_runner.rs'), 'utf8')
const criticalInfraRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/critical_infra/mod.rs'), 'utf8')

const SPECIAL_RUNNABLE_IDS = new Set([])

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

function extractCriticalInfraIds(text) {
  const match = text.match(/pub const ENGINE_IDS: &\[&str\] = &\[(.*?)\];/s)
  if (!match) return new Set()
  return new Set([...match[1].matchAll(/"([^"]+)"/g)].map((item) => item[1]))
}

function extractAliasRunnerIds(text) {
  const start = text.indexOf('match engine_id.trim() {')
  // Match the top-level wildcard arm at 8-space indent, tolerant of both the inline
  // form (`_ => run_alias_probe(`) and the block form (`_ => {`) — the arm body was
  // refactored to a block, which previously broke this marker and the whole gate.
  const end = text.indexOf('\n        _ =>', start)
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
const criticalInfraIds = extractCriticalInfraIds(criticalInfraRs)
const aliasRunnerIds = extractAliasRunnerIds(aliasRs)
const agentRequiredIds = new Set(extractArray('AGENT_REQUIRED_ENGINES', agentAgentRs))

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
  if (criticalInfraIds.has(id)) continue
  if (agentRequiredIds.has(id)) continue
  if (dispatchIds.has(id)) continue
  if (isAliasEngine(id, resolveMap) && aliasRunnerIds.has(id)) continue
  productionWithoutExecutionPath.push(id)
}

const summary = {
  frontendTotal: frontendIds.length,
  productionTotal: productionIds.size,
  aliasTotal: resolveMap.size,
  aliasRunnerArms: aliasRunnerIds.size,
  agentRequiredTotal: agentRequiredIds.size,
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
