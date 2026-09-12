#!/usr/bin/env node
/**
 * Engine quality depth audit — agent hybrid engines must not use empty remote stubs.
 *
 * Usage: node scripts/engine_quality_audit.mjs
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const remoteRs = fs.readFileSync(
  path.join(ROOT, 'fingerprint_engine/src/agent_remote_surface.rs'),
  'utf8',
)
const agentRs = fs.readFileSync(
  path.join(ROOT, 'backend/weissman-core/src/models/engine_agent.rs'),
  'utf8',
)

function extractArray(name, text) {
  const match = text.match(new RegExp(`pub const ${name}: &\\[&str\\] = &\\[(.*?)\\];`, 's'))
  if (!match) throw new Error(`Missing array: ${name}`)
  return [...match[1].matchAll(/"([^"]+)"/g)].map((item) => item[1])
}

const stubEngineIds = []
for (const m of remoteRs.matchAll(
  /"([^"]+)"\s*=>\s*(probe_\w+_surface)\(engine_id, target\)\.await/g,
)) {
  const fnName = m[2]
  const fnRe = new RegExp(`async fn ${fnName}\\([^)]*\\)[\\s\\S]*?^}`, 'm')
  // `String.match` returns an Array; `.includes` on it tests element equality, not
  // substring — so the stub check was a silent no-op. Use the matched string (index 0).
  const fnMatch = remoteRs.match(fnRe)
  const fnBody = fnMatch ? fnMatch[0] : null
  if (
    fnBody &&
    fnBody.includes('collect(engine_id, target, vec![])') &&
    !fnBody.includes('probe_paths_concurrent') &&
    !fnBody.includes('tcp_scan') &&
    !fnBody.includes('dns_')
  ) {
    stubEngineIds.push(m[1])
  }
}

const matchStart = remoteRs.indexOf('match engine_id {')
const matchEnd = remoteRs.indexOf('other =>', matchStart)
if (matchStart < 0 || matchEnd < 0) {
  console.error('could not locate run_remote_surface_probe match')
  process.exit(1)
}
const matchChunk = remoteRs.slice(matchStart, matchEnd)
const agentIds = extractArray('AGENT_REQUIRED_ENGINES', agentRs)
const missingArms = agentIds.filter((id) => !matchChunk.includes(`"${id}"`))

const ok = stubEngineIds.length === 0 && missingArms.length === 0
const summary = {
  ok,
  agent_stub_remote: stubEngineIds,
  agent_stub_remote_count: stubEngineIds.length,
  agent_required_missing_match_arm: missingArms,
  agent_required_missing_match_arm_count: missingArms.length,
  policy:
    'agent_required hybrid engines must have a live remote-surface match arm and must not emit empty stub findings',
  checked_at: new Date().toISOString(),
}

console.log(JSON.stringify(summary, null, 2))
process.exit(ok ? 0 : 1)
