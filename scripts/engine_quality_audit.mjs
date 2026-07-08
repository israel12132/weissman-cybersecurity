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

const stubEngineIds = []
for (const m of remoteRs.matchAll(
  /"([^"]+)"\s*=>\s*(probe_\w+_surface)\(engine_id, target\)\.await/g,
)) {
  const fnName = m[2]
  const fnRe = new RegExp(`async fn ${fnName}\\([^)]*\\)[\\s\\S]*?^}`, 'm')
  const fnBody = remoteRs.match(fnRe)
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

const summary = {
  ok: stubEngineIds.length === 0,
  agent_stub_remote: stubEngineIds,
  agent_stub_remote_count: stubEngineIds.length,
  policy: 'agent_required hybrid engines must emit live remote-surface findings before agent guidance',
  checked_at: new Date().toISOString(),
}

console.log(JSON.stringify(summary, null, 2))
process.exit(stubEngineIds.length === 0 ? 0 : 1)
