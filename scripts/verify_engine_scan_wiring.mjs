#!/usr/bin/env node
/**
 * Verifies command-center scan wiring:
 * - No raw POST /api/command-center/scan in pages (use postScan / launchEngineScan)
 * - Production engines have parameter schemas via getEngineParams()
 */
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const pagesDir = path.join(root, 'frontend/src/pages')

const gen = spawnSync('node', ['scripts/generate_engine_param_defs.mjs'], { cwd: root, encoding: 'utf8' })
if (gen.status !== 0) {
  console.error(gen.stderr || gen.stdout || 'generate_engine_param_defs.mjs failed')
  process.exit(gen.status ?? 1)
}

const pageFiles = fs.readdirSync(pagesDir).filter((f) => f.endsWith('.jsx'))
const violations = []

for (const file of pageFiles) {
  const full = path.join(pagesDir, file)
  const text = fs.readFileSync(full, 'utf8')
  if (text.includes('function firstClientTarget(')) {
    violations.push(`${file}: local firstClientTarget — import from lib/clientTarget.js`)
  }
  if (text.includes("apiFetch('/api/command-center/scan") || text.includes('apiFetch("/api/command-center/scan')) {
    violations.push(`${file}: raw apiFetch to /api/command-center/scan`)
  }
  if (text.includes('fetch(`/api/command-center/scan') || text.includes("fetch('/api/command-center/scan")) {
    violations.push(`${file}: raw fetch to /api/command-center/scan`)
  }
}

const hubPages = pageFiles.filter((f) => {
  const text = fs.readFileSync(path.join(pagesDir, f), 'utf8')
  return text.includes('useCommandCenterScan')
})

const engineRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine.rs'), 'utf8')
const productionMatch = engineRs.match(/pub const PRODUCTION_ENGINE_IDS: &\[\&str\] = &\[(.*?)\];/s)
const productionIds = productionMatch
  ? [...productionMatch[1].matchAll(/"([^"]+)"/g)].map((m) => m[1])
  : []

const paramModule = await import(pathToFileURL(path.join(root, 'frontend/src/lib/engineParamDefs.js')).href)
const missingParams = productionIds.filter((id) => {
  const schema = paramModule.getEngineParams({ id })
  return !schema?.length
})

if (violations.length) {
  console.error('verify_engine_scan_wiring: FAIL (raw scan API)')
  for (const v of violations) console.error(`  - ${v}`)
  process.exit(1)
}

if (missingParams.length) {
  console.error('verify_engine_scan_wiring: FAIL (missing param schemas)')
  for (const id of missingParams.slice(0, 20)) console.error(`  - ${id}`)
  if (missingParams.length > 20) console.error(`  ... and ${missingParams.length - 20} more`)
  process.exit(1)
}

console.log(
  `verify_engine_scan_wiring: OK (${hubPages.length} hub pages, ${productionIds.length} engines with params, 0 raw scan API)`,
)
