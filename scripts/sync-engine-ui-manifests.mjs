#!/usr/bin/env node
/**
 * Regenerate shared/engine_ui_manifests.json from legacy route map + tooling hub overrides.
 * Run: node scripts/sync-engine-ui-manifests.mjs
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const routeFile = path.join(root, 'frontend/src/lib/routeEngineId.js')

// Read manifests from current seed (source of truth after migration) or bootstrap
const seedPath = path.join(root, 'shared/engine_ui_manifests.json')
const outSeed = path.join(root, 'frontend/src/lib/engineUiManifests.seed.json')

if (!fs.existsSync(seedPath)) {
  console.error('Missing shared/engine_ui_manifests.json')
  process.exit(1)
}

const data = JSON.parse(fs.readFileSync(seedPath, 'utf8'))
fs.writeFileSync(outSeed, `${JSON.stringify(data, null, 2)}\n`)
console.log(`sync-engine-ui-manifests: ${data.manifests?.length ?? 0} manifests → frontend seed`)
