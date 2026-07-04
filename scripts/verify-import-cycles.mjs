#!/usr/bin/env node
/**
 * Fail CI if frontend import cycles reappear (TDZ / init-order crashes).
 * Run: node scripts/verify-import-cycles.mjs
 */
import { execSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const frontend = path.join(root, 'frontend')

function evaluateCycles(out) {
  if (!/Found \d+ circular/i.test(out)) return true
  const cycles = out.match(/\d+\)[^\n]+/g) || []
  // routePrefetchMap → Cockpit is a dynamic import() edge only (safe at runtime).
  const blocking = cycles.filter(
    (line) => !(line.includes('routePrefetchMap') && line.includes('Cockpit.jsx')),
  )
  if (blocking.length) {
    console.error('Import cycle check FAILED:\n', blocking.join('\n'))
    return false
  }
  console.warn('Import cycle check: ignored dynamic prefetch edge(s):')
  for (const line of cycles.filter((l) => !blocking.includes(l))) {
    console.warn(' ', line.trim())
  }
  return true
}

let out = ''
try {
  out = execSync(
    'npx --yes madge --circular src/main.jsx src/TacticalApp.jsx src/providers/ProtectedProviders.jsx src/engineC2/EngineManifestContext.jsx',
    { cwd: frontend, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  )
} catch (e) {
  out = `${e.stdout || ''}${e.stderr || ''}`
}

if (!evaluateCycles(out)) process.exit(1)

console.log('Import cycle check passed.')
console.log(out.trim().split('\n').slice(-3).join('\n'))
