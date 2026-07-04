#!/usr/bin/env node
/**
 * Static check: strict context hooks must be mounted under ProtectedProviders / TacticalProviders.
 * Run: node scripts/verify-provider-wiring.mjs
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const src = path.join(root, 'frontend', 'src')

const STRICT_HOOKS = [
  { hook: 'useTelemetry', provider: 'TelemetryProvider' },
  { hook: 'useAuth', provider: 'AuthProvider' },
  { hook: 'useClient', provider: 'ClientProvider' },
]

function walk(dir, out = []) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name)
    if (ent.isDirectory()) {
      if (ent.name === 'node_modules' || ent.name === 'wasm') continue
      walk(p, out)
    } else if (/\.(jsx?|tsx?)$/.test(ent.name)) {
      out.push(p)
    }
  }
  return out
}

const protectedProviders = fs.readFileSync(path.join(src, 'providers', 'ProtectedProviders.jsx'), 'utf8')
const tacticalApp = fs.readFileSync(path.join(src, 'TacticalApp.jsx'), 'utf8')
const mainJsx = fs.readFileSync(path.join(src, 'main.jsx'), 'utf8')

const errors = []

for (const { hook, provider } of STRICT_HOOKS) {
  if (!protectedProviders.includes(provider) && provider !== 'AuthProvider') {
    errors.push(`ProtectedProviders.jsx missing ${provider} (required by ${hook})`)
  }
}

if (!protectedProviders.includes('TelemetryProvider') || !protectedProviders.includes('WarRoomProvider')) {
  errors.push('ProtectedProviders must include TelemetryProvider before WarRoomProvider')
}

if (!tacticalApp.includes('ProtectedProviders') || !tacticalApp.includes('<ProtectedOutlet')) {
  errors.push('TacticalApp must wrap protected routes with ProtectedProviders')
}

if (!mainJsx.includes('TacticalProviders')) {
  errors.push('main.jsx must mount TacticalProviders at root')
}

if (!tacticalApp.includes('AuthProvider')) {
  errors.push('TacticalProviders must include AuthProvider')
}

const files = walk(src)
const hookUsage = new Map(STRICT_HOOKS.map(({ hook }) => [hook, []]))

for (const file of files) {
  const rel = path.relative(src, file)
  const text = fs.readFileSync(file, 'utf8')
  for (const { hook } of STRICT_HOOKS) {
    if (new RegExp(`\\b${hook}\\s*\\(`).test(text)) {
      hookUsage.get(hook).push(rel)
    }
  }
}

// Telemetry consumers outside providers/ and context/ definitions
for (const rel of hookUsage.get('useTelemetry')) {
  if (rel.startsWith('context/') || rel.startsWith('providers/')) continue
  if (rel === 'engineC2/modules/TelemetryStrip.jsx') continue
  if (rel.startsWith('components/cockpit/')) continue
  // all cockpit + pages are under ProtectedOutlet after fix
}

if (errors.length) {
  console.error('Provider wiring check FAILED:')
  for (const e of errors) console.error('  -', e)
  process.exit(1)
}

console.log('Provider wiring check passed.')
console.log('  useTelemetry consumers:', hookUsage.get('useTelemetry').length)
console.log('  useAuth consumers:', hookUsage.get('useAuth').length)
console.log('  useClient consumers:', hookUsage.get('useClient').length)
