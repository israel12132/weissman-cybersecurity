#!/usr/bin/env node
/**
 * Wires Command Center pages to useCommandCenterScan + postEngineScan.
 * Run: node scripts/wire_command_center_scans.mjs
 */
import fs from 'node:fs'
import path from 'node:path'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const pagesDir = path.join(root, 'frontend/src/pages')

const SKIP = new Set([
  'EngineDetail.jsx',
  'BusinessEngineProfile.jsx',
  'TopTierEngineProfile.jsx',
  'OsintEngineProfile.jsx',
  'EngineClientCatalog.jsx',
  'EngineMatrix.jsx',
])

const SCAN_RE = /const\s+r\s*=\s*await\s+apiFetch\(\s*['"]\/api\/command-center\/scan['"]\s*,\s*\{[\s\S]*?body:\s*JSON\.stringify\(([^)]+)\)[\s\S]*?\}\s*\)\s*\n\s*const\s+(\w+)\s*=\s*await\s+r\.json\(\)\.catch\(\(\)\s*=>\s*\(\{\}\)\)/g

function detectClientIdVar(src) {
  if (/\bselectedClientId\b/.test(src)) return 'selectedClientId'
  if (/\bclientId\b/.test(src)) return 'clientId'
  return null
}

function ensureImport(src) {
  let next = src
  if (!next.includes('useCommandCenterScan')) {
    const hookImport = "import { useCommandCenterScan } from '../hooks/useCommandCenterScan'\n"
    const m = next.match(/^import .+$/m)
    if (m) {
      const idx = next.indexOf(m[0])
      next = next.slice(0, idx) + hookImport + next.slice(idx)
    } else {
      next = hookImport + next
    }
  }
  return next
}

function ensureHookCall(src, clientVar) {
  if (src.includes('useCommandCenterScan(')) return src
  const patterns = [
    new RegExp(`(const\\s+\\[${clientVar},\\s*set[^\\]]+\\]\\s*=\\s*useState\\([^\\)]*\\)\\s*\\n)`),
    new RegExp(`(const\\s+\\[${clientVar},\\s*set[^\\]]+\\]\\s*=\\s*useState\\([^\\)]*\\)\\s*;\\s*\\n)`),
  ]
  const hookLine = `  const { postScan } = useCommandCenterScan(${clientVar})\n`
  for (const re of patterns) {
    if (re.test(src)) {
      return src.replace(re, `$1${hookLine}`)
    }
  }
  // fallback: after first useState block in default export function
  const fn = src.indexOf('export default function')
  if (fn === -1) return src
  const brace = src.indexOf('{', fn)
  const insert = src.indexOf('\n', brace) + 1
  return src.slice(0, insert) + hookLine + src.slice(insert)
}

function wireFile(filePath) {
  const base = path.basename(filePath)
  if (SKIP.has(base)) return false
  let src = fs.readFileSync(filePath, 'utf8')
  if (!src.includes("/api/command-center/scan")) return false
  if (src.includes('postScan(') || src.includes('postEngineScan(') || src.includes('launchEngineScan(')) return false

  const clientVar = detectClientIdVar(src)
  if (!clientVar) {
    console.warn(`skip ${base}: no clientId var`)
    return false
  }

  let changed = false
  src = ensureImport(src)
  src = ensureHookCall(src, clientVar)

  const newSrc = src.replace(SCAN_RE, (match, bodyExpr, dataVar) => {
    changed = true
    return `const { ok, data: ${dataVar}, status } = await postScan(${bodyExpr.trim()})`
  })

  // Fix !r.ok -> !ok
  let finalSrc = newSrc.replace(/!r\.ok/g, '!ok').replace(/r\.status/g, 'status')

  if (!changed && finalSrc === fs.readFileSync(filePath, 'utf8')) {
    return false
  }

  fs.writeFileSync(filePath, finalSrc)
  console.log(`wired ${base}`)
  return true
}

let count = 0
for (const name of fs.readdirSync(pagesDir)) {
  if (!name.endsWith('.jsx')) continue
  if (wireFile(path.join(pagesDir, name))) count += 1
}
console.log(`Done: ${count} files updated`)
