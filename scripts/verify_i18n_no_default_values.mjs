#!/usr/bin/env node
/**
 * Fail CI when production UI uses t(..., { defaultValue: ... }) — keys must live in en.json/he.json.
 */
import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'

const SRC = join(process.cwd(), 'frontend/src')
const PATTERN = /defaultValue:\s*['"`]/g

/** confirmDialog prompt API — not i18n fallback */
const ALLOWLIST = new Set(['utils/confirmDialog.jsx', 'lib/routeEvidence.test.js'])

async function walk(dir, out = []) {
  for (const ent of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name)
    if (ent.isDirectory()) {
      if (ent.name === 'node_modules' || ent.name === '__tests__') continue
      await walk(p, out)
    } else if (/\.(jsx|js|tsx|ts)$/.test(ent.name)) {
      out.push(p)
    }
  }
  return out
}

async function main() {
  const files = await walk(SRC)
  const offenders = []

  for (const file of files) {
    const rel = file.replace(`${SRC}/`, '')
    if (ALLOWLIST.has(rel) || rel.endsWith('.test.js') || rel.endsWith('.test.jsx')) continue
    const src = await readFile(file, 'utf8')
    const matches = src.match(PATTERN)
    if (matches?.length) offenders.push({ file: rel, count: matches.length })
  }

  offenders.sort((a, b) => b.count - a.count)
  console.log(`i18n defaultValue audit: ${files.length - offenders.length}/${files.length} files clean`)
  if (offenders.length) {
    console.error('\nFiles with defaultValue fallbacks (add keys to en.json + he.json):')
    for (const o of offenders) {
      console.error(`  ${o.file}: ${o.count}`)
    }
    process.exit(1)
  }
  console.log('All production UI files use proper i18n keys.')
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
