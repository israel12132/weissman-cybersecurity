#!/usr/bin/env node
/**
 * Fail CI when command-center pages use t(..., { defaultValue: ... }) — keys must live in en.json/he.json.
 */
import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'

const PAGES_DIR = join(process.cwd(), 'frontend/src/pages')
const ALLOWLIST = new Set([
  // Legacy pages being migrated in batches — remove as keys are added.
])

const PATTERN = /defaultValue:\s*['"`]/g

async function main() {
  const files = (await readdir(PAGES_DIR)).filter((f) => f.endsWith('.jsx'))
  const offenders = []

  for (const file of files) {
    if (ALLOWLIST.has(file)) continue
    const src = await readFile(join(PAGES_DIR, file), 'utf8')
    const matches = src.match(PATTERN)
    if (matches?.length) {
      offenders.push({ file, count: matches.length })
    }
  }

  offenders.sort((a, b) => b.count - a.count)
  console.log(`i18n defaultValue audit: ${files.length - offenders.length}/${files.length} pages clean`)
  if (offenders.length) {
    console.error('\nPages with defaultValue fallbacks (add keys to en.json + he.json):')
    for (const o of offenders) {
      console.error(`  ${o.file}: ${o.count}`)
    }
    process.exit(1)
  }
  console.log('All pages use proper i18n keys.')
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
