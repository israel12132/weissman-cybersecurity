#!/usr/bin/env node
/**
 * i18n defaultValue ratchet — production UI should not use t(..., { defaultValue: ... });
 * strings belong in en.json / he.json.
 *
 * This was historically a hard-zero gate, but a large pre-existing backlog exists across the
 * codebase (RemediationDetail.jsx, RemediationHub.jsx, the remediation panels, several command-
 * center pages …). It now operates as an anti-regression RATCHET, identical in spirit to
 * report-ui-primitives.mjs: the per-file offender counts are frozen in
 * i18n-defaultvalue-baseline.json and the gate fails only if a file's count INCREASES or a NEW
 * offender file appears. Counts may only go down — every touched file should shed defaultValue
 * fallbacks by moving the string into en.json, never add new ones.
 *
 *   node scripts/verify_i18n_no_default_values.mjs                  # ratchet check (CI default)
 *   node scripts/verify_i18n_no_default_values.mjs --write-baseline # snapshot current counts
 */
import { readdir, readFile, writeFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const SRC = join(process.cwd(), 'frontend/src')
const BASELINE = join(dirname(fileURLToPath(import.meta.url)), 'i18n-defaultvalue-baseline.json')
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

async function collect() {
  const files = await walk(SRC)
  const counts = {}
  for (const file of files) {
    // slice + normalize keeps the relative key POSIX-shaped on Windows (backslash
    // paths would otherwise leak absolute prefixes into the baseline).
    const rel = file.slice(SRC.length + 1).replaceAll('\\', '/')
    if (ALLOWLIST.has(rel) || /\.(test|spec)\.(js|jsx|ts|tsx)$/.test(rel)) continue
    const src = await readFile(file, 'utf8')
    const matches = src.match(PATTERN)
    if (matches?.length) counts[rel] = matches.length
  }
  return counts
}

async function main() {
  const current = await collect()
  const mode = process.argv.slice(2)

  if (mode.includes('--write-baseline')) {
    // Deterministic ordering so the committed baseline diffs cleanly.
    const ordered = Object.fromEntries(Object.entries(current).sort((a, b) => a[0].localeCompare(b[0])))
    await writeFile(BASELINE, `${JSON.stringify(ordered, null, 2)}\n`)
    const total = Object.values(current).reduce((a, b) => a + b, 0)
    console.log(`i18n defaultValue baseline written → ${Object.keys(current).length} files, ${total} occurrences`)
    return
  }

  let baseline = {}
  try {
    baseline = JSON.parse(await readFile(BASELINE, 'utf8'))
  } catch {
    console.error('\n✖ No i18n defaultValue baseline found. Run with --write-baseline first.')
    process.exit(1)
  }

  const regressions = []
  for (const [file, count] of Object.entries(current)) {
    const allowed = baseline[file] ?? 0
    if (count > allowed) regressions.push(`${file}: ${allowed} → ${count}`)
  }

  const total = Object.values(current).reduce((a, b) => a + b, 0)
  const baseTotal = Object.values(baseline).reduce((a, b) => a + b, 0)
  console.log(
    `i18n defaultValue ratchet: ${Object.keys(current).length} files with fallbacks, ${total} occurrences ` +
      `(baseline ${baseTotal}; counts may only go down).`,
  )

  if (regressions.length) {
    console.error('\n✖ i18n defaultValue debt increased vs baseline (adoption must not regress):')
    for (const r of regressions) console.error(`    ${r}`)
    console.error(
      '\n  Move the new string into en.json (and he.json) and drop the defaultValue, or refresh',
    )
    console.error('  the baseline (--write-baseline) only if the increase is genuinely justified.')
    process.exit(1)
  }
  console.log('✓ No new defaultValue fallbacks vs baseline.')
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
