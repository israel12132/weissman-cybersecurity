#!/usr/bin/env node
/**
 * Informational report: which pages still render raw <table> or ad-hoc
 * <button className=...> instead of the shared ui/ primitives (DataTable,
 * Button). Guides the incremental primitive-adoption effort.
 *
 * Always exits 0 — this is a guide, not a gate. Run:
 *   node scripts/report-ui-primitives.mjs
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const pagesDir = path.join(root, 'frontend', 'src', 'pages')

/**
 * Pages intentionally kept on a hand-rolled table because DataTable would
 * regress real behavior (server-side pagination, expandable rows, etc.).
 */
const TABLE_EXCEPTIONS = new Set([
  'AuditLog.jsx', // server-side offset pagination + expandable JSON payload rows
])

function listPages() {
  return fs
    .readdirSync(pagesDir)
    .filter((f) => f.endsWith('.jsx') && !f.endsWith('.test.jsx'))
}

const rawTablePages = []
const rawButtonCounts = []

for (const file of listPages()) {
  const src = fs.readFileSync(path.join(pagesDir, file), 'utf8')
  if (/<table[\s>]/.test(src) && !TABLE_EXCEPTIONS.has(file)) {
    rawTablePages.push(file)
  }
  const btnMatches = src.match(/<button\b[^>]*className=/g)
  if (btnMatches && btnMatches.length) {
    rawButtonCounts.push({ file, count: btnMatches.length })
  }
}

rawButtonCounts.sort((a, b) => b.count - a.count)

const totalPages = listPages().length
console.log('── UI primitive adoption report ──────────────────────────────')
console.log(`Pages scanned: ${totalPages}`)
console.log('')
console.log(`Raw <table> (candidates for DataTable): ${rawTablePages.length}`)
for (const f of rawTablePages) console.log(`  • ${f}`)
if (TABLE_EXCEPTIONS.size) {
  console.log(`  (excluded by design: ${[...TABLE_EXCEPTIONS].join(', ')})`)
}
console.log('')
console.log(`Pages with ad-hoc <button className>: ${rawButtonCounts.length}`)
console.log('  Top offenders (convert to <Button> when next editing):')
for (const { file, count } of rawButtonCounts.slice(0, 15)) {
  console.log(`  • ${String(count).padStart(4)}  ${file}`)
}
console.log('──────────────────────────────────────────────────────────────')

process.exit(0)
