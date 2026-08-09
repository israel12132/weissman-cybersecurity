#!/usr/bin/env node
/**
 * Informational report: which pages still render raw <table> or ad-hoc
 * <button className=...> instead of the shared ui/ primitives (DataTable,
 * Button). Guides the incremental primitive-adoption effort.
 *
 * Modes:
 *   node scripts/report-ui-primitives.mjs                 # informational report (exit 0)
 *   node scripts/report-ui-primitives.mjs --check         # regression ratchet: exit 1 if
 *                                                          # debt increased vs the baseline
 *   node scripts/report-ui-primitives.mjs --write-baseline # snapshot current counts
 *
 * The ratchet lets the large existing backlog stand while blocking NEW raw
 * <table>/<button className> from creeping in — adoption only moves one way.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
// Resolve the vendored parser from the frontend workspace (same as weissman-ui-audit.mjs).
const require = createRequire(path.join(root, 'frontend/package.json'))
const { parse } = require('@babel/parser')
const _traverse = require('@babel/traverse')
const traverse = _traverse.default ?? _traverse

// Count JSX <button …> elements carrying a className attribute. A regex like
// /<button\b[^>]*className=/ cannot cross the `>` inside a JSX arrow-function
// prop (onClick={() => …}), so it silently under-counts the dominant idiom and
// froze the ratchet at 0. Parse the AST instead.
function countAdHocButtons(src, file) {
  let ast
  try {
    ast = parse(src, { sourceType: 'module', plugins: ['jsx', 'importAttributes'] })
  } catch (err) {
    console.error(`  ! parse failed for ${file}: ${err.message}`)
    return 0
  }
  let count = 0
  traverse(ast, {
    JSXOpeningElement({ node }) {
      if (node.name?.type !== 'JSXIdentifier' || node.name.name !== 'button') return
      const hasClassName = node.attributes.some(
        (a) => a.type === 'JSXAttribute' && a.name?.name === 'className',
      )
      if (hasClassName) count += 1
    },
  })
  return count
}
const srcDir = path.join(root, 'frontend', 'src')
// The shared design-system primitives legitimately render raw <button>/<table> (they ARE the
// Button / DataTable everyone else adopts), so they're exempt from the button/table checks.
const PRIMITIVE_DIR = path.join(srcDir, 'components', 'ui')

/**
 * Files intentionally kept on a hand-rolled table because DataTable would
 * regress real behavior (server-side pagination, expandable rows, heatmaps, etc.).
 */
const TABLE_EXCEPTIONS = new Set([
  'AskWeissman.jsx', // dynamic NL→SQL result preview: columns are arbitrary (Object.keys(rows[0])),
  //                    a lightweight inline transcript grid — not a sortable/filterable data table
  'IacSecurityCenter.jsx', // RiskHeatmap: a framework × severity matrix with per-cell severity
  //                          coloring (a heatmap visualization), which DataTable would regress
  'ReportView.jsx', // board-ready client report exported to PDF — a static bordered findings table;
  //                   DataTable's interactive toolbar (search/density/CSV) is wrong for a print report
])

// Recursively list every non-test .jsx under src/ (pages AND components — modals, drawers, nav…).
function listFiles(dir) {
  const out = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) out.push(...listFiles(full))
    else if (entry.name.endsWith('.jsx') && !entry.name.endsWith('.test.jsx')) out.push(full)
  }
  return out
}

const allFiles = listFiles(srcDir)
const rawTablePages = []
const rawButtonCounts = []
const colorCounts = []
// Track which TABLE_EXCEPTIONS actually shielded a raw <table> this run, so a
// stale exemption (its page migrated to DataTable) fails the gate instead of
// silently leaving a blanket exemption open.
const usedExceptions = new Set()

// Hard-coded neutral Tailwind scales that DON'T flip in light mode (unlike the
// CSS-var tokens). Semantic scales (red/green/amber/cyan…) are intentionally
// excluded — those encode status and stay fixed across themes.
const NEUTRAL_COLOR_RE =
  /\b(?:text|bg|border|from|to|via|ring|divide|placeholder|outline)-(?:slate|gray|zinc|neutral|stone)-\d{2,3}\b/g

for (const full of allFiles) {
  const file = path.relative(srcDir, full)
  const base = path.basename(full)
  const isPrimitive = full.startsWith(PRIMITIVE_DIR + path.sep)
  const src = fs.readFileSync(full, 'utf8')
  if (!isPrimitive && /<table[\s>]/.test(src)) {
    if (TABLE_EXCEPTIONS.has(base)) usedExceptions.add(base)
    else rawTablePages.push(file)
  }
  if (!isPrimitive) {
    const btnCount = countAdHocButtons(src, file)
    if (btnCount > 0) {
      rawButtonCounts.push({ file, count: btnCount })
    }
  }
  const colorMatches = src.match(NEUTRAL_COLOR_RE)
  if (colorMatches && colorMatches.length) {
    colorCounts.push({ file, count: colorMatches.length })
  }
}

rawButtonCounts.sort((a, b) => b.count - a.count)
colorCounts.sort((a, b) => b.count - a.count)

const totalPages = allFiles.length
console.log('── UI primitive adoption report ──────────────────────────────')
console.log(`Files scanned (src/**, excl tests + ui/ primitives): ${totalPages}`)
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
console.log('')
const totalColors = colorCounts.reduce((s, r) => s + r.count, 0)
console.log(`Hard-coded neutral colors (won't flip in light mode): ${totalColors} in ${colorCounts.length} pages`)
console.log('  Top offenders (convert slate/gray/zinc → CSS-var tokens):')
for (const { file, count } of colorCounts.slice(0, 10)) {
  console.log(`  • ${String(count).padStart(4)}  ${file}`)
}
console.log('──────────────────────────────────────────────────────────────')

// --- Stale-exception guard ---------------------------------------------------
// A TABLE_EXCEPTIONS entry that no longer shields any raw <table> (its page
// migrated to DataTable) is dead: it would silently exempt a future hand-rolled
// table in that file. Fail the ratchet so the exemption gets removed.
const staleExceptions = [...TABLE_EXCEPTIONS].filter((e) => !usedExceptions.has(e))
if (staleExceptions.length) {
  console.error(`\n✖ Stale TABLE_EXCEPTIONS (no raw <table> found today): ${staleExceptions.join(', ')}`)
  console.error('  Remove them from TABLE_EXCEPTIONS — the page(s) no longer render a raw table.')
}

// --- Regression ratchet ------------------------------------------------------
const totalButtons = rawButtonCounts.reduce((s, r) => s + r.count, 0)
const current = {
  rawTablePages: rawTablePages.length,
  adHocButtonPages: rawButtonCounts.length,
  totalAdHocButtons: totalButtons,
  hardcodedColorPages: colorCounts.length,
  hardcodedColorOccurrences: totalColors,
}
const baselinePath = path.join(root, 'scripts', 'ui-primitives-baseline.json')
const mode = process.argv.slice(2)

if (mode.includes('--write-baseline')) {
  fs.writeFileSync(baselinePath, `${JSON.stringify(current, null, 2)}\n`)
  console.log(`\nBaseline written → ${path.relative(root, baselinePath)}:`, current)
  process.exit(0)
}

if (mode.includes('--check')) {
  if (!fs.existsSync(baselinePath)) {
    console.error('\n✖ No baseline found. Run with --write-baseline first.')
    process.exit(1)
  }
  const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'))
  const regressions = Object.keys(current).filter((k) => current[k] > (baseline[k] ?? 0))
  if (regressions.length || staleExceptions.length) {
    if (regressions.length) {
      console.error('\n✖ UI-primitive debt increased vs baseline (adoption must not regress):')
      for (const k of regressions) console.error(`    ${k}: ${baseline[k]} → ${current[k]}`)
      console.error('  Use the shared ui/DataTable + ui/Button primitives, or refresh the')
      console.error('  baseline (--write-baseline) if the increase is genuinely justified.')
    }
    process.exit(1)
  }
  console.log('\n✓ No UI-primitive regressions vs baseline.', current)
  process.exit(0)
}

process.exit(0)
