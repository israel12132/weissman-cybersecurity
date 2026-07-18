#!/usr/bin/env node
/**
 * Per-crate line-coverage ratchet.
 *
 * The workspace coverage floor used to be a single `cargo llvm-cov --fail-under-lines 40`, a
 * workspace aggregate that failed whenever the total dipped and never told us WHICH crate
 * regressed. This replaces it with a per-crate ratchet backed by coverage-floors.json:
 *
 *   - Maintained crates (weissman-core, weissman-ui-provenance, weissman-ast-cap) hold a fixed
 *     40% floor — the intended standard.
 *   - Legacy debt crates (fingerprint_engine, weissman-db, weissman-job-bus,
 *     weissman-fleet-shaping) and every other crate are quarantined at their CURRENT line
 *     coverage (rounded down), so they can never regress and must trend upward over time.
 *
 * The rule is simple: coverage can only go up, never down.
 *
 * Usage:
 *   cargo llvm-cov --workspace --lib --json --output-path cov.json
 *   node scripts/coverage_ratchet.mjs cov.json                 # ratchet check (CI default)
 *   node scripts/coverage_ratchet.mjs cov.json --write-floors  # snapshot floors
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const FLOORS_PATH = join(dirname(fileURLToPath(import.meta.url)), 'coverage-floors.json')
const STANDARD_FLOOR = 40
const STANDARD_CRATES = new Set(['weissman-core', 'weissman-ui-provenance', 'weissman-ast-cap'])

const args = process.argv.slice(2)
const write = args.includes('--write-floors')
const jsonPath = args.find((a) => !a.startsWith('--'))
if (!jsonPath) {
  console.error('usage: coverage_ratchet.mjs <llvm-cov-json> [--write-floors]')
  process.exit(2)
}

// crate name -> absolute directory (trailing slash). Longest-prefix match wins so a file is
// attributed to the most specific workspace member that contains it.
const meta = JSON.parse(
  execSync('cargo metadata --no-deps --format-version 1', { maxBuffer: 64 * 1024 * 1024 }).toString(),
)
const crateDirs = meta.packages
  .map((p) => ({ name: p.name, dir: `${dirname(p.manifest_path)}/` }))
  .sort((a, b) => b.dir.length - a.dir.length)

function crateOf(file) {
  for (const c of crateDirs) if (file.startsWith(c.dir)) return c.name
  return null
}

const cov = JSON.parse(readFileSync(jsonPath, 'utf8'))
const agg = {} // crate -> { covered, count }
for (const d of cov.data ?? []) {
  for (const f of d.files ?? []) {
    const crate = crateOf(f.filename)
    if (!crate) continue
    const lines = f.summary?.lines
    if (!lines) continue
    const a = (agg[crate] ??= { covered: 0, count: 0 })
    a.covered += lines.covered
    a.count += lines.count
  }
}

const current = {}
for (const [crate, a] of Object.entries(agg)) {
  current[crate] = a.count > 0 ? (a.covered / a.count) * 100 : 100
}

if (write) {
  const floors = {}
  for (const crate of Object.keys(current).sort()) {
    // Round down => ~1% CI margin against benign nondeterminism, while still ratcheting up.
    floors[crate] = STANDARD_CRATES.has(crate) ? STANDARD_FLOOR : Math.floor(current[crate])
  }
  writeFileSync(FLOORS_PATH, `${JSON.stringify(floors, null, 2)}\n`)
  console.log('coverage floors written:')
  for (const [c, f] of Object.entries(floors)) {
    console.log(`  ${c}: floor ${f}%  (current ${current[c].toFixed(1)}%)`)
  }
  process.exit(0)
}

if (!existsSync(FLOORS_PATH)) {
  console.error('✖ No coverage-floors.json — run with --write-floors first.')
  process.exit(1)
}
const floors = JSON.parse(readFileSync(FLOORS_PATH, 'utf8'))
const regressions = []
for (const [crate, floor] of Object.entries(floors)) {
  const cur = current[crate]
  if (cur == null) {
    regressions.push(`${crate}: no coverage data (crate/tests removed?) — expected >= ${floor}%`)
  } else if (cur + 1e-9 < floor) {
    regressions.push(`${crate}: ${cur.toFixed(1)}% < floor ${floor}%`)
  }
}

console.log('per-crate coverage ratchet:')
for (const crate of Object.keys(floors).sort()) {
  const cur = current[crate]
  console.log(`  ${crate}: ${cur == null ? 'MISSING' : `${cur.toFixed(1)}%`} (floor ${floors[crate]}%)`)
}

if (regressions.length) {
  console.error('\n✖ Coverage regressed below floor (coverage may only go up):')
  for (const r of regressions) console.error(`    ${r}`)
  process.exit(1)
}
console.log('\n✓ All crates meet their coverage floor.')
