#!/usr/bin/env node
/**
 * Handler store-down honesty ratchet.
 *
 * HTTP handlers must not turn a datastore failure into a fake success, and must not
 * leak raw SQL / driver error text to API clients. This gate scans every
 * `fingerprint_engine/src/server_handlers_*.inc` for two banned patterns:
 *
 *   (a) QUERY-LEVEL SWALLOW — a sqlx query that terminates in `.fetch_one` /
 *       `.fetch_all` / `.fetch_optional` / `.fetch` / `.execute`, is `.await`ed, and then
 *       has its Result immediately discarded with `.unwrap_or_default()`, `.unwrap_or(…)`
 *       or `.ok()`. That fabricates an empty/zero body (a `200 {ok:true, empty}`) when the
 *       database is actually down — the caller cannot tell "no data" from "store is down".
 *       Only the QUERY-level swallow is flagged: `row.try_get(col).unwrap_or_default()` on an
 *       already-fetched row, and `json.get(k).unwrap_or(0)` value parsing, have no `.await`
 *       feeding the swallow and are intentionally NOT flagged.
 *
 *   (b) RAW SQL / DRIVER-ERROR LEAK — `e.to_string()` / `err.to_string()` placed inside a
 *       `json!(…)` response body or next to an `"error"` / `"detail"` / `"message"` JSON key.
 *       That ships the raw sqlx/Postgres error string (table names, SQL fragments) to the
 *       client.
 *
 * This is an anti-regression RATCHET, modelled exactly on
 * scripts/verify_i18n_no_default_values.mjs: per-file offender counts are frozen in
 * scripts/handler-honesty-baseline.json and the gate fails only when a file's count
 * INCREASES or a NEW offender file appears. Counts may only go DOWN — the pre-existing
 * backlog is burned down incrementally (baseline → 0), never grown.
 *
 *   node scripts/verify_handler_honesty.mjs                       # ratchet check (CI default)
 *   node scripts/verify_handler_honesty.mjs --write-baseline      # snapshot current counts
 *   WEISSMAN_HONESTY_BASELINE_WRITE=1 node scripts/verify_handler_honesty.mjs  # same, via env
 *   node scripts/verify_handler_honesty.mjs --report             # list every violation site
 */
import { readdir, readFile, writeFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const HANDLER_DIR = join(process.cwd(), 'fingerprint_engine/src')
const HANDLER_RE = /^server_handlers_.*\.inc$/
const BASELINE = join(dirname(fileURLToPath(import.meta.url)), 'handler-honesty-baseline.json')

// A sqlx query always terminates in one of these executors right before `.await`. Requiring one
// in the chain feeding the awaited expression is what separates a QUERY-level swallow (risky)
// from a benign `some_future().await.unwrap_or(…)` or `row.try_get(col).unwrap_or_default()`.
const QUERY_EXECUTOR = /\.(fetch_optional|fetch_one|fetch_all|fetch|execute)\s*\(/
// The swallow that must sit immediately after the query's `.await` (whitespace/newlines allowed).
const SWALLOW_AFTER_AWAIT = /\.await\s*\.\s*(unwrap_or_default\s*\(\s*\)|unwrap_or\s*\(|ok\s*\(\s*\))/g
// A JSON error key whose value would carry the raw error string.
const ERROR_KEY = /"(error|errors|detail|details|message|msg|reason|cause)"\s*:/
const RAW_ERR = /\b(?:e|err|error)\.to_string\s*\(\s*\)/g

/** How far back to walk from `.await` when hunting for the query executor / statement start. */
const LOOKBACK = 400

async function listHandlerFiles() {
  const out = []
  for (const ent of await readdir(HANDLER_DIR, { withFileTypes: true })) {
    if (ent.isFile() && HANDLER_RE.test(ent.name)) out.push(ent.name)
  }
  return out.sort()
}

function lineOf(src, index) {
  let line = 1
  for (let i = 0; i < index && i < src.length; i++) if (src[i] === '\n') line++
  return line
}

function snippet(src, index) {
  const start = src.lastIndexOf('\n', index) + 1
  let end = src.indexOf('\n', index)
  if (end === -1) end = src.length
  return src.slice(start, end).trim()
}

/**
 * (a) Query-level swallow. For each `.await.<swallow>`, walk backwards over the method chain
 * (stopping at a statement boundary or a prior `.await`, capped at LOOKBACK chars) and require a
 * query executor in that tail — i.e. the swallow is discarding the result of a DB query.
 */
function findQuerySwallows(src) {
  const hits = []
  for (const m of src.matchAll(SWALLOW_AFTER_AWAIT)) {
    const awaitIdx = m.index
    let start = awaitIdx
    const floor = Math.max(0, awaitIdx - LOOKBACK)
    // Walk back to the start of the awaited expression: stop at a statement/block boundary or
    // at a previous `.await` (so we only inspect the chain that THIS await terminates).
    while (start > floor) {
      const ch = src[start - 1]
      if (ch === ';' || ch === '{' || ch === '}') break
      if (src.startsWith('.await', start - 6)) break
      start--
    }
    const chainTail = src.slice(start, awaitIdx)
    if (QUERY_EXECUTOR.test(chainTail)) {
      // Compact one-line snippet spanning the executor → `.await` → swallow, even when the
      // real source spreads that chain across several lines.
      const text = src.slice(start, awaitIdx + m[0].length).replace(/\s+/g, ' ').trim()
      hits.push({ kind: 'query-swallow', index: awaitIdx, line: lineOf(src, awaitIdx), text })
    }
  }
  return hits
}

/**
 * (b) Raw error leak. Flag `e.to_string()` when it sits inside a `json!(…)` body, or on/adjacent
 * to a JSON error key — i.e. the raw driver error is being serialised into a client response.
 */
function findErrorLeaks(src) {
  const hits = []
  for (const m of src.matchAll(RAW_ERR)) {
    const idx = m.index
    const before = src.slice(Math.max(0, idx - LOOKBACK), idx)
    const lineStart = src.lastIndexOf('\n', idx) + 1
    const lineText = snippet(src, idx)

    // (i) same-line error key, e.g.  "error": e.to_string()
    const keyOnLine = ERROR_KEY.test(src.slice(lineStart, idx + 1))
    // (ii) inside an unclosed json!( … ) macro: find the nearest json! and confirm its
    //      delimiters are still open at the match position.
    let insideJson = false
    const jsonIdx = before.lastIndexOf('json!')
    if (jsonIdx !== -1) {
      const between = before.slice(jsonIdx)
      let depth = 0
      let entered = false
      for (const c of between) {
        if (c === '(' || c === '{' || c === '[') {
          depth++
          entered = true
        } else if (c === ')' || c === '}' || c === ']') {
          depth--
        }
        // Once the json!(…) macro's own delimiters close, anything after it is outside the
        // macro body — later unrelated parens must not re-open it (avoids flagging e.g.
        // `.data(err.to_string())` that merely serialises an already-built json! value).
        if (entered && depth <= 0) break
      }
      if (entered && depth > 0) insideJson = true
    }
    if (keyOnLine || insideJson) {
      hits.push({ kind: 'error-leak', index: idx, line: lineOf(src, idx), text: lineText })
    }
  }
  return hits
}

async function collect() {
  const files = await listHandlerFiles()
  const perFile = {}
  const violations = {}
  for (const name of files) {
    const src = await readFile(join(HANDLER_DIR, name), 'utf8')
    const hits = [...findQuerySwallows(src), ...findErrorLeaks(src)].sort((a, b) => a.index - b.index)
    if (hits.length) {
      perFile[name] = hits.length
      violations[name] = hits
    }
  }
  return { perFile, violations }
}

function total(counts) {
  return Object.values(counts).reduce((a, b) => a + b, 0)
}

async function main() {
  const args = process.argv.slice(2)
  const wantWrite = args.includes('--write-baseline') || process.env.WEISSMAN_HONESTY_BASELINE_WRITE === '1'
  const wantReport = args.includes('--report')

  const { perFile, violations } = await collect()

  if (wantReport) {
    for (const [file, hits] of Object.entries(violations)) {
      for (const h of hits) console.log(`${file}:${h.line}: [${h.kind}] ${h.text}`)
    }
    console.log(`\n${total(perFile)} store-down honesty violations across ${Object.keys(perFile).length} files.`)
    if (!wantWrite) return
  }

  if (wantWrite) {
    const ordered = Object.fromEntries(Object.entries(perFile).sort((a, b) => a[0].localeCompare(b[0])))
    await writeFile(BASELINE, `${JSON.stringify(ordered, null, 2)}\n`)
    console.log(
      `handler honesty baseline written → ${Object.keys(perFile).length} files, ${total(perFile)} violations`,
    )
    return
  }

  let baseline = {}
  try {
    baseline = JSON.parse(await readFile(BASELINE, 'utf8'))
  } catch {
    console.error('\n✖ No handler honesty baseline found. Run with --write-baseline first.')
    process.exit(1)
  }

  const regressions = []
  for (const [file, count] of Object.entries(perFile)) {
    const allowed = baseline[file] ?? 0
    if (count > allowed) regressions.push({ file, allowed, count })
  }

  const cur = total(perFile)
  const base = total(baseline)
  console.log(
    `handler store-down honesty ratchet: ${Object.keys(perFile).length} files with violations, ` +
      `${cur} occurrences (baseline ${base}; counts may only go down).`,
  )

  if (regressions.length) {
    console.error('\n✖ Store-down honesty debt increased vs baseline (handlers must not regress):')
    for (const r of regressions) {
      console.error(`    ${r.file}: ${r.allowed} → ${r.count}`)
      for (const h of violations[r.file].slice(0, 8)) console.error(`        L${h.line} [${h.kind}] ${h.text}`)
    }
    console.error('\n  A datastore failure must surface as an error (e.g. 503), not a fabricated empty/zero')
    console.error('  success body, and raw driver errors must not be serialised into the response.')
    console.error('  Fix the handler, or (only if genuinely justified) refresh the baseline with')
    console.error('  --write-baseline. See docs/PRODUCT_DEBT_BACKLOG.md.')
    process.exit(1)
  }
  console.log('✓ No new store-down honesty violations vs baseline.')
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
