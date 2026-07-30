#!/usr/bin/env node
/**
 * Full production engine live audit — all PRODUCTION_ENGINE_IDS, batched.
 * Uses existing client (default id=1). Writes checkpoint for resume.
 *
 *   node scripts/verify_all_engines_live.mjs
 *   WEISSMAN_ENGINE_BATCH=0 WEISSMAN_ENGINE_BATCH_SIZE=10 node scripts/verify_all_engines_live.mjs
 */
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const REPORT_DIR = path.join(root, '.e2e-stack')
const REPORT = process.env.WEISSMAN_ENGINE_REPORT
  ? path.resolve(process.env.WEISSMAN_ENGINE_REPORT)
  : path.join(REPORT_DIR, 'all_engines_live_report.json')
const WORKER_LOG = path.join(REPORT_DIR, 'logs', 'worker.log')

function loadDotEnv() {
  const p = path.join(root, '.env')
  if (!fs.existsSync(p)) return
  for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
    const t = line.trim()
    if (!t || t.startsWith('#')) continue
    const i = t.indexOf('=')
    if (i < 1) continue
    const k = t.slice(0, i)
    const v = t.slice(i + 1)
    if (process.env[k] == null || process.env[k] === '') process.env[k] = v
  }
}

loadDotEnv()

const BASE = (process.env.WEISSMAN_E2E_BASE || 'http://127.0.0.1:8000').replace(/\/$/, '')
const EMAIL = process.env.WEISSMAN_ADMIN_EMAIL || 'admin@localhost'
const PASSWORD = process.env.WEISSMAN_ADMIN_PASSWORD || ''
const TARGET = process.env.WEISSMAN_SMOKE_TARGET || 'https://example.com'
const CLIENT_ID = Number(process.env.WEISSMAN_E2E_CLIENT_ID || 1)
const POLL_MS = Number(process.env.WEISSMAN_E2E_POLL_MS || 3000)
const POLL_MAX = Number(process.env.WEISSMAN_ENGINE_POLL_MAX || 120)
const START_OFFSET = Number(process.env.WEISSMAN_ENGINE_START_OFFSET || 0)
const ENQ_GAP_MS = Number(process.env.WEISSMAN_ENGINE_ENQ_GAP_MS || 5000)
const AUTH_REFRESH_EVERY = Number(process.env.WEISSMAN_ENGINE_AUTH_REFRESH_EVERY || 6)
const ENGINE_LIMIT = Number(process.env.WEISSMAN_ENGINE_LIMIT || 0)
const BATCH_SIZE = Number(process.env.WEISSMAN_ENGINE_BATCH_SIZE || 10)
const BATCH_INDEX = Number(process.env.WEISSMAN_ENGINE_BATCH || -1)
const TARGETLESS = new Set(
  (process.env.WEISSMAN_TARGETLESS_ENGINES || 'zero_day_radar,threat_intel_feed,threat_emulation')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
)

function loadProductionIds() {
  const engineRs = fs.readFileSync(
    path.join(root, 'backend/weissman-core/src/models/engine.rs'),
    'utf8',
  )
  const m = engineRs.match(/pub const PRODUCTION_ENGINE_IDS: &\[\&str\] = &\[(.*?)\];/s)
  if (!m) throw new Error('PRODUCTION_ENGINE_IDS not found')
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1])
}

async function req(method, urlPath, { body, token, cookie } = {}) {
  const headers = { Accept: 'application/json' }
  if (body != null) headers['Content-Type'] = 'application/json'
  if (token) headers.Authorization = `Bearer ${token}`
  if (cookie) headers.Cookie = cookie
  const r = await fetch(`${BASE}${urlPath}`, {
    method,
    headers,
    body: body != null ? JSON.stringify(body) : undefined,
    redirect: 'manual',
  })
  const text = await r.text()
  let data = {}
  try { data = text ? JSON.parse(text) : {} } catch { data = { raw: text.slice(0, 500) } }
  return { status: r.status, data, setCookie: r.headers.getSetCookie?.() || [] }
}

function cookieHeader(setCookie) {
  return setCookie.map((c) => c.split(';')[0]).join('; ')
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

function tailWorkerLog(sinceLine) {
  if (!fs.existsSync(WORKER_LOG)) return []
  const lines = fs.readFileSync(WORKER_LOG, 'utf8').split('\n')
  return lines.slice(Math.max(0, sinceLine)).filter(Boolean).slice(-30)
}

function loadReport() {
  if (!fs.existsSync(REPORT)) {
    return { started_at: new Date().toISOString(), engines: {}, batches: [] }
  }
  try {
    const raw = fs.readFileSync(REPORT, 'utf8').trim()
    if (!raw) {
      return { started_at: new Date().toISOString(), engines: {}, batches: [] }
    }
    return JSON.parse(raw)
  } catch {
    return { started_at: new Date().toISOString(), engines: {}, batches: [] }
  }
}

function saveReport(report) {
  fs.mkdirSync(REPORT_DIR, { recursive: true })
  report.updated_at = new Date().toISOString()
  fs.writeFileSync(REPORT, JSON.stringify(report, null, 2))
}

async function pollJob(jobId, auth) {
  const terminal = new Set(['completed', 'done', 'failed', 'error', 'dead', 'cancelled'])
  for (let i = 0; i < POLL_MAX; i += 1) {
    let { status, data } = await req('GET', `/api/jobs/${jobId}`, auth)
    if (status === 401 || status === 403) {
      Object.assign(auth, await loginAuth())
      ;({ status, data } = await req('GET', `/api/jobs/${jobId}`, auth))
    }
    if (status === 200) {
      const st = String(data.status || '').toLowerCase()
      if (terminal.has(st)) {
        return { st, data }
      }
    }
    if ((i + 1) % AUTH_REFRESH_EVERY === 0) {
      Object.assign(auth, await loginAuth())
    }
    await sleep(POLL_MS)
  }
  let peek = await req('GET', `/api/jobs/${jobId}`, auth)
  if (peek.status === 401 || peek.status === 403) {
    Object.assign(auth, await loginAuth())
    peek = await req('GET', `/api/jobs/${jobId}`, auth)
  }
  return { st: 'timeout', data: peek.data }
}

async function loginAuth() {
  const login = await req('POST', '/api/login', {
    body: { email: EMAIL, password: PASSWORD, tenant_slug: 'default' },
  })
  const token = login.data?.access_token || login.data?.token || ''
  const cookie = cookieHeader(login.setCookie)
  if (login.status !== 200 || (!token && !cookie)) {
    throw new Error(`login failed HTTP ${login.status}`)
  }
  return { token: token || undefined, cookie: cookie || undefined }
}

async function enqueueScan(engine, auth) {
  const body = { engine, client_id: CLIENT_ID }
  if (!TARGETLESS.has(engine)) body.target = TARGET
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const enq = await req('POST', '/api/command-center/scan', { ...auth, body })
    if (enq.status === 202 && enq.data?.job_id) return enq
    if (enq.status === 401 || enq.status === 403) {
      Object.assign(auth, await loginAuth())
      continue
    }
    // Transient scan-intake shed — 429 `rate_limited` or 503 `load_shed` (self-heal recovery).
    // Both advertise `retry_after_seconds`; honor it (capped) so a legitimate shed is waited out
    // rather than treated as a hard enqueue failure.
    if (enq.status === 429 || enq.status === 503) {
      const hint = Number(enq.data?.retry_after_seconds)
      const wait = Number.isFinite(hint) && hint > 0
        ? Math.min(20_000, hint * 1000)
        : Math.min(15_000, 2000 * (attempt + 1))
      await sleep(wait)
      continue
    }
    return enq
  }
  return req('POST', '/api/command-center/scan', { ...auth, body })
}

async function runEngine(engine, auth, logStartLine) {
  const enq = await enqueueScan(engine, auth)
  if (enq.status !== 202 || !enq.data?.job_id) {
    return {
      engine,
      ok: false,
      phase: 'enqueue',
      http: enq.status,
      detail: enq.data?.detail || enq.data?.message || '',
      worker_tail: tailWorkerLog(logStartLine),
    }
  }

  const jobId = enq.data.job_id
  const { st, data } = await pollJob(jobId, auth)
  const result = data?.result || {}
  const findings = Array.isArray(result.findings) ? result.findings.length : null
  const persisted = result.findings_persisted
  const workerTail = tailWorkerLog(logStartLine)
  const workerErrors = workerTail.filter((l) =>
    /ERROR|failed to persist|panic|timeout/i.test(l),
  )

  const ok = st === 'completed' || st === 'done'
  return {
    engine,
    ok,
    phase: 'run',
    status: st,
    job_id: jobId,
    kind: enq.data?.job_kind || data?.kind,
    findings,
    persisted,
    message: result.message || data?.last_error || '',
    worker_errors: workerErrors,
    worker_tail: workerTail.slice(-8),
  }
}

async function main() {
  console.log(`verify_all_engines_live: ${BASE} client_id=${CLIENT_ID}`)
  if (!PASSWORD) {
    console.error('WEISSMAN_ADMIN_PASSWORD required')
    process.exit(1)
  }

  let allIds = loadProductionIds().slice(START_OFFSET)
  if (ENGINE_LIMIT > 0) allIds = allIds.slice(0, ENGINE_LIMIT)
  const batches = []
  for (let i = 0; i < allIds.length; i += BATCH_SIZE) {
    batches.push(allIds.slice(i, i + BATCH_SIZE))
  }
  console.log(`engines=${allIds.length} batches=${batches.length} batch_size=${BATCH_SIZE}`)

  const login = await loginAuth()
  const auth = { ...login }
  let enginesSinceLogin = 0

  const report = loadReport()
  const batchRange =
    BATCH_INDEX >= 0
      ? [BATCH_INDEX]
      : batches.map((_, i) => i)

  for (const bi of batchRange) {
    const batch = batches[bi]
    if (!batch) continue
    console.log(`\n=== BATCH ${bi + 1}/${batches.length} (${batch.length} engines) ===`)
    const batchResult = { index: bi, engines: [], started_at: new Date().toISOString() }

    for (const engine of batch) {
      const prev = report.engines[engine]
      if (prev?.ok === true) {
        console.log(`  ${engine} … skip (already OK)`)
        continue
      }
      if (enginesSinceLogin >= AUTH_REFRESH_EVERY) {
        Object.assign(auth, await loginAuth())
        enginesSinceLogin = 0
      }
      enginesSinceLogin += 1
      const logLines = fs.existsSync(WORKER_LOG)
        ? fs.readFileSync(WORKER_LOG, 'utf8').split('\n').length
        : 0
      process.stdout.write(`  ${engine} … `)
      const row = await runEngine(engine, auth, logLines)
      report.engines[engine] = row
      batchResult.engines.push(row)
      saveReport(report)
      if (row.ok) {
        console.log(`OK (${row.status}, findings=${row.findings ?? '?'}, persisted=${row.persisted ?? '?'})`)
      } else if (row.phase === 'enqueue') {
        console.log(`ENQ_FAIL ${row.http} ${row.detail}`.slice(0, 100))
      } else {
        console.log(`FAIL (${row.status}) ${(row.message || '').slice(0, 80)}`)
        if (row.worker_errors?.length) {
          console.log(`    log: ${row.worker_errors[0].slice(0, 120)}`)
        }
      }
      await sleep(ENQ_GAP_MS)
    }

    batchResult.ended_at = new Date().toISOString()
    report.batches[bi] = batchResult
    saveReport(report)

    const done = Object.values(report.engines).filter((r) => r.ok).length
    const fail = Object.values(report.engines).filter((r) => r && !r.ok).length
    console.log(`batch ${bi + 1} summary: ok=${done} fail=${fail} / ${allIds.length}`)
  }

  const summary = {
    total: allIds.length,
    ok: Object.values(report.engines).filter((r) => r?.ok).length,
    fail: Object.values(report.engines).filter((r) => r && !r.ok).length,
    pending: allIds.length - Object.keys(report.engines).length,
  }
  report.summary = summary
  saveReport(report)
  console.log('\nverify_all_engines_live summary:', summary)
  console.log(`report: ${REPORT}`)
  process.exit(summary.fail > 0 && summary.ok === 0 ? 1 : 0)
}

main().catch((e) => {
  console.error('FATAL', e)
  process.exit(1)
})
