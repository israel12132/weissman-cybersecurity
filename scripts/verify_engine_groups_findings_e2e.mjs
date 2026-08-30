#!/usr/bin/env node
/**
 * Engine-group findings E2E: one engine per surface → job complete → DB findings → risk fields.
 * Requires running stack (same as verify_scan_pipeline_e2e).
 */
import fs from 'node:fs'
import path from 'node:path'
import { GROUP_SMOKE_PLAN, FINDINGS_E2E_PLAN, collectApprovedDomains } from './lib/group_smoke_plan.mjs'
import { retryScanIntake, retryLogin, retryShed } from './lib/scan_intake.mjs'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')

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

const BASE = (process.env.WEISSMAN_E2E_BASE || process.env.WEISSMAN_SMOKE_BASE_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')
const EMAIL = process.env.WEISSMAN_ADMIN_EMAIL || process.env.WEISSMAN_SMOKE_LOGIN_EMAIL || 'admin@localhost'
const PASSWORD = process.env.WEISSMAN_ADMIN_PASSWORD || process.env.WEISSMAN_SMOKE_LOGIN_PASSWORD || ''
const TENANT = process.env.WEISSMAN_E2E_TENANT || process.env.WEISSMAN_TENANT_SLUG || 'default'
const CLIENT_NAME = process.env.WEISSMAN_FINDINGS_E2E_CLIENT || 'E2E Findings Client'
const POLL_MS = Number(process.env.WEISSMAN_FINDINGS_E2E_POLL_MS || 2000)
const POLL_MAX = Number(process.env.WEISSMAN_FINDINGS_E2E_POLL_MAX || 90)
const BETWEEN_MS = Number(process.env.WEISSMAN_FINDINGS_E2E_DELAY_MS || 800)

const ACTIVE_PLAN = process.env.WEISSMAN_FINDINGS_E2E_FULL === '1'
  ? GROUP_SMOKE_PLAN
  : FINDINGS_E2E_PLAN

const failures = []

function ok(msg) { console.log(`  ✓ ${msg}`) }
function fail(msg) { failures.push(msg); console.error(`  ✗ ${msg}`) }

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)) }

async function api(method, urlPath, { body, token } = {}) {
  const headers = { Accept: 'application/json' }
  if (body != null) headers['Content-Type'] = 'application/json'
  if (token) headers.Authorization = `Bearer ${token}`
  const r = await fetch(`${BASE}${urlPath}`, { method, headers, body: body != null ? JSON.stringify(body) : undefined })
  const text = await r.text()
  let data = {}
  try { data = text ? JSON.parse(text) : {} } catch { data = { raw: text } }
  return { status: r.status, data, text }
}

function terminal(status) {
  return ['completed', 'done', 'failed', 'error', 'dead', 'cancelled'].includes(String(status || '').toLowerCase())
}

function validateRiskFields(row) {
  const cm = Number(row.confidence_multiplier)
  const er = Number(row.effective_risk ?? row.risk_score)
  if (!Number.isFinite(cm) || cm < 0.1 || cm > 1.0) return false
  if (!Number.isFinite(er) || er < 0 || er > 10) return false
  return true
}

async function pollJob(jobId, token) {
  const label = `job ${String(jobId).slice(0, 8)}`
  for (let i = 0; i < POLL_MAX; i += 1) {
    const { status, data } = await retryShed(
      () => api('GET', `/api/jobs/${jobId}`, { token }),
      { label, what: 'job poll', retries: 3 },
    )
    if (status === 200 && terminal(data.status)) return data
    await sleep(POLL_MS)
  }
  return null
}

async function ensureClient(token) {
  const domains = collectApprovedDomains(ACTIVE_PLAN)
  const clients = await api('GET', '/api/clients', { token })
  if (clients.status !== 200 || !Array.isArray(clients.data)) {
    throw new Error(`clients list HTTP ${clients.status}`)
  }
  let client = clients.data.find((c) => c.name === CLIENT_NAME)
  const payload = {
    name: CLIENT_NAME,
    domains: JSON.stringify(domains.length ? domains : ['https://example.com']),
    ip_ranges: JSON.stringify(['127.0.0.0/8']),
  }
  if (!client) {
    const created = await api('POST', '/api/clients', { token, body: payload })
    if (created.status < 200 || created.status >= 300) {
      throw new Error(`client create HTTP ${created.status}`)
    }
    client = { id: created.data.id }
  } else {
    await api('POST', `/api/clients/${client.id}`, { token, body: payload })
  }
  return client.id
}

async function findingsForEngine(token, clientId, engine) {
  const r = await api('GET', `/api/findings?client_id=${clientId}&limit=200`, { token })
  if (r.status !== 200 || r.data?.ok !== true) return []
  const rows = Array.isArray(r.data.findings) ? r.data.findings : []
  return rows.filter((row) => String(row.source || '').toLowerCase() === engine.toLowerCase())
}

async function login() {
  const r = await retryLogin(() => api('POST', '/api/login', {
    body: { email: EMAIL, password: PASSWORD, tenant_slug: TENANT },
  }))
  return r.status === 200 ? r.data?.access_token || null : null
}

async function main() {
  console.log(`verify_engine_groups_findings_e2e: ${BASE}`)
  if (!PASSWORD) { fail('credentials missing'); process.exit(1) }

  let token = await login()
  if (!token) { fail('login'); process.exit(1) }
  ok(`login ${EMAIL}`)

  const clientId = await ensureClient(token)
  ok(`client id=${clientId}`)

  for (const entry of ACTIVE_PLAN) {
    const label = `${entry.group}/${entry.engine}`
    const body = { engine: entry.engine, client_id: Number(clientId) }
    if (entry.target) body.target = entry.target
    // Per-engine job_params (ArsenalConfig) passed straight through the scan
    // body as extras. Live-network engines (jwt_attack, bgp_dns_hijacking) use
    // this to fail fast in the sandboxed runner so they finish inside the poll
    // window instead of stalling on unreachable third-party infrastructure.
    if (entry.params && typeof entry.params === 'object') Object.assign(body, entry.params)

    // Reuse the token. Re-login-per-engine burns the per-IP login quota (8/min)
    // after Playwright already used 127.0.0.1; CI sets a 120-minute JWT.
    const scan = await retryScanIntake(
      () => api('POST', '/api/command-center/scan', { token, body }),
      { label },
    )
    if (scan.status !== 202 || !scan.data?.job_id) {
      fail(`${label}: enqueue HTTP ${scan.status}${scan.data?.code ? ` (${scan.data.code})` : ''}`)
      continue
    }
    ok(`${label}: queued ${scan.data.job_id}`)

    const job = await pollJob(scan.data.job_id, token)
    if (!job) { fail(`${label}: job timeout`); continue }
    if (String(job.status).toLowerCase() !== 'completed') {
      fail(`${label}: terminal ${job.status} ${job.last_error || ''}`)
      // The worker-log dump is unreliable (block-buffered, truncated on live
      // processes), so surface the real terminal error on the reliable step
      // stdout: dump the diagnostic fields of the job row itself.
      const diag = {
        status: job.status,
        last_error: job.last_error,
        attempt_count: job.attempt_count,
        max_attempts: job.max_attempts,
        result: job.result,
        error: job.error,
      }
      console.error(`  ↳ ${label} job detail: ${JSON.stringify(diag).slice(0, 2000)}`)
      continue
    }
    ok(`${label}: completed`)

    const persisted = job.result?.findings_persisted
    if (typeof persisted !== 'number') {
      fail(`${label}: findings_persisted missing`)
    } else {
      ok(`${label}: findings_persisted=${persisted}`)
    }

    const rows = await findingsForEngine(token, clientId, entry.engine)
    if (persisted > 0 && rows.length === 0) {
      fail(`${label}: persisted=${persisted} but /api/findings has 0 rows for source=${entry.engine}`)
    } else if (rows.length > 0) {
      const withRisk = rows.filter(validateRiskFields)
      if (withRisk.length > 0) {
        ok(`${label}: risk fields OK on ${withRisk.length}/${rows.length} rows`)
        const sample = withRisk[0]
        ok(`${label}: sample cm=${sample.confidence_multiplier} er=${sample.effective_risk ?? sample.risk_score}`)
      } else {
        fail(`${label}: ${rows.length} rows but none pass confidence_multiplier/effective_risk contract`)
      }
    } else {
      ok(`${label}: no DB rows (engine produced 0 persistable findings)`)
    }

    await sleep(BETWEEN_MS)
  }

  console.log('')
  if (failures.length) {
    console.error(`verify_engine_groups_findings_e2e: FAIL (${failures.length})`)
    for (const f of failures) console.error(`  - ${f}`)
    process.exit(1)
  }
  console.log(`verify_engine_groups_findings_e2e: OK (${ACTIVE_PLAN.length} groups)`)
}

main().catch((e) => {
  console.error('verify_engine_groups_findings_e2e: FATAL', e)
  process.exit(1)
})
