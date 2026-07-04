#!/usr/bin/env node
/**
 * Live engine smoke — enqueue + poll representative production engines like a customer.
 * Requires: local server + worker (./scripts/run_e2e_stack.sh start)
 *
 * Env: WEISSMAN_E2E_BASE, WEISSMAN_ADMIN_EMAIL, WEISSMAN_ADMIN_PASSWORD
 *      WEISSMAN_SMOKE_ENGINES (comma list, optional)
 *      WEISSMAN_SMOKE_POLL_MAX (default 45)
 */
import fs from 'node:fs'
import path from 'node:path'

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

const BASE = (process.env.WEISSMAN_E2E_BASE || 'http://127.0.0.1:8000').replace(/\/$/, '')
const EMAIL = process.env.WEISSMAN_ADMIN_EMAIL || 'admin@localhost'
const PASSWORD = process.env.WEISSMAN_ADMIN_PASSWORD || ''
const POLL_MS = Number(process.env.WEISSMAN_E2E_POLL_MS || 2000)
const POLL_MAX = Number(process.env.WEISSMAN_SMOKE_POLL_MAX || 90)
const TARGET = process.env.WEISSMAN_SMOKE_TARGET || 'https://example.com'

const DEFAULT_ENGINES = [
  'osint',
  'microsecond_timing',
  'zero_day_radar',
  'email_dns_posture',
  'pki_tls',
  'supply_chain',
  'asm',
  'cache_poisoning',
  'http_smuggling',
  'graphql_attack',
  'jwt_attack',
  'ssrf_advanced',
  'bgp_dns_hijacking',
  'bola_idor',
]

const engines = (process.env.WEISSMAN_SMOKE_ENGINES || DEFAULT_ENGINES.join(','))
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)

const results = []

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
  try { data = text ? JSON.parse(text) : {} } catch { data = { raw: text } }
  return { status: r.status, data, setCookie: r.headers.getSetCookie?.() || [] }
}

function cookieHeader(setCookie) {
  return setCookie.map((c) => c.split(';')[0]).join('; ')
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

async function pollJob(jobId, auth) {
  const terminal = new Set(['completed', 'done', 'failed', 'error', 'dead', 'cancelled'])
  for (let i = 0; i < POLL_MAX; i += 1) {
    const { status, data } = await req('GET', `/api/jobs/${jobId}`, auth)
    if (status === 200) {
      const st = String(data.status || '').toLowerCase()
      if (terminal.has(st)) return { st, data }
    }
    await sleep(POLL_MS)
  }
  return { st: 'timeout', data: null }
}

async function main() {
  console.log(`verify_engine_live_smoke: ${BASE} (${engines.length} engines)`)
  if (!PASSWORD) {
    console.error('WEISSMAN_ADMIN_PASSWORD not set')
    process.exit(1)
  }

  const login = await req('POST', '/api/login', {
    body: { email: EMAIL, password: PASSWORD, tenant_slug: 'default' },
  })
  const token = login.data?.access_token || login.data?.token || ''
  const cookie = cookieHeader(login.setCookie)
  if (login.status !== 200 || (!token && !cookie)) {
    console.error('login failed', login.status)
    process.exit(1)
  }
  const auth = { token: token || undefined, cookie: cookie || undefined }

  const clients = await req('GET', '/api/clients', auth)
  const clientId = clients.data?.[0]?.id
  if (!clientId) {
    console.error('no client — create one first')
    process.exit(1)
  }

  let passed = 0
  let failed = 0

  for (const engine of engines) {
    process.stdout.write(`  ${engine} … `)
    const body = { engine, client_id: Number(clientId), target: TARGET }
    if (engine === 'zero_day_radar') delete body.target

    const enq = await req('POST', '/api/command-center/scan', { ...auth, body })
    if (enq.status !== 202 || !enq.data?.job_id) {
      console.log(`FAIL enqueue HTTP ${enq.status} ${enq.data?.detail || ''}`)
      results.push({ engine, ok: false, phase: 'enqueue', detail: enq.data?.detail })
      failed += 1
      continue
    }

    const { st, data } = await pollJob(enq.data.job_id, auth)
    const result = data?.result || {}
    const findings = Array.isArray(result.findings) ? result.findings.length : null
    const persisted = result.findings_persisted
    const ok = st === 'completed' || st === 'done'
    const row = {
      engine,
      ok,
      status: st,
      findings,
      persisted,
      message: result.message || data?.last_error || '',
      job_id: enq.data.job_id,
    }
    results.push(row)
    if (ok) {
      passed += 1
      console.log(`OK (${st}, findings=${findings ?? '?'}, persisted=${persisted ?? '?'})`)
    } else {
      failed += 1
      console.log(`FAIL (${st}) ${row.message}`.slice(0, 120))
    }
  }

  console.log('')
  console.log(`verify_engine_live_smoke: ${passed}/${engines.length} completed OK, ${failed} failed`)
  const out = path.join(root, '.e2e-stack', 'engine_smoke_report.json')
  fs.mkdirSync(path.dirname(out), { recursive: true })
  fs.writeFileSync(out, JSON.stringify({ at: new Date().toISOString(), results }, null, 2))
  console.log(`report: ${out}`)
  process.exit(failed > 0 ? 1 : 0)
}

main().catch((e) => {
  console.error('FATAL', e)
  process.exit(1)
})
