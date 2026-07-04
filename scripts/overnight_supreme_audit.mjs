#!/usr/bin/env node
/**
 * Overnight supreme audit — API truth, findings verify, log correlation, per-client checks.
 * Logs JSONL to /tmp/weissman-overnight-audit.jsonl
 */
import fs from 'node:fs'
import path from 'node:path'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const LOG = process.env.OVERNIGHT_AUDIT_LOG || '/tmp/weissman-overnight-audit.jsonl'
const BASE = (process.env.WEISSMAN_E2E_BASE || 'http://127.0.0.1:8000').replace(/\/$/, '')

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

const EMAIL = process.env.WEISSMAN_ADMIN_EMAIL || 'admin@localhost'
const PASSWORD = process.env.WEISSMAN_ADMIN_PASSWORD || ''

function log(entry) {
  const row = { ts: new Date().toISOString(), ...entry }
  fs.appendFileSync(LOG, `${JSON.stringify(row)}\n`)
  const tag = entry.status || entry.phase || 'info'
  console.log(`[${tag}] ${entry.msg || entry.route || entry.check || JSON.stringify(entry).slice(0, 120)}`)
}

async function req(method, urlPath, opts = {}) {
  const headers = { Accept: 'application/json', ...(opts.headers || {}) }
  if (opts.body != null) headers['Content-Type'] = 'application/json'
  const r = await fetch(`${BASE}${urlPath}`, {
    method,
    headers,
    body: opts.body != null ? JSON.stringify(opts.body) : undefined,
  })
  const text = await r.text()
  let data = {}
  try { data = text ? JSON.parse(text) : {} } catch { data = { raw: text.slice(0, 300) } }
  return { status: r.status, data, text }
}

function looksLikeUrlOrHost(s) {
  const t = String(s || '').trim()
  return t.startsWith('http') || (t.includes('.') && !t.includes(' ') && t.length >= 4)
}

async function main() {
  log({ phase: 'start', msg: `overnight audit → ${LOG}`, base: BASE })
  if (!PASSWORD) {
    log({ status: 'FAIL', phase: 'auth', msg: 'WEISSMAN_ADMIN_PASSWORD missing' })
    process.exit(1)
  }

  const health = await req('GET', '/api/health')
  log({
    status: health.data.ok ? 'OK' : 'FAIL',
    phase: 'health',
    postgres_ok: health.data.postgres_ok,
    uptime_secs: health.data.uptime_secs,
  })

  const login = await req('POST', '/api/login', {
    body: { email: EMAIL, password: PASSWORD, tenant_slug: 'default' },
  })
  const token = login.data?.access_token || ''
  if (!token) {
    log({ status: 'FAIL', phase: 'login', http: login.status })
    process.exit(1)
  }
  const auth = { headers: { Authorization: `Bearer ${token}` } }
  log({ status: 'OK', phase: 'login', email: EMAIL })

  const clientsR = await req('GET', '/api/clients', auth)
  const clients = Array.isArray(clientsR.data) ? clientsR.data : clientsR.data?.clients || []
  log({ status: 'OK', phase: 'clients', count: clients.length })

  let totalFindings = 0
  let noiseCount = 0
  let verifiedCount = 0
  let scopeOffCount = 0
  const clientSummaries = []

  for (const client of clients) {
    const cid = client.id
    const cname = client.name || `client-${cid}`
    const domains = (() => {
      try {
        return JSON.parse(client.domains || '[]')
      } catch {
        return []
      }
    })()

    const findingsR = await req('GET', `/api/findings?client_id=${cid}&limit=500`, auth)
    const findings = findingsR.data?.findings || []
    totalFindings += findings.length

    let clientNoise = 0
    let clientVerified = 0
    let clientScopeOff = 0
    const engines = new Map()

    for (const f of findings) {
      const src = f.source || f.engine_id || 'unknown'
      engines.set(src, (engines.get(src) || 0) + 1)
      const target = f.target || f.raw?.target || ''
      const verdict = f.live_verdict || f.live_verification?.verdict || ''
      if (verdict === 'NOISE' || verdict === 'FALSE_POSITIVE') clientNoise++
      if (verdict) clientVerified++
      const inScope = domains.length === 0 || domains.some((d) => {
        const dom = String(d).replace(/^https?:\/\//, '').replace(/\/$/, '').toLowerCase()
        return String(target).toLowerCase().includes(dom) || dom.includes(String(target).toLowerCase())
      })
      if (!inScope && target && !looksLikeUrlOrHost(target) === false && target.trim()) {
        if (!inScope) clientScopeOff++
      }
      if (!looksLikeUrlOrHost(target) && target.trim()) {
        // label/campaign noise risk
      }
    }

    noiseCount += clientNoise
    verifiedCount += clientVerified
    scopeOffCount += clientScopeOff

    const topEngines = [...engines.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8)
    const summary = {
      client_id: cid,
      name: cname,
      findings: findings.length,
      live_verified: clientVerified,
      noise_verdicts: clientNoise,
      scope_off: clientScopeOff,
      top_engines: Object.fromEntries(topEngines),
    }
    clientSummaries.push(summary)
    log({ status: 'OK', phase: 'findings_client', ...summary })

    // Sample verify up to 5 unverified findings per client
    const toVerify = findings
      .filter((f) => !f.live_verdict && f.raw_id)
      .slice(0, 5)
    for (const f of toVerify) {
      const vr = await req('POST', `/api/findings/${f.raw_id}/verify`, {
        ...auth,
        body: { deep: false },
      })
      log({
        status: vr.data.ok ? 'OK' : 'FAIL',
        phase: 'verify',
        client_id: cid,
        finding_id: f.raw_id,
        title: (f.title || '').slice(0, 80),
        verdict: vr.data.verdict,
        confidence: vr.data.confidence,
      })
      await new Promise((r) => setTimeout(r, 300))
    }
  }

  log({
    status: 'OK',
    phase: 'findings_summary',
    total_findings: totalFindings,
    live_verified: verifiedCount,
    noise_verdicts: noiseCount,
    scope_off: scopeOffCount,
    clients: clientSummaries,
  })

  // Jobs health
  const jobs = await req('GET', '/api/jobs?limit=20', auth)
  const jobList = jobs.data?.jobs || []
  const failedJobs = jobList.filter((j) => ['failed', 'error', 'dead'].includes(String(j.status || '').toLowerCase()))
  log({
    status: failedJobs.length ? 'WARN' : 'OK',
    phase: 'jobs',
    total: jobs.data?.total,
    recent_failed: failedJobs.length,
    failed_sample: failedJobs.slice(0, 5).map((j) => ({ id: j.id, engine: j.engine, status: j.status })),
  })

  // Engine capabilities count
  const caps = await req('GET', '/api/engines/capabilities', auth)
  const engineCount = Array.isArray(caps.data?.engines)
    ? caps.data.engines.length
    : Object.keys(caps.data?.engines || caps.data || {}).length
  log({ status: 'OK', phase: 'engines', count: engineCount })

  // Log file scan
  for (const logFile of [
    path.join(root, '.e2e-stack/logs/server.log'),
    path.join(root, '.e2e-stack/logs/worker.log'),
  ]) {
    if (!fs.existsSync(logFile)) continue
    const tail = fs.readFileSync(logFile, 'utf8').split('\n').slice(-500).join('\n')
    const errors = (tail.match(/ERROR|FATAL|panic|pool timed out/gi) || []).length
    log({
      status: errors > 10 ? 'WARN' : 'OK',
      phase: 'log_scan',
      file: path.basename(logFile),
      error_hits_last_500_lines: errors,
    })
  }

  log({ phase: 'done', msg: 'overnight API/findings audit complete' })
}

main().catch((e) => {
  log({ status: 'FAIL', phase: 'fatal', msg: String(e.message || e) })
  process.exit(1)
})
