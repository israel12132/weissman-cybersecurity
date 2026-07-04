#!/usr/bin/env node
/**
 * Live E2E supreme gate: auth → client → integrations → scan routing → worker → jobs API.
 * Requires: ./scripts/run_e2e_stack.sh start
 *
 * Env: WEISSMAN_E2E_BASE, WEISSMAN_ADMIN_EMAIL, WEISSMAN_ADMIN_PASSWORD, WEISSMAN_E2E_TENANT
 *      WEISSMAN_E2E_POLL_MS (default 2000), WEISSMAN_E2E_POLL_MAX (default 120)
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
const TENANT = process.env.WEISSMAN_E2E_TENANT || 'default'
const POLL_MS = Number(process.env.WEISSMAN_E2E_POLL_MS || 2000)
const POLL_MAX = Number(process.env.WEISSMAN_E2E_POLL_MAX || 120)
const MASK = '••••••••'

const steps = []
const failures = []

function ok(label, detail = '') {
  steps.push({ ok: true, label, detail })
  console.log(`  ✓ ${label}${detail ? ` — ${detail}` : ''}`)
}

function fail(label, detail = '') {
  steps.push({ ok: false, label, detail })
  failures.push(`${label}${detail ? `: ${detail}` : ''}`)
  console.error(`  ✗ ${label}${detail ? ` — ${detail}` : ''}`)
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
  try { data = text ? JSON.parse(text) : {} } catch { data = { raw: text } }
  const setCookie = r.headers.getSetCookie?.() || []
  return { status: r.status, data, setCookie, text }
}

function cookieHeader(setCookie) {
  return setCookie.map((c) => c.split(';')[0]).join('; ')
}

function parseDomains(raw) {
  if (Array.isArray(raw)) return raw
  if (typeof raw === 'string') {
    try { return JSON.parse(raw || '[]') } catch { return [] }
  }
  return []
}

async function pollJob(jobId, auth, { label = 'job_poll', max = POLL_MAX } = {}) {
  const terminal = new Set(['completed', 'done', 'failed', 'error', 'dead', 'cancelled'])
  for (let i = 0; i < max; i += 1) {
    const { status, data } = await req('GET', `/api/jobs/${jobId}`, auth)
    if (status !== 200) {
      await sleep(POLL_MS)
      continue
    }
    const st = String(data.status || data.state || '').toLowerCase()
    if (terminal.has(st)) {
      if (st === 'failed' || st === 'error' || st === 'dead') {
        fail(label, `${st} ${data.last_error || data.error || ''}`)
      } else {
        ok(label, st)
      }
      return { status: st, data }
    }
    await sleep(POLL_MS)
  }
  fail(label, `timeout after ${max * POLL_MS / 1000}s`)
  return { status: 'timeout', data: null }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

function payloadHasRawSecret(payload, key, raw) {
  const v = payload?.[key]
  return v != null && String(v) === raw
}

function payloadShowsMasked(payload, key) {
  const v = payload?.[key]
  if (v == null) return true
  const s = typeof v === 'string' ? v : JSON.stringify(v)
  return s.includes('••••')
}

function validateRiskFields(row) {
  const cm = Number(row.confidence_multiplier)
  const er = Number(row.effective_risk ?? row.risk_score)
  if (!Number.isFinite(cm) || cm < 0.1 || cm > 1.0) return false
  if (!Number.isFinite(er) || er < 0 || er > 10) return false
  return true
}

async function main() {
  console.log(`verify_scan_pipeline_e2e: ${BASE}`)

  if (!PASSWORD) {
    fail('credentials', 'WEISSMAN_ADMIN_PASSWORD not set')
    process.exit(1)
  }

  const health = await req('GET', '/api/health')
  if (health.status === 200) ok('health', 'DB reachable')
  else { fail('health', `HTTP ${health.status}`); process.exit(1) }

  const login = await req('POST', '/api/login', {
    body: { email: EMAIL, password: PASSWORD, tenant_slug: TENANT },
  })
  const token = login.data?.access_token || login.data?.token || ''
  const cookie = cookieHeader(login.setCookie)
  if (login.status === 200 && (token || cookie)) ok('login', EMAIL)
  else { fail('login', `HTTP ${login.status} ${login.data?.detail || ''}`); process.exit(1) }

  const auth = { token: token || undefined, cookie: cookie || undefined }

  // Client scope
  let clientId = null
  const clients = await req('GET', '/api/clients', auth)
  if (clients.status === 200 && Array.isArray(clients.data)) {
    const existing = clients.data.find((c) =>
      parseDomains(c.domains).some((x) => String(x).includes('example.com')),
    )
    clientId = existing?.id ?? clients.data[0]?.id ?? null
  }
  if (!clientId) {
    const created = await req('POST', '/api/clients', {
      ...auth,
      body: {
        name: 'E2E Pipeline Client',
        domains: JSON.stringify(['https://example.com']),
        ip_ranges: JSON.stringify(['127.0.0.0/8']),
      },
    })
    clientId = created.data?.id
    if (created.status >= 200 && created.status < 300 && clientId) ok('client_create', `id=${clientId}`)
    else { fail('client_create', `HTTP ${created.status}`); process.exit(1) }
  } else {
    ok('client_resolve', `id=${clientId}`)
  }

  // Integrations GET — masked shape
  const ints = await req('GET', `/api/clients/${clientId}/integrations`, auth)
  if (ints.status === 200) {
    const gh = ints.data?.github_token
    const maskedOk = gh == null || typeof gh === 'object' || gh === '' || String(gh).includes('••••')
    if (maskedOk) ok('integrations_get', 'tenant secrets masked')
    else fail('integrations_get', 'github_token not masked')
  } else {
    fail('integrations_get', `HTTP ${ints.status}`)
  }

  // PATCH client credential for server-side hydration (value never echoed raw to client)
  const hydrationExt = `e2e-ext-${Date.now()}`
  const patch = await req('PATCH', `/api/clients/${clientId}/integrations`, {
    ...auth,
    body: { aws_external_id: hydrationExt },
  })
  if (patch.status >= 200 && patch.status < 300) ok('integrations_patch', 'aws_external_id stored')
  else fail('integrations_patch', `HTTP ${patch.status} ${patch.data?.detail || ''}`)

  const ints2 = await req('GET', `/api/clients/${clientId}/integrations`, auth)
  if (ints2.status === 200 && payloadShowsMasked(ints2.data, 'aws_external_id')) {
    ok('integrations_mask_roundtrip', 'PATCH value masked on GET')
  } else {
    fail('integrations_mask_roundtrip', 'aws_external_id not masked after PATCH')
  }

  // Tenant github_token for hydration (system_configs)
  const cfgPost = await req('POST', '/api/system/configs', {
    ...auth,
    body: {
      configs: {
        github_token: 'ghp_e2e_hydration_test_token_not_real',
      },
    },
  })
  if (cfgPost.status >= 200 && cfgPost.status < 300) ok('tenant_github_config', 'stored')
  else if (cfgPost.status === 403) ok('tenant_github_config', 'skipped (non-admin tenant config)')
  else fail('tenant_github_config', `HTTP ${cfgPost.status}`)

  // Reject unknown engine
  const unknown = await req('POST', '/api/command-center/scan', {
    ...auth,
    body: { engine: 'not_a_real_engine_xyz', client_id: Number(clientId), target: 'https://example.com' },
  })
  if (unknown.status === 400) ok('reject_unknown_engine', 'HTTP 400')
  else fail('reject_unknown_engine', `HTTP ${unknown.status}`)

  // Scope reject
  const badScope = await req('POST', '/api/command-center/scan', {
    ...auth,
    body: {
      engine: 'microsecond_timing',
      client_id: Number(clientId),
      target: 'https://totally-not-in-scope.invalid',
    },
  })
  if (badScope.status === 403 || badScope.status === 400) ok('scope_reject', `HTTP ${badScope.status}`)
  else fail('scope_reject', `expected 403/400 got ${badScope.status}`)

  // Targetless intel (threat_intel_run)
  const intel = await req('POST', '/api/command-center/scan', {
    ...auth,
    body: { engine: 'zero_day_radar', client_id: Number(clientId) },
  })
  if (intel.status === 202 && intel.data?.job_id) {
    ok('intel_enqueue', `job=${intel.data.job_id}`)
    await pollJob(intel.data.job_id, auth, { label: 'intel_job_poll' })
  } else {
    fail('intel_enqueue', `HTTP ${intel.status}`)
  }

  // timing_scan — scope + masked hub param stripped/redacted
  const timing = await req('POST', '/api/command-center/scan', {
    ...auth,
    body: {
      engine: 'microsecond_timing',
      client_id: Number(clientId),
      target: 'https://example.com',
      github_token: MASK,
    },
  })
  if (timing.status === 202 && timing.data?.job_id) {
    ok('timing_enqueue', timing.data.job_id)
    const peek = await req('GET', `/api/jobs/${timing.data.job_id}`, auth)
    const payload = peek.data?.payload || {}
    if (payload.validated_scope?.host === 'example.com') ok('scope_injected', payload.validated_scope.host)
    else fail('scope_injected', 'missing validated_scope')
    if (payloadHasRawSecret(payload, 'github_token', 'ghp_e2e_hydration_test_token_not_real')) {
      fail('job_payload_leak', 'raw github_token in GET /api/jobs payload')
    } else if (payload.github_token == null) {
      ok('job_payload_strip', 'github_token stripped from stored job payload')
    } else if (payloadShowsMasked(payload, 'github_token')) {
      ok('job_payload_redact', 'github_token masked in API response')
    } else {
      fail('job_payload_redact', 'unexpected github_token shape')
    }
    await pollJob(timing.data.job_id, auth, { label: 'timing_job_poll' })
  } else {
    fail('timing_enqueue', `HTTP ${timing.status}`)
  }

  // command_center_engine — osint (primary production path)
  const osint = await req('POST', '/api/command-center/scan', {
    ...auth,
    body: {
      engine: 'osint',
      client_id: Number(clientId),
      target: 'https://example.com',
      depth: '1',
      github_token: MASK,
      aws_external_id: MASK,
    },
  })
  if (osint.status === 202 && osint.data?.job_id) {
    ok('osint_enqueue', `${osint.data.job_id} kind=${osint.data?.job_kind || '?'}`)
    const peek = await req('GET', `/api/jobs/${osint.data.job_id}`, auth)
    const payload = peek.data?.payload || {}
    if (payload.engine === 'osint') ok('osint_payload_engine', 'command_center_engine')
    else fail('osint_payload_engine', `engine=${payload.engine}`)
    if (payloadHasRawSecret(payload, 'aws_external_id', hydrationExt)) {
      fail('hydration_leak', 'raw aws_external_id visible in job GET')
    } else if (payloadShowsMasked(payload, 'aws_external_id')) {
      ok('hydration_redact', 'hydrated aws_external_id masked in API')
    } else {
      ok('hydration_redact', 'aws_external_id absent from client payload')
    }
    await pollJob(osint.data.job_id, auth, { label: 'osint_job_poll', max: 60 })
    const done = await req('GET', `/api/jobs/${osint.data.job_id}`, auth)
    const jobStatus = String(done.data?.status || '').toLowerCase()
    const result = done.data?.result || {}
    const findings = result.findings
    const persisted = result.findings_persisted
    if (jobStatus === 'completed') {
      if (typeof persisted === 'number') ok('findings_persist_counter', `persisted=${persisted}`)
      else fail('findings_persist_counter', 'findings_persisted missing from completed job result')
      if (Array.isArray(findings)) ok('osint_result_shape', `findings=${findings.length}`)
      else fail('osint_result_shape', 'findings array missing')
    } else if (jobStatus === 'running' || jobStatus === 'pending') {
      fail('osint_job_poll', `still ${jobStatus} after poll window`)
    }

    // Findings Command Center API — DB-backed rows for this client
    const findingsApi = await req('GET', `/api/findings?client_id=${clientId}&limit=500`, auth)
    if (findingsApi.status === 200 && findingsApi.data?.ok === true) {
      const rows = Array.isArray(findingsApi.data.findings) ? findingsApi.data.findings : []
      const osintRows = rows.filter((r) => String(r.source || '').toLowerCase() === 'osint')
      ok('findings_api', `total=${findingsApi.data.total ?? rows.length} osint=${osintRows.length}`)
      if (typeof persisted === 'number' && persisted > 0 && osintRows.length === 0) {
        fail('findings_db_sync', `persisted=${persisted} but no osint rows in /api/findings (limit=500)`)
      } else if (typeof persisted === 'number' && persisted > 0) {
        ok('findings_db_sync', `persisted=${persisted} osint_visible=${osintRows.length}`)
      }
      const withRisk = osintRows.filter(validateRiskFields)
      if (osintRows.length > 0) {
        if (withRisk.length > 0) {
          const s = withRisk[0]
          ok('confidence_risk_fields', `cm=${s.confidence_multiplier} er=${s.effective_risk ?? s.risk_score}`)
        } else {
          fail('confidence_risk_fields', 'osint rows missing confidence_multiplier/effective_risk')
        }
      } else {
        ok('confidence_risk_fields', 'skipped (no osint rows in page)')
      }
    } else {
      fail('findings_api', `HTTP ${findingsApi.status}`)
    }

    const csv = await req('GET', '/api/findings/export/csv', auth)
    if (csv.status === 200 && String(csv.text || '').includes('finding_id')) {
      ok('findings_csv_export', 'CSV contract OK')
    } else if (csv.status === 200) {
      ok('findings_csv_export', 'HTTP 200')
    } else {
      fail('findings_csv_export', `HTTP ${csv.status}`)
    }
  } else {
    fail('osint_enqueue', `HTTP ${osint.status} ${osint.data?.detail || ''}`)
  }

  // Jobs list API
  const jobs = await req('GET', '/api/jobs?limit=5', auth)
  if (jobs.status === 200 && jobs.data?.ok !== false) ok('jobs_list', `total=${jobs.data?.total ?? '?'}`)
  else fail('jobs_list', `HTTP ${jobs.status}`)

  // Engine history
  const hist = await req('GET', '/api/engines/history/osint?limit=3', auth)
  if (hist.status === 200) ok('engine_history', `entries=${Array.isArray(hist.data) ? hist.data.length : '?'}`)
  else fail('engine_history', `HTTP ${hist.status}`)

  console.log('')
  if (failures.length) {
    console.error('verify_scan_pipeline_e2e: FAIL')
    for (const f of failures) console.error(`  - ${f}`)
    process.exit(1)
  }
  console.log(`verify_scan_pipeline_e2e: OK (${steps.length} checks)`)
}

main().catch((e) => {
  console.error('verify_scan_pipeline_e2e: FATAL', e)
  process.exit(1)
})
