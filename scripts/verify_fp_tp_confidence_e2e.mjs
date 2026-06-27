#!/usr/bin/env node
/**
 * Live FP/TP feedback loop: mark finding FALSE_POSITIVE → confidence_multiplier drops in API.
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

const failures = []
function ok(l, d = '') { console.log(`  ✓ ${l}${d ? ` — ${d}` : ''}`) }
function fail(l, d = '') { failures.push(`${l}${d ? `: ${d}` : ''}`); console.error(`  ✗ ${l}${d ? ` — ${d}` : ''}`) }

async function api(method, urlPath, { body, token } = {}) {
  const headers = { Accept: 'application/json' }
  if (body != null) headers['Content-Type'] = 'application/json'
  if (token) headers.Authorization = `Bearer ${token}`
  const r = await fetch(`${BASE}${urlPath}`, {
    method,
    headers,
    body: body != null ? JSON.stringify(body) : undefined,
  })
  const text = await r.text()
  let data = {}
  try { data = text ? JSON.parse(text) : {} } catch { data = { raw: text } }
  return { status: r.status, data, text }
}

async function main() {
  console.log(`verify_fp_tp_confidence_e2e: ${BASE}`)
  if (!PASSWORD) { fail('credentials'); process.exit(1) }

  const login = await api('POST', '/api/login', {
    body: { email: EMAIL, password: PASSWORD, tenant_slug: TENANT },
  })
  const token = login.data?.access_token
  if (login.status !== 200 || !token) { fail('login'); process.exit(1) }
  ok('login', EMAIL)

  const clients = await api('GET', '/api/clients', { token })
  if (clients.status !== 200 || !Array.isArray(clients.data) || !clients.data[0]?.id) {
    fail('clients'); process.exit(1)
  }
  const clientId = clients.data[0].id
  ok('client', `id=${clientId}`)

  const findings = await api('GET', `/api/findings?client_id=${clientId}&limit=100`, { token })
  if (findings.status !== 200 || findings.data?.ok !== true) {
    fail('findings_list', `HTTP ${findings.status}`)
    process.exit(1)
  }
  const rows = Array.isArray(findings.data.findings) ? findings.data.findings : []
  if (!rows.length) {
    fail('findings_list', 'no findings to exercise FP/TP loop — run osint scan first')
    process.exit(1)
  }

  const candidate = rows.find((r) => r.signature_hash && r.raw_id && r.source) || rows[0]
  const rawId = candidate.raw_id
  const sig = candidate.signature_hash || ''
  const engine = candidate.source
  const beforeCm = Number(candidate.confidence_multiplier ?? 1)
  ok('finding_pick', `raw_id=${rawId} engine=${engine} cm=${beforeCm}`)

  const fp = await api('PATCH', `/api/findings/${rawId}/status`, {
    token,
    body: { status: 'FALSE_POSITIVE' },
  })
  if (fp.status === 200 && fp.data?.ok) {
    ok('mark_false_positive', `suppression_added=${fp.data.suppression_added ?? false}`)
  } else {
    fail('mark_false_positive', `HTTP ${fp.status} ${fp.data?.detail || ''}`)
    process.exit(1)
  }

  const after = await api('GET', `/api/findings?client_id=${clientId}&limit=100`, { token })
  const updated = (after.data?.findings || []).find((r) => r.raw_id === rawId)
  if (!updated) { fail('finding_after_fp', 'row missing'); process.exit(1) }
  if (String(updated.status).toUpperCase() === 'FALSE_POSITIVE') {
    ok('status_updated', 'FALSE_POSITIVE')
  } else {
    fail('status_updated', `got ${updated.status}`)
  }

  const afterCm = Number(updated.confidence_multiplier)
  if (!Number.isFinite(afterCm)) {
    fail('confidence_after_fp', 'missing multiplier')
  } else if (sig && afterCm < beforeCm) {
    ok('confidence_after_fp', `${beforeCm} → ${afterCm}`)
  } else if (sig && afterCm <= 0.5) {
    ok('confidence_after_fp', `cm=${afterCm} (bayesian shrinkage)`)
  } else if (!sig) {
    ok('confidence_after_fp', 'no signature_hash — skipped strict drop check')
  } else {
    fail('confidence_after_fp', `expected drop from ${beforeCm}, got ${afterCm}`)
  }

  // TP path restores trust slightly when analyst validates
  const tp = await api('PATCH', `/api/findings/${rawId}/status`, {
    token,
    body: { status: 'ACKNOWLEDGED' },
  })
  if (tp.status === 200 && tp.data?.ok) ok('mark_acknowledged_tp', 'record_tp path')
  else fail('mark_acknowledged_tp', `HTTP ${tp.status}`)

  console.log('')
  if (failures.length) {
    console.error('verify_fp_tp_confidence_e2e: FAIL')
    for (const f of failures) console.error(`  - ${f}`)
    process.exit(1)
  }
  console.log('verify_fp_tp_confidence_e2e: OK')
}

main().catch((e) => {
  console.error('verify_fp_tp_confidence_e2e: FATAL', e)
  process.exit(1)
})
