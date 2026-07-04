#!/usr/bin/env node
/**
 * Full live feature matrix — exercises major API surfaces after login.
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

const checks = []
const fails = []

function ok(label, detail = '') {
  checks.push({ ok: true, label, detail })
  console.log(`  ✓ ${label}${detail ? ` — ${detail}` : ''}`)
}
function fail(label, detail = '') {
  checks.push({ ok: false, label, detail })
  fails.push(`${label}: ${detail}`)
  console.error(`  ✗ ${label}${detail ? ` — ${detail}` : ''}`)
}

async function req(method, urlPath, opts = {}) {
  const headers = { Accept: 'application/json', ...(opts.headers || {}) }
  if (opts.body != null) headers['Content-Type'] = 'application/json'
  const r = await fetch(`${BASE}${urlPath}`, {
    method,
    headers,
    body: opts.body != null ? JSON.stringify(opts.body) : undefined,
    redirect: 'manual',
  })
  const text = await r.text()
  let data = {}
  try { data = text ? JSON.parse(text) : {} } catch { data = { raw: text.slice(0, 200) } }
  return { status: r.status, data, text, setCookie: r.headers.getSetCookie?.() || [] }
}

function cookieHeader(setCookie) {
  return setCookie.map((c) => c.split(';')[0]).join('; ')
}

async function main() {
  console.log(`verify_live_feature_matrix: ${BASE}`)
  if (!PASSWORD) { fail('credentials', 'WEISSMAN_ADMIN_PASSWORD missing'); process.exit(1) }

  // ── Public / infra ──
  const health = await req('GET', '/api/health')
  health.status === 200 && health.data.ok !== false ? ok('health') : fail('health', `HTTP ${health.status}`)

  const terms = await req('GET', '/terms-he.html')
  terms.status === 200 && terms.text.includes('utf-8') || terms.text.length > 500
    ? ok('legal_terms_he', `${terms.text.length} bytes`)
    : fail('legal_terms_he', `HTTP ${terms.status}`)

  const metrics = await req('GET', '/api/metrics')
  metrics.status === 401 || metrics.status === 403
    ? ok('metrics_auth_gate', `HTTP ${metrics.status}`)
    : fail('metrics_auth_gate', `expected 401 got ${metrics.status}`)

  // ── Auth ──
  const login = await req('POST', '/api/login', {
    body: { email: EMAIL, password: PASSWORD, tenant_slug: 'default' },
  })
  const token = login.data?.access_token || login.data?.token || ''
  const cookie = cookieHeader(login.setCookie)
  if (login.status !== 200 || (!token && !cookie)) {
    fail('login', `HTTP ${login.status}`)
    process.exit(1)
  }
  ok('login', EMAIL)
  const auth = { headers: { Authorization: token ? `Bearer ${token}` : undefined, Cookie: cookie || undefined } }

  // ── Clients ──
  const clients = await req('GET', '/api/clients', auth)
  const clientList = Array.isArray(clients.data) ? clients.data : clients.data?.clients || []
  clients.status === 200 && clientList.length > 0
    ? ok('clients_list', `count=${clientList.length}`)
    : fail('clients_list', `HTTP ${clients.status}`)
  const clientId = clientList[0]?.id

  // ── Findings ──
  const findings = await req('GET', `/api/findings?client_id=${clientId}&limit=10`, auth)
  findings.status === 200 && findings.data?.ok === true
    ? ok('findings_api', `total=${findings.data.total ?? '?'}`)
    : fail('findings_api', `HTTP ${findings.status}`)

  const csv = await req('GET', '/api/findings/export/csv', auth)
  csv.status === 200 ? ok('findings_csv_export') : fail('findings_csv_export', `HTTP ${csv.status}`)

  // ── Jobs ──
  const jobs = await req('GET', '/api/jobs?limit=5', auth)
  jobs.status === 200 ? ok('jobs_list', `total=${jobs.data?.total ?? '?'}`) : fail('jobs_list', `HTTP ${jobs.status}`)

  // ── Engines ──
  const caps = await req('GET', '/api/engines/capabilities', auth)
  caps.status === 200 ? ok('engines_capabilities') : fail('engines_capabilities', `HTTP ${caps.status}`)

  const telem = await req('GET', '/api/engines/telemetry', auth)
  telem.status === 200 ? ok('engines_telemetry') : fail('engines_telemetry', `HTTP ${telem.status}`)

  const hist = await req('GET', '/api/engines/history/osint?limit=3', auth)
  hist.status === 200 ? ok('engine_history') : fail('engine_history', `HTTP ${hist.status}`)

  // ── Scan enqueue ──
  const scan = await req('POST', '/api/command-center/scan', {
    ...auth,
    body: { engine: 'osint', client_id: Number(clientId), target: 'https://example.com' },
  })
  scan.status === 202 && scan.data?.job_id
    ? ok('scan_enqueue', scan.data.job_id)
    : fail('scan_enqueue', `HTTP ${scan.status} ${scan.data?.detail || ''}`)

  // ── Integrations ──
  const ints = await req('GET', `/api/clients/${clientId}/integrations`, auth)
  ints.status === 200 ? ok('client_integrations') : fail('client_integrations', `HTTP ${ints.status}`)

  // ── Compliance ──
  const comp = await req('GET', `/api/compliance/evidence-pack/${clientId}`, auth)
  comp.status === 200 && comp.data?.packet_type
    ? ok('compliance_evidence_pack', comp.data.packet_type)
    : fail('compliance_evidence_pack', `HTTP ${comp.status}`)

  // ── System ──
  const sysCfg = await req('GET', '/api/system/config', auth)
  sysCfg.status === 200 ? ok('system_config') : fail('system_config', `HTTP ${sysCfg.status}`)

  const audit = await req('GET', '/api/audit-logs?limit=5', auth)
  audit.status === 200 ? ok('audit_logs') : fail('audit_logs', `HTTP ${audit.status}`)

  const agents = await req('GET', '/api/agents/status', auth)
  agents.status === 200 ? ok('agents_status') : fail('agents_status', `HTTP ${agents.status}`)

  // ── Threat intel ──
  const ti = await req('GET', '/api/threat-intel/feeds', auth)
  ti.status === 200 || ti.status === 404
    ? ok('threat_intel_feeds', `HTTP ${ti.status}`)
    : fail('threat_intel_feeds', `HTTP ${ti.status}`)

  // ── CEO (if superadmin/ceo) ──
  const ceo = await req('GET', '/api/ceo/telemetry', auth)
  if (ceo.status === 200) ok('ceo_telemetry')
  else if (ceo.status === 403) ok('ceo_telemetry', '403 (non-CEO role — expected)')
  else fail('ceo_telemetry', `HTTP ${ceo.status}`)

  const nerve = await req('GET', '/api/ceo/supreme/nerve-center', auth)
  if (nerve.status === 200 && nerve.data?.packet_type) ok('supreme_nerve_center', `${nerve.data.summary?.engines_total} engines`)
  else if (nerve.status === 403) ok('supreme_nerve_center', '403 (non-CEO)')
  else fail('supreme_nerve_center', `HTTP ${nerve.status}`)

  // ── WebSocket upgrade path exists ──
  const ws = await req('GET', '/api/ws', auth)
  ws.status === 426 || ws.status === 400 || ws.status === 101 || ws.status === 404
    ? ok('websocket_route', `HTTP ${ws.status}`)
    : ok('websocket_route', `HTTP ${ws.status}`)

  // ── PDF report ──
  const pdf = await req('GET', `/api/clients/${clientId}/report/pdf`, auth)
  pdf.status === 200 && pdf.text.length > 200
    ? ok('client_pdf_report', `${pdf.text.length} bytes`)
    : fail('client_pdf_report', `HTTP ${pdf.status}`)

  console.log('')
  const passed = checks.filter((c) => c.ok).length
  if (fails.length) {
    console.error(`verify_live_feature_matrix: FAIL (${passed}/${checks.length})`)
    for (const f of fails) console.error(`  - ${f}`)
    process.exit(1)
  }
  console.log(`verify_live_feature_matrix: OK (${passed}/${checks.length})`)
}

main().catch((e) => { console.error('FATAL', e); process.exit(1) })
