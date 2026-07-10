import type { Page, Route } from '@playwright/test'

const MOCK_CLIENT = {
  id: 1,
  name: 'E2E Test Client',
  domains: '["https://example.com"]',
  domains_json: '["https://example.com"]',
}

// Sample findings so the Findings console renders real rows for driving the
// selection / bulk-status / saved-views / URL-filter / density features in-browser.
const MOCK_FINDINGS = [
  { id: 101, raw_id: 101, severity: 'critical', status: 'OPEN', title: 'SQL Injection in /login', type: 'sqli', description: 'Blind SQL injection on username', source: 'sqli_advanced', engine: 'sqli_advanced', target: 'https://example.com/login', cvss_score: 9.1, priority_score: 95, compliance: ['PCI-DSS 6.5.1'] },
  { id: 102, raw_id: 102, severity: 'high', status: 'OPEN', title: 'Reflected XSS in search', type: 'xss', description: 'Reflected XSS via q parameter', source: 'xss_engine', engine: 'xss_engine', target: 'https://example.com/search', cvss_score: 7.4 },
  { id: 103, raw_id: 103, severity: 'medium', status: 'FIXED', title: 'Missing HSTS header', type: 'header', description: 'No Strict-Transport-Security header', source: 'pki_tls', engine: 'pki_tls', target: 'https://example.com', cvss_score: 4.2 },
  { id: 104, raw_id: 104, severity: 'critical', status: 'OPEN', title: 'Exposed S3 bucket', type: 'cloud', description: 'Publicly readable bucket', source: 'aws_attack', engine: 'aws_attack', target: 's3://example-public', cvss_score: 9.8, kev_listed: true },
]

function fulfillJson(route: Route, body: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: 'application/json; charset=utf-8',
    body: JSON.stringify(body),
  })
}

/**
 * Intercepts all `/api/**` calls so the SPA can authenticate and load every cockpit tab
 * without a live Rust server or database. Keeps fetch-based SSE telemetry open with a minimal SSE body.
 */
export async function installCommandCenterApiMocks(page: Page): Promise<void> {
  await page.route('**/api/**', async (route) => {
    const req = route.request()
    const url = new URL(req.url())
    const path = url.pathname
    const method = req.method()

    if (method === 'OPTIONS') {
      return route.fulfill({
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
          'Access-Control-Allow-Headers': '*',
        },
      })
    }

    // SSE telemetry — fetch ReadableStream clients accept a single fulfilled body in e2e mocks.
    if (path === '/api/telemetry/stream' && method === 'GET') {
      return route.fulfill({
        status: 200,
        headers: {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
        },
        body: 'retry: 60000\ndata: {"event":"progress","engine":"e2e","message":"mock"}\n\n',
      })
    }

    if (path === '/api/auth/me' && method === 'GET') {
      return fulfillJson(route, {
        ok: true,
        email: 'e2e@weissman.test',
        role: 'analyst',
        is_superadmin: false,
      })
    }

    if (path === '/api/clients' && method === 'GET') {
      return fulfillJson(route, [MOCK_CLIENT])
    }

    if (path === '/api/clients' && method === 'POST') {
      return fulfillJson(route, { id: 2, name: 'New', domains: '[]' })
    }

    if (/^\/api\/clients\/\d+$/.test(path) && method === 'DELETE') {
      return route.fulfill({ status: 204 })
    }

    const configMatch = path.match(/^\/api\/clients\/(\d+)\/config$/)
    if (/^\/api\/clients\/\d+\/integrations$/.test(path) && method === 'GET') {
      return fulfillJson(route, { integrations: {} })
    }

    if (configMatch && method === 'GET') {
      return fulfillJson(route, {
        enabled_engines: ['osint', 'asm', 'semantic_ai_fuzz'],
        roe_mode: 'safe_proofs',
        stealth_level: 50,
        auto_harvest: false,
        industrial_ot_enabled: false,
      })
    }

    if (/^\/api\/clients\/\d+\/findings$/.test(path) && method === 'GET') {
      return fulfillJson(route, { findings: [] })
    }

    // Findings console (FindingsCommandCenter / VulnIntelDashboard)
    if (path === '/api/findings' && method === 'GET') {
      return fulfillJson(route, MOCK_FINDINGS)
    }
    if (/^\/api\/findings\/\d+\/status$/.test(path) && method === 'PATCH') {
      const body = (() => { try { return req.postDataJSON() } catch { return {} } })()
      return fulfillJson(route, { ok: true, status: body?.status || 'OPEN' })
    }
    if (/^\/api\/findings\/\d+\/verify$/.test(path) && method === 'POST') {
      return fulfillJson(route, { ok: true, verdict: 'confirmed' })
    }
    if (path === '/api/findings/export/csv' && method === 'GET') {
      return route.fulfill({ status: 200, contentType: 'text/csv', headers: { 'content-disposition': 'attachment; filename="findings.csv"' }, body: 'id,title\n101,SQLi\n' })
    }
    if (path === '/api/config/public' && method === 'GET') {
      return fulfillJson(route, { region: 'us-e2e' })
    }
    if (path.startsWith('/api/search') && method === 'GET') {
      return fulfillJson(route, { results: [{ type: 'finding', id: 101, title: 'SQL Injection in /login', path: '/findings', icon: '🔎' }] })
    }

    if (/^\/api\/clients\/\d+\/risk-graph$/.test(path) && method === 'GET') {
      return fulfillJson(route, { nodes: [], edges: [] })
    }

    if (/^\/api\/clients\/\d+\/risk-graph$/.test(path) && method === 'POST') {
      return fulfillJson(route, { ok: true })
    }

    if (/^\/api\/clients\/\d+\/identity-contexts$/.test(path)) {
      if (method === 'GET') return fulfillJson(route, { contexts: [] })
      if (method === 'POST') return fulfillJson(route, { ok: true })
    }
    if (/^\/api\/clients\/\d+\/identity-contexts\/[^/]+$/.test(path) && method === 'DELETE') {
      return fulfillJson(route, { ok: true })
    }

    if (/^\/api\/clients\/\d+\/privilege-escalation$/.test(path) && method === 'GET') {
      return fulfillJson(route, { events: [] })
    }

    if (/^\/api\/clients\/\d+\/deception/.test(path)) {
      return fulfillJson(route, { assets: [] })
    }

    if (/^\/api\/clients\/\d+\/heal-requests$/.test(path) && method === 'GET') {
      return fulfillJson(route, [])
    }

    if (/^\/api\/clients\/\d+\/auto-heal$/.test(path) && method === 'POST') {
      return fulfillJson(route, { ok: true, job_id: 'e2e' })
    }

    if (/^\/api\/heal-verify\/.+\/steps$/.test(path) && method === 'GET') {
      return fulfillJson(route, { steps: [] })
    }

    if (/^\/api\/clients\/\d+\/containment-rules$/.test(path)) {
      if (method === 'GET') return fulfillJson(route, { rules: [] })
      if (method === 'PATCH' || method === 'POST') return fulfillJson(route, { ok: true })
    }

    if (/^\/api\/clients\/\d+\/containment\/execute$/.test(path) && method === 'POST') {
      return fulfillJson(route, { ok: true })
    }

    if (/^\/api\/clients\/\d+\/llm-fuzz\/(summary|events)$/.test(path) && method === 'GET') {
      return fulfillJson(route, method === 'GET' && path.endsWith('summary') ? { runs: 0 } : { events: [] })
    }

    if (/^\/api\/clients\/\d+\/llm-fuzz\/run$/.test(path) && method === 'POST') {
      return fulfillJson(route, { ok: true })
    }

    if (/^\/api\/clients\/\d+\/swarm\/run$/.test(path) && method === 'POST') {
      return fulfillJson(route, { ok: true })
    }

    if (/^\/api\/clients\/\d+\/cloud-integration$/.test(path) && method === 'PATCH') {
      return fulfillJson(route, { ok: true })
    }

    if (/^\/api\/clients\/\d+\/cloud-scan\/run$/.test(path) && method === 'POST') {
      return fulfillJson(route, { ok: true, findings_count: 0 })
    }

    if (path.startsWith('/api/compliance/posture') && method === 'GET') {
      return fulfillJson(route, { frameworks: [] })
    }

    if (path === '/api/audit-logs' && method === 'GET') {
      return fulfillJson(route, { logs: [] })
    }

    if (path === '/api/dag' && method === 'GET') {
      return fulfillJson(route, { nodes: [], edges: [], stage_to_nodes: {} })
    }

    if (path === '/api/pipeline/state' && (method === 'GET' || method === 'PATCH')) {
      return fulfillJson(route, { run_id: null, states: [], stage_labels: [] })
    }

    if (path === '/api/edge-swarm/nodes' && method === 'GET') {
      return fulfillJson(route, { nodes: [] })
    }

    if (path === '/api/edge-fuzz/manifest' && method === 'GET') {
      return fulfillJson(route, { payloads: [] })
    }

    if (path === '/api/dashboard/stats' && method === 'GET') {
      return fulfillJson(route, {
        total_vulnerabilities: 0,
        security_score: 85,
        active_scans: false,
      })
    }

    if (path === '/api/enterprise/settings' && (method === 'GET' || method === 'PATCH')) {
      return fulfillJson(route, { global_safe_mode: false, alert_webhook_url: '' })
    }

    if (path === '/api/health' && method === 'GET') {
      return fulfillJson(route, {
        uptime_secs: 120,
        db_bytes: 1024,
        scanning_active: false,
      })
    }

    if (path === '/api/system/backup' && method === 'POST') {
      return fulfillJson(route, { path: '/tmp/e2e-backup.sql' })
    }

    if (path === '/api/reports/executive' && method === 'GET') {
      return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' })
    }

    if (path === '/api/scan/run-all' && method === 'POST') {
      return fulfillJson(route, { message: 'e2e' })
    }

    if (path === '/api/poe-scan/run' && method === 'POST') {
      return fulfillJson(route, { job_id: 'e2e-job' })
    }

    if (path === '/api/latency-probe' && method === 'POST') {
      return fulfillJson(route, { latency_ms: 12 })
    }

    // Safe default — many routes only check r.ok
    return fulfillJson(route, { ok: true, detail: null })
  })
}
