import type { Page, Route } from '@playwright/test'

const MOCK_CLIENT = {
  id: 1,
  name: 'E2E Test Client',
  domains: '["https://example.com"]',
  domains_json: '["https://example.com"]',
}

function fulfillJson(route: Route, body: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: 'application/json; charset=utf-8',
    body: JSON.stringify(body),
  })
}

/**
 * Intercepts all `/api/**` calls so the SPA can authenticate and load every cockpit tab
 * without a live Rust server or database. Keeps EventSource telemetry open with a minimal SSE body.
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

    // EventSource — keep connection valid; clients close on error anyway.
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
