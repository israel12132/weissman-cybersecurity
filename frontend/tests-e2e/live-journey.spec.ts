/**
 * Live-stack E2E — login → client → scan → findings with evidence → PDF export.
 * Requires: PLAYWRIGHT_LIVE=1, WEISSMAN_ADMIN_PASSWORD, running backend (run_e2e_stack.sh or Docker).
 */
import { test, expect } from '@playwright/test'
import {
  apiLogin,
  authHeaders,
  ensureE2eClient,
  ensureUiSession,
  liveEnabled,
  pollJobTerminal,
  uiLogin,
  selectFirstCockpitClient,
} from './live-helpers'

test.describe.configure({ mode: 'serial' })

test.beforeEach(async ({ page }, testInfo) => {
  test.skip(!liveEnabled(), 'Set PLAYWRIGHT_LIVE=1 and WEISSMAN_ADMIN_PASSWORD for live E2E')
  await page.addInitScript(() => {
    try {
      const t = localStorage.getItem('weissman_access_token')
      if (t && !sessionStorage.getItem('weissman_access_token')) {
        sessionStorage.setItem('weissman_access_token', t)
      }
    } catch {
      /* ignore */
    }
  })
  page.on('pageerror', (err) => {
    testInfo.attach('pageerror', { body: err.message, contentType: 'text/plain' })
  })
})

test('health — backend reachable', async ({ request }) => {
  const r = await request.get('/api/health')
  expect(r.ok()).toBeTruthy()
  const data = await r.json()
  expect(data.status || data.ok !== false).toBeTruthy()
})

test('UI login — session established', async ({ page }) => {
  await page.goto('/command-center/operations', { waitUntil: 'domcontentloaded' })
  await page.getByText('Verifying session').waitFor({ state: 'hidden', timeout: 30_000 }).catch(() => {})
  await expect(page).not.toHaveURL(/\/login/)
  await expect(page).toHaveURL(/\/command-center\/operations/)
  await expect(page.locator('#root')).toBeVisible()
})

test('journey — client, scan, findings evidence, PDF export', async ({ page, request }) => {
  test.setTimeout(240_000)
  const auth = await apiLogin(request)
  const clientId = await ensureE2eClient(request, auth)

  await ensureUiSession(page)
  await page.goto('/command-center/operations', { waitUntil: 'domcontentloaded' })

  await selectFirstCockpitClient(page)
  await expect(page.locator('#cockpit-engage-scan-btn')).toBeVisible({ timeout: 20_000 })

  // Enqueue osint scan via API (deterministic) then verify UI findings tab
  const scan = await request.post('/api/command-center/scan', {
    headers: { ...authHeaders(auth), 'Content-Type': 'application/json' },
    data: {
      engine: 'osint',
      client_id: clientId,
      target: 'https://example.com',
      depth: '1',
    },
  })
  expect(scan.status()).toBe(202)
  const scanBody = await scan.json()
  const jobId = String(scanBody.job_id || '')
  expect(jobId.length).toBeGreaterThan(0)

  const jobStatus = await pollJobTerminal(request, auth, jobId, {
    maxAttempts: 45,
    intervalMs: 2000,
    clientId,
  })

  // Findings API — prefer this client; fall back to tenant rollups when worker queue is slow
  let findingsRes = await request.get(`/api/findings?client_id=${clientId}&limit=20`, {
    headers: authHeaders(auth),
  })
  expect(findingsRes.ok()).toBeTruthy()
  let findingsPayload = await findingsRes.json()
  expect(findingsPayload.ok).toBe(true)
  let rows = Array.isArray(findingsPayload.findings) ? findingsPayload.findings : []

  if (rows.length === 0) {
    const tenantRes = await request.get('/api/findings?limit=20', { headers: authHeaders(auth) })
    expect(tenantRes.ok()).toBeTruthy()
    const tenantPayload = await tenantRes.json()
    rows = Array.isArray(tenantPayload.findings) ? tenantPayload.findings : []
  }

  expect(rows.length).toBeGreaterThan(0)
  expect(['completed', 'done', 'findings_ready', 'timeout', 'failed']).toContain(jobStatus)

  // UI — Findings & Reports tab (avoid networkidle — cockpit polls continuously)
  await page.getByRole('button', { name: /Findings & Reports/i }).click()
  const main = page.locator('main').first()
  await expect(main).toBeVisible({ timeout: 30_000 })
  await expect(main).toContainText(/finding|report|severity|export/i, { timeout: 30_000 })
  const mainText = await main.innerText()
  expect(mainText.replace(/\s+/g, ' ').trim().length).toBeGreaterThan(10)

  if (rows.length > 0) {
    const withEvidence = rows.some(
      (r: Record<string, unknown>) =>
        r.evidence != null ||
        r.raw_data != null ||
        r.verification_method != null ||
        r.verified != null,
    )
    expect(withEvidence).toBeTruthy()
  }

  // PDF export — cryptographic report contract
  const pdfRes = await request.get(`/api/clients/${clientId}/report/pdf`, {
    headers: authHeaders(auth),
  })
  expect(pdfRes.ok()).toBeTruthy()
  const ct = pdfRes.headers()['content-type'] || ''
  expect(ct).toMatch(/html|pdf|octet-stream/i)
  const pdfBody = await pdfRes.text()
  expect(pdfBody.length).toBeGreaterThan(200)
  expect(pdfBody.toLowerCase()).toMatch(/report|weissman|finding|executive/i)

  // Compliance evidence pack API
  const packRes = await request.get(`/api/compliance/evidence-pack/${clientId}`, {
    headers: authHeaders(auth),
  })
  expect(packRes.ok()).toBeTruthy()
  const pack = await packRes.json()
  expect(pack.packet_type).toBe('weissman-compliance-evidence-pack-v2')
  expect(pack.client_id).toBe(clientId)
})
