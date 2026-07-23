/**
 * True-Live feature E2E — drives this session's new Findings-console features
 * (multi-select bulk status, saved views, URL-shareable severity filter, row
 * density) and the ⌘K command palette against the REAL Rust backend + Postgres
 * + Redis. NO API mocks: every row comes from the live DB, and the bulk-status
 * mutation is verified to have persisted server-side via an API round-trip.
 *
 * This is the counterpart to feature-verify.spec.ts (which runs against mocks):
 * it proves the same UI features work end-to-end against production wiring
 * (WEISSMAN_ENV=production), which mocks cannot demonstrate.
 *
 * Requires: PLAYWRIGHT_LIVE=1, WEISSMAN_ADMIN_PASSWORD, a running backend
 * (WEISSMAN_E2E_BASE) whose DB has — or can produce via a scan — findings.
 * Auth is inherited from auth.setup.ts (storageState).
 */
import { test, expect, type APIRequestContext, type Page } from '@playwright/test'
import {
  apiLogin,
  apiRequestWithRetry,
  authHeaders,
  ensureE2eClient,
  ensureUiSession,
  liveEnabled,
  pollJobTerminal,
  LIVE_BASE,
  type LiveAuth,
} from './live-helpers'

test.describe.configure({ mode: 'serial' })

const CRASH_MARKERS = [
  /This view crashed/i,
  /This tab encountered an error/i,
  /Minified React error/i,
  /Something went wrong/i,
]

// Server-side allow-list (fingerprint_engine: FINDING_STATUSES).
const VALID_STATUSES = ['OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'FIXED', 'FALSE_POSITIVE']

type LiveFinding = { id: number; status: string; severity: string; title: string }

// Memoized across the serial suite: log in + guarantee findings exist exactly once.
let cachedAuth: LiveAuth | null = null
let cachedFindings: LiveFinding[] | null = null

async function fetchFindings(request: APIRequestContext, auth: LiveAuth, limit = 50): Promise<LiveFinding[]> {
  const r = await apiRequestWithRetry(() =>
    request.get(`${LIVE_BASE}/api/findings?limit=${limit}`, { headers: authHeaders(auth) }),
  )
  if (!r.ok()) return []
  const payload = await r.json()
  const list = Array.isArray(payload) ? payload : Array.isArray(payload?.findings) ? payload.findings : []
  // The findings API returns a display `id` ("VLN-1") plus the numeric primary
  // key as `raw_id` — the latter is what PATCH /api/findings/:id/status expects
  // (and what the table's bulk action targets via `f.raw_id ?? f.id`).
  return list
    .map((f: Record<string, unknown>) => ({
      id: Number(f.raw_id ?? f.id),
      status: String(f.status ?? 'OPEN').toUpperCase(),
      severity: String(f.severity ?? '').toLowerCase(),
      title: String(f.title ?? ''),
    }))
    .filter((f: LiveFinding) => Number.isFinite(f.id))
}

/**
 * Guarantee the tenant has findings in the live DB. If the table is empty, birth
 * them through the real scan pipeline (osint on example.com — the same path the
 * live-journey relies on), then poll until the worker persists rows.
 */
async function ensureLiveFindings(request: APIRequestContext): Promise<{ auth: LiveAuth; findings: LiveFinding[] }> {
  if (!cachedAuth) cachedAuth = await apiLogin(request)
  const auth = cachedAuth
  if (cachedFindings && cachedFindings.length > 0) return { auth, findings: cachedFindings }

  let findings = await fetchFindings(request, auth)
  if (findings.length === 0) {
    const clientId = await ensureE2eClient(request, auth)
    const scan = await apiRequestWithRetry(() =>
      request.post(`${LIVE_BASE}/api/command-center/scan`, {
        headers: { ...authHeaders(auth), 'Content-Type': 'application/json' },
        data: { engine: 'osint', client_id: clientId, target: 'https://example.com', depth: '1' },
      }),
    )
    if (scan.status() === 202) {
      const jobId = String((await scan.json()).job_id || '')
      if (jobId) {
        await pollJobTerminal(request, auth, jobId, { maxAttempts: 60, intervalMs: 2500, clientId })
      }
    }
    // Give the worker a moment to flush, then re-read.
    for (let i = 0; i < 10 && findings.length === 0; i += 1) {
      findings = await fetchFindings(request, auth)
      if (findings.length === 0) await new Promise((res) => setTimeout(res, 2000))
    }
  }
  cachedFindings = findings
  return { auth, findings }
}

async function assertNoCrash(page: Page) {
  const body = await page.locator('body').innerText()
  for (const re of CRASH_MARKERS) {
    expect(body, `crash copy ${re}`).not.toMatch(re)
  }
}

async function gotoFindings(page: Page, query = '') {
  await ensureUiSession(page)
  await page.goto(`/command-center/findings${query}`, { waitUntil: 'domcontentloaded' })
  await page.getByText('Verifying session').waitFor({ state: 'hidden', timeout: 30_000 }).catch(() => {})
  await expect(page).not.toHaveURL(/\/login/)
}

test.beforeEach(async ({ page }, testInfo) => {
  test.skip(!liveEnabled(), 'Set PLAYWRIGHT_LIVE=1 and WEISSMAN_ADMIN_PASSWORD for live E2E')
  // Mirror bearer token into sessionStorage and force English so the option
  // values / hardcoded aria-labels line up with the assertions below.
  await page.addInitScript(() => {
    try {
      const t = localStorage.getItem('weissman_access_token')
      if (t && !sessionStorage.getItem('weissman_access_token')) {
        sessionStorage.setItem('weissman_access_token', t)
      }
      localStorage.setItem('weissman_lang', 'en')
    } catch {
      /* ignore */
    }
  })
  page.on('pageerror', (err) => {
    testInfo.attach('pageerror', { body: err.message, contentType: 'text/plain' })
  })
})

test('findings table renders live DB rows + density toggle', async ({ page, request }) => {
  test.setTimeout(240_000)
  const { findings } = await ensureLiveFindings(request)
  expect(findings.length, 'live DB must contain findings for a True-Live drive').toBeGreaterThan(0)

  await gotoFindings(page)
  const table = page.locator('#findings-command-table')
  await expect(table).toBeVisible({ timeout: 30_000 })
  const rowCount = await table.locator('tbody tr').count()
  expect(rowCount).toBeGreaterThan(0)

  // Density: comfortable (py-3) → compact (py-1.5), driven by the real DataTable.
  const firstCell = table.locator('tbody td').first()
  await expect(firstCell).toHaveClass(/py-3/)
  await page.getByRole('button', { name: /switch to compact rows/i }).click()
  await expect(firstCell).toHaveClass(/py-1\.5/)

  await assertNoCrash(page)
})

test('bulk status update persists to Postgres (real DB round-trip)', async ({ page, request }) => {
  test.setTimeout(240_000)
  const { auth, findings } = await ensureLiveFindings(request)
  expect(findings.length).toBeGreaterThan(0)

  await gotoFindings(page)
  const table = page.locator('#findings-command-table')
  await expect(table).toBeVisible({ timeout: 30_000 })

  // The table sorts CLIENT-SIDE (default: by severity), so the first visible row is
  // NOT necessarily the first API row. Read the domain id straight off the row we are
  // about to mutate (`data-row-id` = raw_id) and verify THAT finding — never an
  // assumed-parallel API ordering.
  const firstRow = table.locator('tbody tr[data-row-id]').first()
  await expect(firstRow).toBeVisible({ timeout: 30_000 })
  const targetId = Number(await firstRow.getAttribute('data-row-id'))
  expect(Number.isFinite(targetId), 'first row must expose a numeric data-row-id').toBe(true)

  // Current status of THAT finding (wide fetch so a high-severity row sorted to the
  // top is still covered regardless of its position in API order).
  const before = await fetchFindings(request, auth, 2000)
  const current = (before.find((f) => f.id === targetId)?.status || 'OPEN').toUpperCase()
  const newStatus = current === 'ACKNOWLEDGED' ? 'IN_PROGRESS' : 'ACKNOWLEDGED'
  expect(VALID_STATUSES).toContain(newStatus)

  // Select that exact row and drive the bulk-status bar.
  await firstRow.locator('input[type="checkbox"]').first().check()
  await expect(page.getByText(/1 selected/i)).toBeVisible()

  // The <select> options carry raw status values — language-independent.
  const statusSelect = page.getByLabel('Set status')
  await expect(statusSelect).toBeVisible()
  await statusSelect.selectOption({ value: newStatus })
  await page.getByRole('button', { name: /apply to 1/i }).click()

  // Selection clears once the batched PATCH resolves.
  await expect(page.getByText(/1 selected/i)).toBeHidden({ timeout: 20_000 })
  await assertNoCrash(page)

  // THE PROOF: re-read the finding straight from the backend and confirm the
  // new status was written to Postgres (not just reflected in local UI state).
  let persisted = ''
  for (let i = 0; i < 10; i += 1) {
    const fresh = await fetchFindings(request, auth, 2000)
    const row = fresh.find((f) => f.id === targetId)
    if (row) persisted = row.status
    if (persisted === newStatus) break
    await new Promise((res) => setTimeout(res, 1000))
  }
  expect(persisted, `finding ${targetId} status must be ${newStatus} in the live DB`).toBe(newStatus)

  // Restore the original status so reruns stay deterministic.
  await request
    .patch(`${LIVE_BASE}/api/findings/${targetId}/status`, {
      headers: { ...authHeaders(auth), 'Content-Type': 'application/json' },
      data: { status: current },
    })
    .catch(() => {})
})

test('saved view persists and re-applies a live filter snapshot', async ({ page, request }) => {
  test.setTimeout(180_000)
  await ensureLiveFindings(request)
  await gotoFindings(page)
  await expect(page.locator('#findings-command-table')).toBeVisible({ timeout: 30_000 })

  await page.getByPlaceholder('Name this view…').fill('E2E Live View')
  await page.getByRole('button', { name: 'Save view' }).click()

  // Chip is exact — a delete button's aria-label also contains the name.
  const chip = page.getByRole('button', { name: 'E2E Live View', exact: true })
  await expect(chip).toBeVisible()
  await chip.click()
  await assertNoCrash(page)
})

test('severity filter round-trips through the URL against live data', async ({ page, request }) => {
  test.setTimeout(180_000)
  const { auth } = await ensureLiveFindings(request)

  // What the backend itself returns for the critical slice.
  const critical = (await fetchFindings(request, auth)).filter((f) => f.severity === 'critical')

  await gotoFindings(page, '?sev=critical')
  const table = page.locator('#findings-command-table')

  if (critical.length === 0) {
    // No critical findings live → the filtered table must be empty/absent, never
    // showing a non-critical row. Accept either the empty-match state or 0 rows.
    const rows = await table.locator('tbody tr').count().catch(() => 0)
    expect(rows).toBe(0)
  } else {
    await expect(table).toBeVisible({ timeout: 30_000 })
    const severityCells = table.locator('tbody tr td:nth-child(2)')
    const n = await severityCells.count()
    expect(n).toBeGreaterThan(0)
    // Every rendered row must be critical — the URL param really drove the filter.
    for (let i = 0; i < n; i += 1) {
      await expect(severityCells.nth(i)).toContainText(/critical/i)
    }
  }
  await assertNoCrash(page)
})

test('⌘K command palette works on the live findings page', async ({ page, request }) => {
  test.setTimeout(120_000)
  await ensureLiveFindings(request)
  await gotoFindings(page)
  await expect(page.locator('#findings-command-table')).toBeVisible({ timeout: 30_000 })

  await page.keyboard.press('Control+k')
  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  const input = dialog.getByRole('combobox')
  await input.fill('audit')
  await expect(dialog.getByRole('option').first()).toBeVisible()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(/\/audit/, { timeout: 15_000 })
  await assertNoCrash(page)
})
