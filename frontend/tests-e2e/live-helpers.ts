/**
 * Helpers for live-stack Playwright E2E (real backend — no API mocks).
 */
import type { APIRequestContext, APIResponse } from '@playwright/test'
import type { Page } from '@playwright/test'

export const LIVE_BASE = (process.env.WEISSMAN_E2E_BASE || 'http://127.0.0.1:8000').replace(/\/$/, '')
export const ADMIN_EMAIL = process.env.WEISSMAN_ADMIN_EMAIL || 'admin@localhost'
export const ADMIN_PASSWORD = process.env.WEISSMAN_ADMIN_PASSWORD || ''
export const TENANT = process.env.WEISSMAN_E2E_TENANT || 'default'

export type LiveAuth = {
  token: string
  cookie: string
}

export function liveEnabled(): boolean {
  return process.env.PLAYWRIGHT_LIVE === '1' && !!ADMIN_PASSWORD
}

// Ceiling on a SINGLE honored back-off. It must stay above every Retry-After the stack actually
// sends, or honoring the hint is silently defeated — the same truncation #234 fixed on the Node
// side (scripts/lib/scan_intake.mjs). Two limiters answer 429 here and they ask for very different
// waits: the 30/s-per-IP burst limiter wants ~1s, but the login limiter
// (http/login_rate_limit.rs) asks for 60s. At the old 3s ceiling a shed login slept 3s and retried
// five times INSIDE one 60s quota window, so every attempt was refused and the run failed while
// the server was plainly saying "wait 60s". 75s clears the 60s hint with margin.
const RETRY_AFTER_CAP_MS = 75_000
// Ceiling on the CUMULATIVE back-off for one call. Honoring a 60s hint five times over would eat
// the whole 12-minute globalTimeout in two tests. One honored 60s wait clears the login window, so
// this only has to allow one, and it keeps the worst case inside the 180s per-test timeout.
const RETRY_AFTER_TOTAL_BUDGET_MS = 90_000
// The platform sheds with two codes, and both carry a Retry-After: 429 from the rate limiters and
// 503 from self-heal load shedding. scripts/lib/scan_intake.mjs has always treated them as one set;
// this side only ever retried 429, so a 503 fell through to `apiLogin`'s non-success check and
// failed the run on a back-off the server expected us to wait out. Anything else — 401, 500 — still
// passes straight through and fails fast.
const isShed = (status: number) => status === 429 || status === 503

/**
 * Retry a live-stack API call while the platform sheds it (429). The live E2E drives ALL browser +
 * harness traffic through one IP (127.0.0.1), so legitimate bursts trip limits no single real
 * client ever would. The API answers 429 with an explicit `Retry-After` — a documented "retry in
 * Ns" contract — so a correct client honors it instead of failing the run. Non-429 responses (incl.
 * real errors) pass straight through, so a genuinely bad credential still fails fast.
 */
export async function apiRequestWithRetry(
  fn: () => Promise<APIResponse>,
  retries = 5,
): Promise<APIResponse> {
  let r = await fn()
  let spentMs = 0
  for (let attempt = 0; attempt < retries && isShed(r.status()); attempt += 1) {
    const ra = Number(r.headers()['retry-after'])
    const waitMs = Number.isFinite(ra) && ra > 0
      ? Math.min(ra * 1000, RETRY_AFTER_CAP_MS)
      : 400 * (attempt + 1)
    if (spentMs + waitMs > RETRY_AFTER_TOTAL_BUDGET_MS) break
    spentMs += waitMs
    await new Promise((res) => setTimeout(res, waitMs))
    r = await fn()
  }
  return r
}

export async function apiLogin(request: APIRequestContext): Promise<LiveAuth> {
  const r = await apiRequestWithRetry(() =>
    request.post(`${LIVE_BASE}/api/login`, {
      data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD, tenant_slug: TENANT },
    }),
  )
  if (!r.ok()) {
    throw new Error(`login failed HTTP ${r.status()}: ${await r.text()}`)
  }
  const data = await r.json()
  const token = String(data.access_token || data.token || '')
  const setCookie = r.headers()['set-cookie'] || ''
  const cookie = setCookie
    .split(/,\s*(?=[^;]+=)/)
    .map((c) => c.split(';')[0])
    .filter(Boolean)
    .join('; ')
  if (!token && !cookie) throw new Error('login returned no token or cookie')
  return { token, cookie }
}

export function authHeaders(auth: LiveAuth): Record<string, string> {
  const h: Record<string, string> = { Accept: 'application/json' }
  if (auth.token) h.Authorization = `Bearer ${auth.token}`
  if (auth.cookie) h.Cookie = auth.cookie
  return h
}

export async function ensureE2eClient(request: APIRequestContext, auth: LiveAuth): Promise<number> {
  const headers = { ...authHeaders(auth), 'Content-Type': 'application/json' }
  const list = await apiRequestWithRetry(() => request.get(`${LIVE_BASE}/api/clients`, { headers }))
  if (list.ok()) {
    const clients = await list.json()
    const arr = Array.isArray(clients) ? clients : []
    const existing = arr.find((c: { name?: string }) =>
      String(c.name || '').includes('Playwright E2E'),
    )
    if (existing?.id) return Number(existing.id)
  }
  const created = await apiRequestWithRetry(() =>
    request.post(`${LIVE_BASE}/api/clients`, {
      headers,
      data: {
        name: `Playwright E2E ${Date.now()}`,
        domains: JSON.stringify(['https://example.com']),
        ip_ranges: JSON.stringify(['127.0.0.0/8']),
      },
    }),
  )
  if (!created.ok()) {
    throw new Error(`client create failed HTTP ${created.status()}: ${await created.text()}`)
  }
  const body = await created.json()
  const id = Number(body.id)
  if (!Number.isFinite(id)) throw new Error('client create returned no id')
  return id
}

export async function pollJobTerminal(
  request: APIRequestContext,
  auth: LiveAuth,
  jobId: string,
  { maxAttempts = 90, intervalMs = 2000, clientId }: { maxAttempts?: number; intervalMs?: number; clientId?: number } = {},
): Promise<string> {
  const headers = authHeaders(auth)
  const terminal = new Set(['completed', 'done', 'failed', 'error', 'dead', 'cancelled'])
  for (let i = 0; i < maxAttempts; i += 1) {
    const r = await request.get(`${LIVE_BASE}/api/jobs/${jobId}`, { headers })
    if (r.ok()) {
      const data = await r.json()
      const st = String(data.status || data.state || '').toLowerCase()
      if (terminal.has(st)) return st
    }
    if (clientId != null) {
      const fr = await request.get(`${LIVE_BASE}/api/findings?client_id=${clientId}&limit=1`, { headers })
      if (fr.ok()) {
        const fp = await fr.json()
        const rows = Array.isArray(fp.findings) ? fp.findings : []
        if (rows.length > 0) return 'findings_ready'
      }
    }
    await new Promise((res) => setTimeout(res, intervalMs))
  }
  return 'timeout'
}

export async function uiLogin(page: Page) {
  // Diagnostic capture: if the SPA fails to mount (login form never renders),
  // surface the browser-side cause on stdout — CI logs don't otherwise expose
  // console/pageerror or the rendered DOM.
  const consoleMsgs: string[] = []
  page.on('console', (m) => {
    if (m.type() === 'error' || m.type() === 'warning') consoleMsgs.push(`[${m.type()}] ${m.text()}`)
  })
  page.on('pageerror', (e) => consoleMsgs.push(`[pageerror] ${e.message}`))
  page.on('requestfailed', (r) => consoleMsgs.push(`[requestfailed] ${r.url()} ${r.failure()?.errorText ?? ''}`))
  await page.goto('/command-center/login', { waitUntil: 'domcontentloaded' })
  await page.locator('script[type="module"]').first().waitFor({ state: 'attached', timeout: 15_000 })
  try {
    await page.locator('#email').waitFor({ state: 'visible', timeout: 45_000 })
  } catch (err) {
    const html = await page.content().catch(() => '(page.content failed)')
    // eslint-disable-next-line no-console
    console.log(
      `\n===== uiLogin DIAGNOSTIC (#email never visible) =====\nURL: ${page.url()}\n` +
        `--- console/pageerror/requestfailed (${consoleMsgs.length}) ---\n${consoleMsgs.join('\n') || '(none captured)'}\n` +
        `--- page.content() [first 4000 chars] ---\n${html.slice(0, 4000)}\n===== END DIAGNOSTIC =====\n`,
    )
    throw err
  }
  await page.locator('#email').fill(ADMIN_EMAIL)
  await page.locator('#password').fill(ADMIN_PASSWORD)

  // Submit, and treat a shed login as "wait and submit again" rather than a failure.
  //
  // This used to wait only for a 2xx `/api/login`. When the login limiter shed the attempt with
  // 429 that response never arrived, so the wait burned its full 45s and the test died on a
  // timeout that named nothing — with the server having answered immediately and precisely, asking
  // for a 60s wait. Matching ANY /api/login response lets a shed be seen for what it is.
  const submitOnce = async () => {
    const wait = page.waitForResponse((r) => r.url().includes('/api/login'), { timeout: 45_000 })
    await page.locator('button[type="submit"]').click()
    return wait
  }
  let loginResp = await submitOnce()
  let shedSpentMs = 0
  for (let attempt = 0; attempt < 3 && isShed(loginResp.status()); attempt += 1) {
    const ra = Number(loginResp.headers()['retry-after'])
    const waitMs = Number.isFinite(ra) && ra > 0
      ? Math.min(ra * 1000, RETRY_AFTER_CAP_MS)
      : 1_000 * (attempt + 1)
    if (shedSpentMs + waitMs > RETRY_AFTER_TOTAL_BUDGET_MS) break
    shedSpentMs += waitMs
    // eslint-disable-next-line no-console
    console.log(`  … uiLogin: login shed (HTTP ${loginResp.status()}); backing off ${Math.round(waitMs / 1000)}s`)
    await new Promise((res) => setTimeout(res, waitMs))
    loginResp = await submitOnce()
  }
  if (!loginResp.ok()) {
    throw new Error(`uiLogin failed: HTTP ${loginResp.status()} ${(await loginResp.text().catch(() => '')).slice(0, 200)}`)
  }
  const body = await loginResp.json().catch(() => ({}))
  if (body?.ok !== true && !body?.access_token) {
    throw new Error(`uiLogin failed: ${JSON.stringify(body).slice(0, 200)}`)
  }
  if (body?.access_token) {
    await page.evaluate((token) => {
      sessionStorage.setItem('weissman_access_token', token)
      localStorage.setItem('weissman_access_token', token)
    }, String(body.access_token))
  }
  await page.goto('/command-center/operations', { waitUntil: 'domcontentloaded' })
  await page.getByText('Verifying session').waitFor({ state: 'hidden', timeout: 30_000 }).catch(() => {})
  await expectNotLoginPage(page)
}

/** Re-login when storage state expired or context was reset. */
export async function ensureUiSession(page: Page) {
  await page.goto('/command-center/operations', { waitUntil: 'domcontentloaded' })
  await page.getByText('Verifying session').waitFor({ state: 'hidden', timeout: 30_000 }).catch(() => {})
  const onLogin =
    page.url().includes('/login') ||
    (await page.locator('#email').isVisible({ timeout: 2_000 }).catch(() => false))
  if (onLogin) {
    await uiLogin(page)
  }
  await expectNotLoginPage(page)
}

export async function selectFirstCockpitClient(page: Page) {
  const sidebar = page.locator('aside.cockpit-sidebar')
  await sidebar.waitFor({ state: 'visible', timeout: 20_000 })
  const clientBtn = sidebar.locator('ul.space-y-px li button').first()
  await clientBtn.click({ timeout: 15_000 })
}

export async function expectNotLoginPage(page: Page) {
  const url = page.url()
  if (url.includes('/login')) {
    throw new Error(`Expected authenticated session but got login page: ${url}`)
  }
}
