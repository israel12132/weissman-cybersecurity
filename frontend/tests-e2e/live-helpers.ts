/**
 * Helpers for live-stack Playwright E2E (real backend — no API mocks).
 */
import type { APIRequestContext, Page } from '@playwright/test'

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

export async function apiLogin(request: APIRequestContext): Promise<LiveAuth> {
  const r = await request.post(`${LIVE_BASE}/api/login`, {
    data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD, tenant_slug: TENANT },
  })
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
  const list = await request.get(`${LIVE_BASE}/api/clients`, { headers })
  if (list.ok()) {
    const clients = await list.json()
    const arr = Array.isArray(clients) ? clients : []
    const existing = arr.find((c: { name?: string }) =>
      String(c.name || '').includes('Playwright E2E'),
    )
    if (existing?.id) return Number(existing.id)
  }
  const created = await request.post(`${LIVE_BASE}/api/clients`, {
    headers,
    data: {
      name: `Playwright E2E ${Date.now()}`,
      domains: JSON.stringify(['https://example.com']),
      ip_ranges: JSON.stringify(['127.0.0.0/8']),
    },
  })
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
  await page.goto('/command-center/login', { waitUntil: 'domcontentloaded' })
  await page.locator('script[type="module"]').first().waitFor({ state: 'attached', timeout: 15_000 })
  await page.locator('#email').waitFor({ state: 'visible', timeout: 45_000 })
  await page.locator('#email').fill(ADMIN_EMAIL)
  await page.locator('#password').fill(ADMIN_PASSWORD)
  const loginWait = page.waitForResponse(
    (r) => r.url().includes('/api/login') && r.status() >= 200 && r.status() < 300,
    { timeout: 45_000 },
  )
  await page.locator('button[type="submit"]').click()
  const loginResp = await loginWait
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
