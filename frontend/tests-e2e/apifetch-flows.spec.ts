import { test, expect, type Page } from '@playwright/test'

/**
 * Lane B — mock-backed E2E for the unified apiFetch layer.
 *
 * Explicitly exercises the surfaces changed by the network-layer unification:
 *   1. AuthContext login (raw fetch, deliberately exempt from retry/breaker).
 *   2. SystemConfiguration MFA panel (migrated onto the `api` client).
 *   3. apiFetch resilience — jittered retry + per-origin circuit breaker —
 *      driven through the REAL module (Vite serves /src) with mocked transport,
 *      asserting behavior by counting intercepted requests.
 */

function forceEnglish(page: Page) {
  return page.addInitScript(() => {
    try {
      localStorage.setItem('i18nextLng', 'en')
    } catch {
      /* storage may be unavailable */
    }
  })
}

const json = (body: unknown, status = 200) => ({
  status,
  contentType: 'application/json',
  body: JSON.stringify(body),
})

test.describe('Lane B — apiFetch unification flows (mock-backed)', () => {
  test('AuthContext: a successful login redirects into the command center', async ({ page }) => {
    await forceEnglish(page)
    let loggedIn = false
    let loginCalls = 0
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname
      const method = route.request().method()
      if (path === '/api/login' && method === 'POST') {
        loginCalls += 1
        loggedIn = true
        return route.fulfill(
          json({ ok: true, access_token: 'e2e', user_id: 1, tenant_id: 1, role: 'analyst', is_superadmin: false }),
        )
      }
      if (path === '/api/auth/me') {
        return loggedIn
          ? route.fulfill(json({ ok: true, email: 'e2e@weissman.test', role: 'analyst', is_superadmin: false }))
          : route.fulfill(json({ detail: 'unauthenticated' }, 401))
      }
      if (path === '/api/auth/refresh') return route.fulfill(json({}, 401))
      return route.fulfill(json({ ok: true, detail: null }))
    })

    await page.goto('/command-center/login', { waitUntil: 'domcontentloaded' })
    await page.locator('input[type="email"]').fill('admin@weissman.test')
    await page.locator('input[type="password"]').fill('correct-horse-battery-staple')
    await page.locator('button[type="submit"]').first().click()

    await expect(page).toHaveURL(/\/command-center\/operations\/?$/, { timeout: 30_000 })
    expect(loginCalls).toBe(1)
  })

  test('AuthContext: a 401 surfaces an error and never loops (exactly one attempt)', async ({ page }) => {
    await forceEnglish(page)
    let loginCalls = 0
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname
      const method = route.request().method()
      if (path === '/api/login' && method === 'POST') {
        loginCalls += 1
        return route.fulfill(json({ detail: 'Invalid credentials' }, 401))
      }
      if (path === '/api/auth/me') return route.fulfill(json({ detail: 'unauthenticated' }, 401))
      if (path === '/api/auth/refresh') return route.fulfill(json({}, 401))
      return route.fulfill(json({ ok: true, detail: null }))
    })

    await page.goto('/command-center/login', { waitUntil: 'domcontentloaded' })
    await page.locator('input[type="email"]').fill('admin@weissman.test')
    await page.locator('input[type="password"]').fill('wrong-password')
    await page.locator('button[type="submit"]').first().click()

    // The login error region (role="alert") becomes visible.
    await expect(page.getByRole('alert')).toBeVisible({ timeout: 15_000 })
    // No redirect — still on the login route.
    await expect(page).toHaveURL(/\/command-center\/login\/?$/)
    // Give any (incorrect) retry/loop a generous window to misbehave, then assert
    // exactly one login request was ever issued. Login is raw fetch — no breaker, no retry.
    await page.waitForTimeout(1500)
    expect(loginCalls).toBe(1)
  })

  test('SystemConfiguration: MFA setup renders the otpauth provisioning URI via the api client', async ({
    page,
  }) => {
    await forceEnglish(page)
    await page.addInitScript(() => {
      try {
        sessionStorage.setItem('weissman_access_token', 'e2e-admin')
      } catch {
        /* ignore */
      }
    })
    let statusCalls = 0
    let setupCalls = 0
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname
      const method = route.request().method()
      if (path === '/api/auth/me') {
        return route.fulfill(json({ ok: true, email: 'admin@weissman.test', role: 'admin', is_superadmin: true }))
      }
      if (path === '/api/system/config' && method === 'GET') {
        // The page spreads these sections into inputs — must be section-shaped.
        return route.fulfill(
          json({ general: {}, security: {}, scanning: {}, integrations: {}, retention: {}, performance: {}, compliance: {} }),
        )
      }
      if (path === '/api/auth/mfa/status' && method === 'GET') {
        statusCalls += 1
        return route.fulfill(json({ mfa_enabled: false, mfa_provisioned: false }))
      }
      if (path === '/api/auth/mfa/setup' && method === 'POST') {
        setupCalls += 1
        return route.fulfill(
          json({
            otpauth_url:
              'otpauth://totp/Weissman-Cybersecurity:admin@weissman.test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Weissman-Cybersecurity',
          }),
        )
      }
      return route.fulfill(json({ ok: true, detail: null }))
    })

    await page.goto('/command-center/system-config', { waitUntil: 'domcontentloaded' })

    // Open the Security tab, where the MFA self-service panel lives.
    await page.getByRole('button', { name: 'Security' }).click()

    // The panel loads MFA status via api.get, then offers the setup action.
    const setupBtn = page.getByRole('button', { name: 'Set up MFA' })
    await expect(setupBtn).toBeVisible({ timeout: 15_000 })
    expect(statusCalls).toBeGreaterThanOrEqual(1)

    await setupBtn.click()

    // The provisioning URI returned by api.post('/api/auth/mfa/setup') is rendered.
    await expect(page.getByText(/otpauth:\/\/totp\//)).toBeVisible({ timeout: 15_000 })
    expect(setupCalls).toBe(1)
  })

  test('apiFetch resilience: jittered retry recovers 503,503,200; breaker short-circuits sustained 500s', async ({
    page,
  }) => {
    // A page on the dev origin so the browser can import the real Vite-served modules.
    await page.goto('/command-center/login', { waitUntil: 'domcontentloaded' })

    // Distinct synthetic origins => isolated per-origin breakers, immune to the
    // app's own same-origin traffic. CORS-permissive so the cross-origin GETs resolve.
    let flakyHits = 0
    await page.route(/e2e-flaky\.test/, async (route) => {
      flakyHits += 1
      const status = flakyHits <= 2 ? 503 : 200
      return route.fulfill({
        status,
        contentType: 'application/json',
        headers: { 'access-control-allow-origin': '*' },
        body: JSON.stringify(status === 200 ? { ok: true, recovered: true } : { detail: 'overloaded' }),
      })
    })
    let downHits = 0
    await page.route(/e2e-down\.test/, async (route) => {
      downHits += 1
      return route.fulfill({
        status: 500,
        contentType: 'application/json',
        headers: { 'access-control-allow-origin': '*' },
        body: JSON.stringify({ detail: 'down' }),
      })
    })

    // --- Retry: 503, 503, 200 through the REAL apiFetch (jittered backoff, real timers). ---
    const retryResult = await page.evaluate(async () => {
      const m = await import('/command-center/src/utils/apiFetch.js')
      const r = await import('/command-center/src/lib/resilience.js')
      r._resetCircuitBreakers()
      return m.apiFetch('http://e2e-flaky.test/probe', {
        credentials: 'omit',
        retries: 3,
        retryBaseMs: 5,
        retryMaxMs: 20,
      })
    })
    expect(retryResult).toMatchObject({ recovered: true })
    expect(flakyHits).toBe(3)

    // --- Breaker: sustained 500s trip after the threshold; further calls short-circuit. ---
    const breaker = await page.evaluate(async () => {
      const m = await import('/command-center/src/utils/apiFetch.js')
      const r = await import('/command-center/src/lib/resilience.js')
      r._resetCircuitBreakers()
      let httpFailures = 0
      let shortCircuited = 0
      for (let i = 0; i < 9; i += 1) {
        try {
          await m.apiFetch('http://e2e-down.test/probe', { credentials: 'omit', retries: 0 })
        } catch (e) {
          if ((e as { code?: string })?.code === 'CIRCUIT_OPEN') shortCircuited += 1
          else httpFailures += 1
        }
      }
      return { httpFailures, shortCircuited }
    })

    // Default breaker threshold is 6: the first 6 reach transport and fail, the
    // remaining 3 short-circuit WITHOUT hitting the network (no self-inflicted flood).
    expect(downHits).toBe(6)
    expect(breaker.httpFailures).toBe(6)
    expect(breaker.shortCircuited).toBe(3)
  })
})
