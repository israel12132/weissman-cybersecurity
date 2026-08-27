import { test, expect } from '@playwright/test'
import { installCommandCenterApiMocks } from '../tests-e2e/api-mock'
import { PRODUCTION_ENGINE_COUNT } from '../src/lib/platformScale'

/**
 * Customer regression fortress — live UI contracts the other teams must not break:
 * login lives only at /command-center/login, 563 + live backdrop stay, scoped JWT
 * never renders select[name=client_id].
 */

test.describe('legacy auth URLs are gone', () => {
  for (const path of ['/login', '/signin', '/auth']) {
    test(`${path} is HTTP 404`, async ({ request }) => {
      const resp = await request.get(path, { maxRedirects: 0 })
      expect(resp.status(), `${path} must 404; login is /command-center/login`).toBe(404)
    })
  }
})

test.describe('Command Center login', () => {
  test('serves the live cockpit at /command-center/login', async ({ page }) => {
    await page.goto('/command-center/login', { waitUntil: 'domcontentloaded' })
    await expect(page.locator('[data-testid="cyber-live-backdrop"]')).toBeVisible({
      timeout: 30_000,
    })
    await expect(page.locator('.wm-cyber-backdrop')).toBeVisible()
    await expect(page.getByText(new RegExp(`${PRODUCTION_ENGINE_COUNT} attack engines`))).toBeVisible(
      { timeout: 20_000 },
    )
    await expect(page.getByText(`${PRODUCTION_ENGINE_COUNT} engines`).first()).toBeVisible()
    await expect(page.getByText(/254 engines/)).toHaveCount(0)
    await expect(page.locator('input[type="email"]')).toBeVisible()
    await expect(page.locator('input[type="password"]')).toBeVisible()
  })

  test('/command-center/signin is SPA NotFound, not a second login', async ({ page }) => {
    const resp = await page.goto('/command-center/signin', { waitUntil: 'domcontentloaded' })
    expect(resp?.status()).toBe(200)
    await expect(page.getByText(/404|not found/i).first()).toBeVisible({ timeout: 20_000 })
    await expect(page.locator('input[type="password"]')).toHaveCount(0)
  })
})

test.describe('portal JWT hides the client picker', () => {
  test('no select[name=client_id] when client_picker_hidden even if /api/clients lists two', async ({
    page,
  }) => {
    await installCommandCenterApiMocks(page)
    // Last-registered Playwright route wins over the generic /api/** mock.
    await page.route('**/api/auth/me', async (route) => {
      if (route.request().method() !== 'GET') return route.fallback()
      await route.fulfill({
        status: 200,
        contentType: 'application/json; charset=utf-8',
        body: JSON.stringify({
          ok: true,
          email: 'portal@weissman.test',
          role: 'client',
          is_superadmin: false,
          is_client_user: true,
          assigned_client_id: 7,
          allowed_client_ids: [7],
          client_picker_hidden: true,
          can_create_clients: false,
          can_delete_clients: false,
        }),
      })
    })
    await page.route('**/api/clients', async (route) => {
      if (route.request().method() !== 'GET') return route.fallback()
      await route.fulfill({
        status: 200,
        contentType: 'application/json; charset=utf-8',
        body: JSON.stringify([
          { id: 7, name: 'Bound Customer', domains: '["https://bound.example"]' },
          { id: 8, name: 'Other Corp', domains: '["https://other.example"]' },
        ]),
      })
    })

    await page.goto('/command-center/engines', { waitUntil: 'domcontentloaded' })
    await expect(page.getByText('Verifying session')).toBeHidden({ timeout: 30_000 })
    await expect(page.locator('select[name="client_id"]')).toHaveCount(0)
  })
})
