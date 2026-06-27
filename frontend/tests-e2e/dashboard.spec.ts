import { test, expect, type Page } from '@playwright/test'
import { installCommandCenterApiMocks } from './api-mock'

/**
 * Mirrors `TABS` in src/components/cockpit/ClientCockpit.jsx — every cockpit nav tab.
 */
const COCKPIT_TAB_LABELS = [
  'Overview',
  'Engine Room',
  'Findings & Reports',
  'Identity Matrix',
  'Risk Graph',
  'Auto-Heal',
  'Deception Grid',
  'Pipeline Monitor',
  'Audit Trail',
  'Settings & Alerts',
  'Compliance',
  'Swarm Mind',
  'Auto-Containment',
  'AI Model Risk',
  'Edge Swarm Map',
] as const

const CRASH_MARKERS = [
  /This view crashed/i,
  /This tab encountered an error/i,
  /Tab error/i,
  /Minified React error/i,
  /Uncaught Error/i,
]

async function assertNoFatalUi(page: Page) {
  const body = await page.locator('body').innerText()
  expect(body.trim().length, 'document body should not be empty').toBeGreaterThan(20)
  for (const re of CRASH_MARKERS) {
    expect(body, `should not show crash copy matching ${re}`).not.toMatch(re)
  }
  await expect(page.locator('#root')).toBeVisible()
  await expect(page.locator('main').first()).toBeVisible()
}

async function assertHealthyMainPane(page: Page) {
  const main = page.locator('main').first()
  await expect(main).toBeVisible()
  const txt = await main.innerText()
  expect(txt.replace(/\s+/g, ' ').trim().length, 'main should render visible content').toBeGreaterThan(5)
}

async function clickCockpitTab(page: Page, label: string) {
  const nav = page.locator('header nav')
  const tabBtn = nav.getByRole('button', { name: label, exact: true })
  await expect(tabBtn).toBeVisible()
  await tabBtn.click()
  // Sequential navigation can outrun Vite lazy chunks on the dev server.
  await page.waitForLoadState('networkidle')
}

test.describe('Command Center — cockpit tabs', () => {
  test.beforeEach(async ({ page }) => {
    await installCommandCenterApiMocks(page)

    const pageErrors: string[] = []
    page.on('pageerror', (err) => pageErrors.push(err.message))

    await page.goto('/command-center/operations', { waitUntil: 'domcontentloaded' })

    await expect(page).toHaveURL(/\/command-center\/operations\/?$/)
    await expect(page.getByText('Verifying session')).toBeHidden({ timeout: 30_000 })

    const clientBtn = page.getByRole('button', { name: 'E2E Test Client' })
    await expect(clientBtn).toBeVisible({ timeout: 15_000 })
    await clientBtn.click()

    await expect(page.locator('#cockpit-engage-scan-btn')).toBeVisible({ timeout: 15_000 })

    // Fail fast if React threw during bootstrap
    expect(pageErrors, 'no uncaught page errors during load').toEqual([])
  })

  for (const label of COCKPIT_TAB_LABELS) {
    test(`tab "${label}" renders without crash`, async ({ page }) => {
      const pageErrors: string[] = []
      page.on('pageerror', (err) => pageErrors.push(err.message))

      const nav = page.locator('header nav')
      await expect(nav).toBeVisible()

      await clickCockpitTab(page, label)

      await assertNoFatalUi(page)
      await assertHealthyMainPane(page)

      // Regression: Settings & Compliance used to white-screen
      if (label === 'Settings & Alerts') {
        await expect(page.getByRole('heading', { name: /Settings & alerts/i })).toBeVisible()
        await expect(page.getByPlaceholder(/hooks\.slack\.com/i)).toBeVisible()
      }
      if (label === 'Compliance') {
        await expect(page.getByRole('heading', { name: /Compliance & agentless cloud/i })).toBeVisible()
      }

      expect(pageErrors, `no pageerror while on "${label}"`).toEqual([])
    })
  }

  test('sequential walk: all tabs in one session', async ({ page }) => {
    const pageErrors: string[] = []
    page.on('pageerror', (err) => pageErrors.push(err.message))

    for (const label of COCKPIT_TAB_LABELS) {
      await clickCockpitTab(page, label)
      await assertNoFatalUi(page)
      await assertHealthyMainPane(page)
    }

    expect(pageErrors).toEqual([])
  })
})
