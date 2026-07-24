/**
 * Live UI crawl — authenticated visit of every sidebar route + key interactions.
 * Run: cd frontend && set -a && source ../.env && set +a && \
 *   PLAYWRIGHT_LIVE=1 PLAYWRIGHT_UI_DEV=1 npm run test:e2e -- live-ui-crawl.spec.ts
 */
import { test, expect } from '@playwright/test'
import { ensureUiSession, liveEnabled, selectFirstCockpitClient } from './live-helpers'
import { PRIMARY_NAV, NAV_GROUPS } from '../src/lib/appNav.js'

const CRASH = [/This view crashed/i, /Tab error/i, /Minified React error/i, /Something went wrong/i]
const PREFIX = '/command-center'

function navToRoute(to: string): string {
  if (to === '/') return `${PREFIX}/operations`
  return `${PREFIX}${to}`
}

/** Every registered sidebar route (single source: appNav). */
const ROUTES = [
  ...PRIMARY_NAV.map((item) => navToRoute(item.to)),
  ...NAV_GROUPS.flatMap((g) =>
    g.items.filter((item) => !item.hideFromNav).map((item) => navToRoute(item.to)),
  ),
].filter((route, i, arr) => arr.indexOf(route) === i)

test.describe.configure({ mode: 'parallel' })

test.beforeEach(async ({ page }, testInfo) => {
  test.skip(!liveEnabled(), 'PLAYWRIGHT_LIVE=1 and WEISSMAN_ADMIN_PASSWORD required')
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
  const errors: string[] = []
  page.on('pageerror', (e) => {
    errors.push(e.message)
    testInfo.annotations.push({ type: 'pageerror', description: e.message })
  })
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      const t = msg.text()
      if (!/favicon|404|ResizeObserver|websocket/i.test(t)) {
        errors.push(t)
      }
    }
  })
  // @ts-expect-error attach for afterEach
  page._uiErrors = errors
})

test.afterEach(async ({ page }, testInfo) => {
  // @ts-expect-error read attached errors
  const errors: string[] = page._uiErrors || []
  const fatal = errors.filter(
    (e) =>
      /Cannot read properties|is not a function|Minified React error|This view crashed/i.test(e) &&
      !/Failed to fetch|NetworkError/i.test(e),
  )
  if (fatal.length) {
    throw new Error(`${testInfo.title}: fatal UI errors:\n${fatal.slice(0, 5).join('\n')}`)
  }
})

async function visitRoute(page: import('@playwright/test').Page, route: string) {
  // Response listener is registered BEFORE the first navigation so 5xx/429 during session
  // bootstrap are visible too; previously it was attached after ensureUiSession, making errors
  // on the most failure-prone navigation invisible.
  const apiErrors: string[] = []
  page.on('response', (r) => {
    const u = r.url()
    // 429 was previously missed (`>= 500` only), so per-IP rate limiting during a 100-route
    // crawl surfaced as a mystery timeout rather than a named failure.
    if (u.includes('/api/') && (r.status() === 429 || r.status() >= 500)) {
      apiErrors.push(`${r.status()} ${u}`)
    }
  })
  // NOTE: no pre-emptive ensureUiSession() here. It unconditionally loaded the cockpit
  // (live-helpers.ts: `page.goto('/command-center/operations')`) before EVERY route, so each
  // route test paid TWO full cold-cache SPA boots instead of one — the dominant cost behind the
  // 150-min step. storageState (playwright.config.ts) already supplies the session; the lazy
  // recovery branch below handles the rare expired-state case.
  await page.goto(route, { waitUntil: 'domcontentloaded' })
  await page.locator('script[type="module"]').first().waitFor({ state: 'attached', timeout: 20_000 })
  await page.getByText('Verifying session').waitFor({ state: 'hidden', timeout: 30_000 }).catch(() => {})
  // isVisible() IGNORES its `timeout` option (deprecated no-op in playwright-core 1.59.1), so the
  // old probe sampled the DOM one tick after domcontentloaded — before React mounts — and this
  // recovery branch effectively never fired. waitFor() actually honours the budget.
  const bounced =
    /\/login/.test(page.url()) ||
    (await page
      .locator('#email')
      .waitFor({ state: 'visible', timeout: 1_500 })
      .then(() => true, () => false))
  if (bounced) {
    await ensureUiSession(page)
    await page.goto(route, { waitUntil: 'domcontentloaded' })
    await page.getByText('Verifying session').waitFor({ state: 'hidden', timeout: 30_000 }).catch(() => {})
  }
  await expect(page).not.toHaveURL(/\/login/)
  // Was `await page.waitForTimeout(1200)` — a blind 120s tax across 100 routes that asserted
  // nothing, simultaneously too long for fast routes and too short for slow ones. This waits for
  // the condition the sleep stood in for, returns in ~50ms on a healthy route, and names the
  // route when content never arrives.
  await expect
    .poll(async () => (await page.locator('#root').innerText()).trim().length, {
      timeout: 15_000,
      message: `${route}: #root never rendered meaningful content`,
    })
    .toBeGreaterThan(40)
  const body = await page.locator('body').innerText()
  expect(body.trim().length, `${route} empty body`).toBeGreaterThan(20)
  for (const re of CRASH) {
    expect(body, `${route} crash: ${re}`).not.toMatch(re)
  }
  await expect(page.locator('#root')).toBeVisible()
  const mainContent = page.locator('main, #main-content, [role="main"]').first()
  const hasLandmark = await mainContent.isVisible({ timeout: 8_000 }).catch(() => false)
  if (hasLandmark) {
    await expect(mainContent).toBeVisible()
  } else {
    const rootText = await page.locator('#root').innerText()
    expect(rootText.trim().length, `${route} thin #root content`).toBeGreaterThan(40)
  }
  if (apiErrors.length) {
    throw new Error(`API 5xx on ${route}:\n${apiErrors.slice(0, 5).join('\n')}`)
  }
}

for (const route of ROUTES) {
  test(`route loads: ${route}`, async ({ page }) => {
    test.setTimeout(90_000)
    await visitRoute(page, route)
  })
}

test('engines — open first engine card', async ({ page }) => {
  test.setTimeout(90_000)
  await visitRoute(page, `${PREFIX}/engines`)
  const card = page.locator('[data-engine-id], a[href*="/engines/"]').first()
  if (await card.isVisible({ timeout: 10_000 }).catch(() => false)) {
    await card.click()
    await page.waitForTimeout(1500)
    await expect(page).not.toHaveURL(/\/login/)
    const body = await page.locator('body').innerText()
    for (const re of CRASH) expect(body).not.toMatch(re)
  }
})

test('clients — list loads', async ({ page }) => {
  test.setTimeout(60_000)
  await visitRoute(page, `${PREFIX}/clients`)
  const main = page.locator('main').first()
  await expect(main).toContainText(/client|לקוח|new|create/i)
})

test('findings — table or empty state', async ({ page }) => {
  test.setTimeout(60_000)
  await ensureUiSession(page)
  await page.goto(`${PREFIX}/findings`, { waitUntil: 'domcontentloaded' })
  await page.getByText('Verifying session').waitFor({ state: 'hidden', timeout: 30_000 }).catch(() => {})
  const content = page.locator('main, #main-content').first()
  await expect(content).toContainText(/finding|ממצא|severity|critical|high|empty|export|filter|open|verify|אמת/i)
})

test('cockpit — engage scan UI visible', async ({ page }) => {
  test.setTimeout(90_000)
  await visitRoute(page, `${PREFIX}/operations`)
  await selectFirstCockpitClient(page)
  await expect(page.locator('#cockpit-engage-scan-btn')).toBeVisible({ timeout: 20_000 })
})

test('cockpit — war room tabs load without crash', async ({ page }) => {
  test.setTimeout(120_000)
  await visitRoute(page, `${PREFIX}/operations`)
  await selectFirstCockpitClient(page)
  const tabs = ['findings', 'engine-room', 'pipeline', 'risk-graph']
  for (const tabId of tabs) {
    const btn = page.locator(`#cockpit-tab-${tabId}`)
    if (await btn.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await btn.click()
      await page.waitForTimeout(800)
      const body = await page.locator('body').innerText()
      for (const re of CRASH) expect(body, `tab ${tabId}`).not.toMatch(re)
    }
  }
})

test('top-tier engine profile loads', async ({ page }) => {
  test.setTimeout(90_000)
  await visitRoute(page, `${PREFIX}/engines/top-tier/jwt_attack`)
})
