import { test, expect, type Page } from '@playwright/test'
import { PRODUCTION_ENGINE_COUNT } from '../src/lib/platformScale'

/**
 * Login screen, driven in a real browser: the workspace picker and the backdrop's loop.
 *
 * The seam tests are the reason this file exists. "The background loops without a visible jump" is
 * not checkable by reading CSS and not checkable by eye — a layer whose travel distance drifts from
 * its tile period animates perfectly smoothly and then teleports by the difference once per cycle,
 * which a screenshot cannot show and a human watching a 60s recording will miss. Here the claim is
 * measured: each backdrop animation is paused and parked at t=0 and at t=exactly one period, and the
 * two rendered frames must be byte-identical, while a frame parked mid-period must differ (otherwise
 * "identical" would just mean "nothing moves").
 */

const LOGIN = '/command-center/login'
const BACKDROP = '[data-testid="cyber-live-backdrop"]'

type DirectoryPayload = Record<string, unknown>

const ENUMERATED: DirectoryPayload = {
  ok: true,
  listing: 'enumerated',
  tenants: [
    { slug: 'acme-energy', name: 'Acme Energy Grid' },
    { slug: 'default', name: 'Default Organization' },
    { slug: 'northwind-health', name: 'Northwind Health' },
  ],
  default_slug: 'default',
  allow_custom: false,
  truncated: false,
}

const RESTRICTED: DirectoryPayload = {
  ok: true,
  listing: 'restricted',
  tenants: [],
  default_slug: 'default',
  allow_custom: true,
  truncated: false,
}

async function gotoLogin(page: Page, directory: DirectoryPayload | 'unavailable') {
  await page.route('**/api/auth/tenant-directory', (route) =>
    directory === 'unavailable'
      ? route.fulfill({ status: 503, contentType: 'application/json', body: '{"ok":false}' })
      : route.fulfill({
          status: 200,
          contentType: 'application/json; charset=utf-8',
          body: JSON.stringify(directory),
        }),
  )
  await page.goto(LOGIN, { waitUntil: 'domcontentloaded' })
  await page.waitForSelector(BACKDROP, { timeout: 30_000 })
}

/** Backdrop animations only — the form's entrance transitions are none of this file's business. */
async function backdropAnimations(page: Page) {
  return page.evaluate(() =>
    document
      .getAnimations()
      .filter((a) => (a.effect as KeyframeEffect | null)?.target?.closest?.('.wm-cyber-backdrop'))
      .map((a) => ({
        name: (a as CSSAnimation).animationName,
        klass: ((a.effect as KeyframeEffect).target as Element).className,
        duration: Number((a.effect as KeyframeEffect).getTiming().duration),
      })),
  )
}

/**
 * Hide the foreground and freeze the page so a screenshot is a pure function of animation time:
 * no caret blink, no logo glow, no text antialiasing to compare.
 */
async function isolateBackdrop(page: Page) {
  await page.addStyleTag({
    content: `.wm-cyber-backdrop ~ * { visibility: hidden !important; }`,
  })
  await page.evaluate(() => {
    for (const a of document.getAnimations()) {
      const target = (a.effect as KeyframeEffect | null)?.target as Element | undefined
      if (target?.closest?.('.wm-cyber-backdrop')) a.pause()
      else a.finish?.()
    }
  })
}

/** Show only the layers matching `selector` (or all of them when null). */
async function showOnly(page: Page, selector: string | null) {
  await page.evaluate((sel) => {
    for (const el of document.querySelectorAll<HTMLElement>('.wm-cyber-backdrop > *')) {
      const keep = sel === null || el.matches(sel) || !!el.querySelector(sel)
      el.style.visibility = keep ? 'visible' : 'hidden'
    }
  }, selector)
}

/** Park matching backdrop animations at `fraction` of their own period and render. */
async function frameAt(page: Page, selector: string | null, fraction: number): Promise<Buffer> {
  await page.evaluate(
    ({ sel, f }) => {
      for (const a of document.getAnimations()) {
        const target = (a.effect as KeyframeEffect | null)?.target as Element | undefined
        if (!target?.closest?.('.wm-cyber-backdrop')) continue
        if (sel !== null && !target.matches(sel) && !target.closest(sel)) continue
        a.currentTime = Number((a.effect as KeyframeEffect).getTiming().duration) * f
      }
    },
    { sel: selector, f: fraction },
  )
  // One rAF beat so the compositor commits the parked time before the capture.
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => resolve(null))))
  return page.screenshot({ animations: 'allow' })
}

test.describe('Login — workspace picker', () => {
  test('renders the workspaces the directory lists, as a select', async ({ page }) => {
    await gotoLogin(page, ENUMERATED)
    const select = page.locator('select#tenant')
    await expect(select).toBeVisible({ timeout: 20_000 })
    await expect(select).toHaveValue('default')
    await expect(select.locator('option')).toHaveText([
      'Acme Energy Grid · acme-energy',
      'Default Organization · default',
      'Northwind Health · northwind-health',
    ])

    await select.selectOption('northwind-health')
    await expect(select).toHaveValue('northwind-health')
  })

  test('adopts a real slug when the form default is not one of them', async ({ page }) => {
    await gotoLogin(page, {
      ...ENUMERATED,
      tenants: [{ slug: 'acme-energy', name: 'Acme Energy Grid' }],
    })
    await expect(page.locator('select#tenant')).toHaveValue('acme-energy', { timeout: 20_000 })
  })

  test('degrades to manual entry, with the reason, when the list is withheld', async ({ page }) => {
    await gotoLogin(page, RESTRICTED)
    const input = page.locator('input#tenant')
    await expect(input).toBeVisible({ timeout: 20_000 })
    await expect(page.locator('select#tenant')).toHaveCount(0)
    await expect(page.getByText(/does not publish its workspace list/i)).toBeVisible()
    await input.fill('ops-eu')
    await expect(input).toHaveValue('ops-eu')
  })

  test('degrades to manual entry when the directory endpoint is down', async ({ page }) => {
    await gotoLogin(page, 'unavailable')
    await expect(page.locator('input#tenant')).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText(/Workspace list unavailable/i)).toBeVisible()
  })

  test('quotes the shipped engine count in the brand copy and the badge', async ({ page }) => {
    await gotoLogin(page, ENUMERATED)
    await expect(
      page.getByText(new RegExp(`${PRODUCTION_ENGINE_COUNT} attack engines`)),
    ).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText(`${PRODUCTION_ENGINE_COUNT} engines`).first()).toBeVisible()
  })
})

test.describe('Login — live backdrop', () => {
  test('every layer animates, forever', async ({ page }) => {
    await gotoLogin(page, ENUMERATED)
    const animations = await backdropAnimations(page)
    expect(animations.length).toBeGreaterThanOrEqual(8)
    for (const animation of animations) {
      expect(animation.duration, `${animation.name} must have a real period`).toBeGreaterThan(0)
    }
    const infinite = await page.evaluate(() =>
      [...document.querySelectorAll('.wm-cyber-backdrop *')]
        .filter((el) => getComputedStyle(el).animationName !== 'none')
        .every((el) => getComputedStyle(el).animationIterationCount === 'infinite'),
    )
    expect(infinite, 'a backdrop layer stops looping').toBe(true)
  })

  test('moves on its own, with no script driving it', async ({ page }) => {
    await gotoLogin(page, ENUMERATED)
    await page.addStyleTag({ content: `.wm-cyber-backdrop ~ * { visibility: hidden !important; }` })
    const frames: string[] = []
    for (let i = 0; i < 3; i += 1) {
      frames.push((await page.screenshot({ animations: 'allow' })).toString('base64'))
      await page.waitForTimeout(400)
    }
    expect(new Set(frames).size, 'the backdrop rendered identical frames 400ms apart').toBe(3)
    // No canvas and no rAF loop: the motion is the compositor's, so a hidden tab costs nothing.
    expect(await page.locator(`${BACKDROP} canvas, ${BACKDROP} video`).count()).toBe(0)
  })

  test('has no seam: each layer renders the same frame at t=0 and t=one period', async ({
    page,
  }) => {
    await gotoLogin(page, ENUMERATED)
    await isolateBackdrop(page)

    for (const { name, klass } of await backdropAnimations(page)) {
      const selector = `.${klass.trim().split(/\s+/).join('.')}`
      await showOnly(page, selector)

      const start = await frameAt(page, selector, 0)
      const wrapped = await frameAt(page, selector, 1)
      const middle = await frameAt(page, selector, 0.37)

      expect(
        start.equals(wrapped),
        `${name} (${selector}) renders a different frame after one full period — that difference ` +
          'is the jump a viewer sees once per cycle',
      ).toBe(true)
      expect(
        start.equals(middle),
        `${name} (${selector}) renders the same frame mid-period, so it is not actually moving ` +
          'and the seam check above proves nothing',
      ).toBe(false)
    }
  })

  test('has no seam as a whole: the composite wraps too', async ({ page }) => {
    await gotoLogin(page, ENUMERATED)
    await isolateBackdrop(page)
    await showOnly(page, null)

    const start = await frameAt(page, null, 0)
    const wrapped = await frameAt(page, null, 1)
    const middle = await frameAt(page, null, 0.61)

    expect(start.equals(wrapped), 'the composed backdrop jumps when its cycles wrap').toBe(true)
    expect(start.equals(middle), 'the composed backdrop does not move').toBe(false)
  })
})
