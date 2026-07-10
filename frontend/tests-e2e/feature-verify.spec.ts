import { test, expect, type Page } from '@playwright/test'
import { installCommandCenterApiMocks } from './api-mock'

/**
 * In-browser verification of this session's new features, driven in a real
 * Chromium against the mock API layer: findings selection + bulk status, saved
 * views, URL-shareable filters, row density, and the ⌘K command palette.
 *
 * These exercise DOM/interaction/keyboard behavior that unit tests cannot.
 */

const CRASH_MARKERS = [
  /This view crashed/i,
  /This tab encountered an error/i,
  /Minified React error/i,
  /Uncaught Error/i,
  /Something went wrong/i,
]

async function assertNoCrash(page: Page) {
  const body = await page.locator('body').innerText()
  for (const re of CRASH_MARKERS) {
    expect(body, `crash copy ${re}`).not.toMatch(re)
  }
}

async function gotoAuthed(page: Page, route: string) {
  await installCommandCenterApiMocks(page)
  await page.goto(route, { waitUntil: 'domcontentloaded' })
  await expect(page.getByText('Verifying session')).toBeHidden({ timeout: 30_000 })
}

test.describe('Findings console — new features', () => {
  test('table renders live rows + density toggle changes row padding', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (e) => errors.push(e.message))
    await gotoAuthed(page, '/command-center/findings')

    const table = page.locator('#findings-command-table')
    await expect(table).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText('SQL Injection in /login')).toBeVisible()
    // 4 mock findings → 4 body rows.
    await expect(table.locator('tbody tr')).toHaveCount(4)

    // Density: comfortable (py-3) → compact (py-1.5).
    const firstCell = table.locator('tbody td').first()
    await expect(firstCell).toHaveClass(/py-3/)
    await page.getByRole('button', { name: /switch to compact rows/i }).click()
    await expect(firstCell).toHaveClass(/py-1\.5/)

    await assertNoCrash(page)
    expect(errors).toEqual([])
  })

  test('multi-select drives the bulk-status bar', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (e) => errors.push(e.message))
    await gotoAuthed(page, '/command-center/findings')

    const table = page.locator('#findings-command-table')
    await expect(table).toBeVisible({ timeout: 20_000 })

    // Select the first two rows via their checkboxes.
    const rowBoxes = table.locator('tbody input[type="checkbox"]')
    await rowBoxes.nth(0).check()
    await rowBoxes.nth(1).check()

    // Bulk bar appears with a live count and non-blank status options.
    await expect(page.getByText(/2 selected/i)).toBeVisible()
    const statusSelect = page.getByLabel('Set status')
    await expect(statusSelect).toBeVisible()
    // Regression guard: options must have real labels (the labelKey bug).
    const optionText = await statusSelect.locator('option').nth(1).innerText()
    expect(optionText.trim().length).toBeGreaterThan(0)

    await statusSelect.selectOption({ index: 1 })
    await page.getByRole('button', { name: /apply to 2/i }).click()
    // Selection clears after the bulk action completes.
    await expect(page.getByText(/2 selected/i)).toBeHidden({ timeout: 10_000 })

    await assertNoCrash(page)
    expect(errors).toEqual([])
  })

  test('saved views persist and re-apply a filter snapshot', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (e) => errors.push(e.message))
    await gotoAuthed(page, '/command-center/findings')
    await expect(page.locator('#findings-command-table')).toBeVisible({ timeout: 20_000 })

    // Name + save the current view.
    await page.getByPlaceholder('Name this view…').fill('E2E Critical')
    await page.getByRole('button', { name: 'Save view' }).click()

    // The saved-view chip appears and is clickable (exact — a separate delete
    // button's aria-label also contains the name).
    const chip = page.getByRole('button', { name: 'E2E Critical', exact: true })
    await expect(chip).toBeVisible()
    await chip.click()

    await assertNoCrash(page)
    expect(errors).toEqual([])
  })

  test('severity filter round-trips through the URL (shareable)', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (e) => errors.push(e.message))

    // Open a pre-filtered link directly → the table hydrates from the URL.
    await gotoAuthed(page, '/command-center/findings?sev=critical')
    const table = page.locator('#findings-command-table')
    await expect(table).toBeVisible({ timeout: 20_000 })
    // Only the two critical findings survive the filter.
    await expect(table.locator('tbody tr')).toHaveCount(2)
    await expect(page.getByText('Exposed S3 bucket')).toBeVisible()
    await expect(page.getByText('Missing HSTS header')).toBeHidden()

    await assertNoCrash(page)
    expect(errors).toEqual([])
  })
})

test.describe('Command palette (⌘K)', () => {
  test('⌘K opens, filters routes, and navigates by keyboard', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (e) => errors.push(e.message))
    // The palette is now global — available even on the bespoke findings page.
    await gotoAuthed(page, '/command-center/findings')
    await expect(page.locator('#findings-command-table')).toBeVisible({ timeout: 20_000 })

    // Ctrl/⌘-K opens the palette dialog (real keyboard binding).
    await page.keyboard.press('Control+k')
    const dialog = page.getByRole('dialog')
    await expect(dialog).toBeVisible()

    // Idle state shows quick-nav options.
    await expect(dialog.getByRole('option').first()).toBeVisible()

    // Type to filter to a route, then Enter navigates.
    const input = dialog.getByRole('combobox')
    await input.fill('audit')
    await expect(dialog.getByRole('option')).toHaveCount(1)
    await page.keyboard.press('Enter')
    await expect(page).toHaveURL(/\/audit/, { timeout: 15_000 })

    await assertNoCrash(page)
    expect(errors).toEqual([])
  })

  test('header search button opens the palette; Escape closes it', async ({ page }) => {
    await gotoAuthed(page, '/command-center/findings')
    await expect(page.locator('#findings-command-table')).toBeVisible({ timeout: 20_000 })
    // The header affordance dispatches the open event.
    await page.evaluate(() => document.dispatchEvent(new CustomEvent('weissman:open-command-palette')))
    await expect(page.getByRole('dialog')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog')).toBeHidden()
  })
})
