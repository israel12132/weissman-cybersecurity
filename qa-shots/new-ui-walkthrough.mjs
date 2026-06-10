// Targeted walkthrough for the new UI additions:
//   - Branded SVG logo in nav
//   - Profile menu top-right (open + close)
//   - Toast notification system
//   - Keyboard shortcuts overlay (? key)
//   - Finding detail drawer (click row in Vuln Intel)
//   - Audit log viewer
//   - 404 page
//
// Outputs to ./qa-shots/new-ui-*.png and writes a short report to new-ui-report.txt.

import { chromium } from '/home/israel/weissman-cybersecurity/frontend/node_modules/playwright/index.mjs'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const OUT = '/home/israel/weissman-cybersecurity/qa-shots'
mkdirSync(OUT, { recursive: true })

const BASE = 'http://localhost'
const EMAIL = 'admin@localhost'
const PASSWORD = 'QaTest2026!'
const TENANT = 'default'

const consoleErrors = []
const lines = []
let step = 0
async function shot(page, label) {
  step += 1
  const num = String(step).padStart(2, '0')
  const safe = label.replace(/[^a-z0-9-]+/gi, '_').toLowerCase()
  const path = join(OUT, `new-ui-${num}-${safe}.png`)
  await page.screenshot({ path, fullPage: false })
  const errs = consoleErrors.splice(0)
  lines.push(`#${num} ${label}\n  url:    ${page.url()}\n  shot:   ${path}\n  errors: ${errs.length ? errs.length + ' (' + errs.slice(0,2).join(' | ') + ')' : 'none'}`)
  console.log(`[ok] ${num} ${label}`)
}

const browser = await chromium.launch({
  headless: true,
  args: ['--no-sandbox', '--disable-setuid-sandbox'],
  executablePath: '/home/israel/.cache/ms-playwright/chromium-1148/chrome-linux/chrome',
})
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true })
const page = await ctx.newPage()
page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text().slice(0, 120)) })
page.on('pageerror', (e) => consoleErrors.push(`pageerror: ${e.message.slice(0, 120)}`))

await page.goto(`${BASE}/command-center/login`, { waitUntil: 'domcontentloaded' })
await page.waitForTimeout(800)
await page.fill('input#tenant_slug', TENANT).catch(() => {})
await page.fill('input#email, input[type=email]', EMAIL)
await page.fill('input#password, input[type=password]', PASSWORD)
await shot(page, 'login_with_logo')
await page.click('button[type=submit]')
await page.waitForLoadState('networkidle', { timeout: 12000 }).catch(() => {})
await page.waitForTimeout(1500)
await shot(page, 'cockpit_with_new_logo_and_profile_menu')

// 1) Open profile menu
{
  const profileBtn = page.locator('button[aria-haspopup="menu"]').first()
  if (await profileBtn.isVisible().catch(() => false)) {
    await profileBtn.click()
    await page.waitForTimeout(400)
    await shot(page, 'profile_menu_open')
    await page.keyboard.press('Escape')
    await page.waitForTimeout(300)
  } else {
    lines.push('SKIP: profile menu button not found')
  }
}

// 2) Keyboard shortcuts overlay
{
  await page.keyboard.press('?')
  await page.waitForTimeout(400)
  await shot(page, 'kbd_shortcuts_overlay')
  await page.keyboard.press('Escape')
  await page.waitForTimeout(300)
}

// 3) Vuln Intel + finding drawer
{
  await page.goto(`${BASE}/command-center/vuln-intel`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(1200)
  await shot(page, 'vuln_intel_with_skeleton_or_data')
  const row = page.locator('table tbody tr').first()
  if (await row.isVisible().catch(() => false)) {
    await row.click()
    await page.waitForTimeout(500)
    await shot(page, 'finding_drawer_open')
    await page.keyboard.press('Escape')
    await page.waitForTimeout(300)
  } else {
    lines.push('NOTE: no findings yet — empty state should be visible above')
  }
}

// 4) Audit log
{
  await page.goto(`${BASE}/command-center/audit-log`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(1500)
  await shot(page, 'audit_log_viewer')
  await page.fill('input[placeholder*="action"]', 'login').catch(() => {})
  await page.waitForTimeout(900)
  await shot(page, 'audit_log_filtered_login')
}

// 5) 404 page
{
  await page.goto(`${BASE}/command-center/does-not-exist-xyz`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(600)
  await shot(page, 'not_found_404')
}

// 6) Switch to Hebrew via profile menu (RTL check)
{
  await page.goto(`${BASE}/command-center/`, { waitUntil: 'domcontentloaded' })
  await page.waitForTimeout(800)
  const profileBtn = page.locator('button[aria-haspopup="menu"]').first()
  if (await profileBtn.isVisible().catch(() => false)) {
    await profileBtn.click()
    await page.waitForTimeout(300)
    const heBtn = page.locator('button[aria-pressed]', { hasText: 'עברית' }).first()
    if (await heBtn.isVisible().catch(() => false)) {
      await heBtn.click()
      await page.waitForTimeout(500)
      await shot(page, 'profile_menu_hebrew_active')
    }
  }
  // Click outside to close
  await page.mouse.click(20, 20)
  await page.waitForTimeout(400)
  await shot(page, 'cockpit_rtl_hebrew')
}

await browser.close()

writeFileSync(join(OUT, 'new-ui-report.txt'), lines.join('\n\n'))
console.log('\n=== Summary ===')
console.log(lines.join('\n\n'))
