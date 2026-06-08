// Visual diff of the new real-time UI (KPI strip + activity feed + MITRE matrix +
// top movers + trend chart). Captures full-page screenshots after login.

import { chromium } from '/home/israel/weissman-cybersecurity/frontend/node_modules/playwright/index.mjs'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'

const OUT = '/home/israel/weissman-cybersecurity/qa-shots'
mkdirSync(OUT, { recursive: true })

const BASE = 'http://localhost'
const EMAIL = 'admin@localhost'
const PASSWORD = 'QaTest2026!'
const TENANT = 'default'

const browser = await chromium.launch({
  headless: true,
  args: ['--no-sandbox'],
  executablePath: '/home/israel/.cache/ms-playwright/chromium-1148/chrome-linux/chrome',
})
const ctx = await browser.newContext({
  viewport: { width: 1600, height: 1000 },
  ignoreHTTPSErrors: true,
})
const page = await ctx.newPage()
page.on('console', (m) => { if (m.type() === 'error') console.log('[console.error]', m.text().slice(0, 160)) })

let step = 0
async function shot(label) {
  step += 1
  const file = join(OUT, `realtime-ui-${String(step).padStart(2, '0')}-${label}.png`)
  await page.screenshot({ path: file, fullPage: true })
  console.log(`  ${step.toString().padStart(2, '0')} ${label}  →  ${file}`)
}

console.log('\n=== Real-time UI screenshots ===')
await page.goto(`${BASE}/command-center/login`, { waitUntil: 'domcontentloaded' })
await page.waitForTimeout(800)
await page.fill('input#tenant_slug, input[name=tenant_slug]', TENANT).catch(() => {})
await page.fill('input#email, input[type=email]', EMAIL)
await page.fill('input#password, input[type=password]', PASSWORD)
await page.click('button[type=submit]')
await page.waitForLoadState('networkidle', { timeout: 12000 }).catch(() => {})
await page.waitForTimeout(2500)

await shot('cockpit_with_exec_kpi_strip')

// Switch to Overview tab to see the new dashboard panels
const overviewTab = page.locator('button:has-text("Overview")').first()
if (await overviewTab.isVisible().catch(() => false)) {
  await overviewTab.click()
  await page.waitForTimeout(2500)
}
await shot('overview_with_realtime_panels')

// Scroll down to see all panels
await page.evaluate(() => window.scrollTo(0, 600))
await page.waitForTimeout(800)
await shot('overview_scrolled_mitre_matrix')

await page.evaluate(() => window.scrollTo(0, 1400))
await page.waitForTimeout(800)
await shot('overview_scrolled_top_movers')

await browser.close()
console.log('\n=== Done ===')
