// CEO end-to-end click-through. Runs against the live Docker stack at http://localhost.
// Each screenshot is written to ./qa-shots/NN_<page>.png and we also log every interaction.

import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'

const OUT = '/home/israel/weissman-cybersecurity/qa-shots'
mkdirSync(OUT, { recursive: true })
const BASE = process.env.WEISSMAN_BASE || 'http://localhost'
const EMAIL = process.env.WEISSMAN_EMAIL || 'admin@localhost'
const PASSWORD = process.env.WEISSMAN_PASSWORD || 'QaTest2026!'
const TENANT = process.env.WEISSMAN_TENANT || 'default'

let stepNo = 0
const reportLines = []

async function shot(page, label) {
  stepNo += 1
  const num = String(stepNo).padStart(2, '0')
  const safe = label.replace(/[^a-z0-9-]+/gi, '_').toLowerCase()
  const file = join(OUT, `${num}_${safe}.png`)
  await page.screenshot({ path: file, fullPage: true })
  const consoleErrors = await page.evaluate(() => {
    return (window.__captured_console_errors || []).slice(-5)
  })
  const url = page.url()
  reportLines.push(`#${num} ${label}\n  url:   ${url}\n  shot:  ${file}\n  errors:${consoleErrors.length ? '\n    ' + consoleErrors.join('\n    ') : ' (none)'}`)
  console.log(`[ok] #${num} ${label} -> ${file}`)
}

async function clickIfVisible(page, selector, label) {
  const el = page.locator(selector).first()
  try {
    await el.waitFor({ state: 'visible', timeout: 4000 })
    await el.click({ timeout: 4000 })
    await page.waitForTimeout(900)
    console.log(`[click] ${label || selector}`)
    return true
  } catch (e) {
    console.log(`[skip] ${label || selector} — not visible`)
    return false
  }
}

const browser = await chromium.launch({
  headless: true,
  args: ['--no-sandbox', '--disable-setuid-sandbox'],
})
const ctx = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  deviceScaleFactor: 1,
  ignoreHTTPSErrors: true,
})
ctx.on('console', (msg) => {
  if (msg.type() === 'error') {
    console.log(`[console.error] ${msg.text()}`)
  }
})

const page = await ctx.newPage()
await page.addInitScript(() => {
  const real = console.error
  window.__captured_console_errors = []
  console.error = function (...args) {
    try { window.__captured_console_errors.push(args.map(String).join(' ')) } catch (_) {}
    real.apply(console, args)
  }
})

try {
  // ── 1. /status (no auth)
  await page.goto(`${BASE}/command-center/status`, { waitUntil: 'networkidle' })
  await shot(page, 'status_public')

  // ── 2. Login page
  await page.goto(`${BASE}/command-center/login`, { waitUntil: 'networkidle' })
  await shot(page, 'login_empty')

  await page.fill('input#tenant', TENANT).catch(() => {})
  await page.fill('input#email', EMAIL)
  await page.fill('input#password', PASSWORD)
  await shot(page, 'login_filled')

  // ── 3. Submit login
  await page.click('button[type="submit"]')
  await page.waitForURL(/\/command-center\/?$/, { timeout: 15000 }).catch(() => {})
  await page.waitForTimeout(2500)
  await shot(page, 'cockpit_home')

  // ── 4. Engines / Engine Matrix
  await page.goto(`${BASE}/command-center/engines`, { waitUntil: 'networkidle' }).catch(() => {})
  await page.waitForTimeout(1500)
  await shot(page, 'engines_matrix')

  // 4a. Open one engine detail
  const firstEngineLink = page.locator('a[href*="/command-center/engines/"]').first()
  if (await firstEngineLink.isVisible().catch(() => false)) {
    await firstEngineLink.click()
    await page.waitForTimeout(1200)
    await shot(page, 'engine_detail')
  }

  // ── 5. Clients page
  await page.goto(`${BASE}/command-center/clients`, { waitUntil: 'networkidle' }).catch(() => {})
  await page.waitForTimeout(1500)
  await shot(page, 'clients_list')

  // 5a. New client form
  await page.goto(`${BASE}/command-center/clients/new`, { waitUntil: 'networkidle' }).catch(() => {})
  await page.waitForTimeout(1200)
  await shot(page, 'client_new_form')

  // ── 6. Findings
  await page.goto(`${BASE}/command-center/findings`, { waitUntil: 'networkidle' }).catch(() => {})
  await page.waitForTimeout(1500)
  await shot(page, 'findings_command_center')

  // ── 7. Vuln Intel Dashboard
  await page.goto(`${BASE}/command-center/vuln-intel`, { waitUntil: 'networkidle' }).catch(() => {})
  await page.waitForTimeout(1500)
  await shot(page, 'vuln_intel_dashboard')

  // 7a. Change severity filter
  await clickIfVisible(page, 'select', 'severity_filter')
  await shot(page, 'vuln_intel_severity_open')

  // ── 8. Agents
  await page.goto(`${BASE}/command-center/agents`, { waitUntil: 'networkidle' }).catch(() => {})
  await page.waitForTimeout(1500)
  await shot(page, 'agents_management')

  // ── 9. System config (MFA panel + AI quota)
  await page.goto(`${BASE}/command-center/system-config`, { waitUntil: 'networkidle' }).catch(() => {})
  await page.waitForTimeout(1500)
  await shot(page, 'system_config')

  // ── 10. CEO command center (root)
  await page.goto(`${BASE}/command-center/`, { waitUntil: 'networkidle' }).catch(() => {})
  await page.waitForTimeout(2000)
  await shot(page, 'ceo_command_center')

  // ── 11. Jobs dashboard
  await page.goto(`${BASE}/command-center/jobs`, { waitUntil: 'networkidle' }).catch(() => {})
  await page.waitForTimeout(1200)
  await shot(page, 'jobs_dashboard')

  // ── 12. Compliance
  await page.goto(`${BASE}/command-center/compliance`, { waitUntil: 'networkidle' }).catch(() => {})
  await page.waitForTimeout(1200)
  await shot(page, 'compliance_frameworks')

  // ── 13. Admin (user management)
  await page.goto(`${BASE}/command-center/admin`, { waitUntil: 'networkidle' }).catch(() => {})
  await page.waitForTimeout(1200)
  await shot(page, 'admin_management')

  // ── 14. Hit a known-broken route to make sure the error boundary catches it
  await page.goto(`${BASE}/command-center/this-route-does-not-exist`, { waitUntil: 'networkidle' }).catch(() => {})
  await page.waitForTimeout(800)
  await shot(page, 'unknown_route_fallback')
} catch (err) {
  console.log(`[FATAL] ${err.message}`)
  await shot(page, 'fatal_error')
} finally {
  console.log('')
  console.log('────────────────────────────  CEO walk-through report  ────────────────────────────')
  console.log(reportLines.join('\n\n'))
  await browser.close()
}
