/**
 * Headed check: intel-map stays usable; Scan all clients requires a second confirm.
 * Does not POST run-all. DISPLAY=:1. WEISSMAN_ADMIN_PASSWORD required.
 */
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { writeFileSync } from 'node:fs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const require = createRequire(join(ROOT, 'frontend/package.json'))
const { chromium } = require('playwright')

const BASE = (process.env.WEISSMAN_E2E_BASE || 'http://127.0.0.1').replace(/\/$/, '')
const EMAIL = process.env.WEISSMAN_ADMIN_EMAIL || 'admin@localhost'
const PASSWORD = process.env.WEISSMAN_ADMIN_PASSWORD || ''
if (!PASSWORD) {
  console.error('WEISSMAN_ADMIN_PASSWORD is required')
  process.exit(1)
}

const chrome =
  process.env.PLAYWRIGHT_CHROME ||
  ['/usr/bin/google-chrome-stable', '/usr/bin/google-chrome'].find((p) => {
    try {
      require('node:fs').readFileSync(p)
      return true
    } catch {
      return false
    }
  }) || '/usr/bin/google-chrome'

const out = { at: new Date().toISOString(), ok: false, notes: [] }
const browser = await chromium.launch({
  headless: false,
  executablePath: chrome,
  args: ['--start-maximized', '--no-first-run', '--disable-dev-shm-usage'],
})
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
page.setDefaultTimeout(25_000)
page.on('pageerror', (err) => out.notes.push(`pageerror ${err.message}`))

try {
  await page.goto(`${BASE}/command-center/login`, { waitUntil: 'domcontentloaded' })
  await page.locator('#email').fill(EMAIL)
  await page.locator('#password').fill(PASSWORD)
  await page.locator('button[type="submit"]').click()
  await page.waitForURL((url) => !String(url).includes('/login'), { timeout: 60_000 })
  out.notes.push('login ok')

  await page.goto(`${BASE}/command-center/intel-map`, { waitUntil: 'domcontentloaded' })
  await page.locator('#soc-intel-map-root').waitFor({ state: 'visible', timeout: 20_000 })
  out.notes.push('intel-map root visible')
  const scanAll = page.locator('#intel-map-scan-all-clients-btn')
  await scanAll.waitFor({ state: 'visible', timeout: 20_000 })
  const before = (await scanAll.innerText()).trim()
  await scanAll.click()
  await page.waitForTimeout(400)
  const after = (await scanAll.innerText()).trim()
  const barStill = await page.locator('#intel-map-command-bar, [data-testid="intel-map-command-bar"]').isVisible()
  out.before = before
  out.after = after
  out.barStill = barStill
  out.armed = /confirm/i.test(after)
  out.ok = barStill && out.armed
  out.notes.push(`first click: "${before}" -> "${after}" bar=${barStill}`)
} catch (e) {
  out.error = e.message
} finally {
  writeFileSync('/tmp/weissman-live-ops/intel-map-check.json', JSON.stringify(out, null, 2))
  console.log(JSON.stringify({ ok: out.ok, notes: out.notes, before: out.before, after: out.after, error: out.error }))
  await browser.close()
}
process.exit(out.ok ? 0 : 1)
