/**
 * Headed live operator: login as owner, click War Power, walk Command Center routes.
 * Run from repo root:
 *   DISPLAY=:1 WEISSMAN_E2E_BASE=http://127.0.0.1 PLAYWRIGHT_LIVE=1 node scripts/live_war_power_click.mjs
 * Does not print secrets.
 */
import { mkdirSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

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

const LOG_DIR = process.env.WEISSMAN_LIVE_OPS_DIR || '/tmp/weissman-live-ops'
const LOG_FILE = join(LOG_DIR, 'ui-walk.log')
mkdirSync(LOG_DIR, { recursive: true })

function log(line) {
  const row = `${new Date().toISOString()} ${line}`
  console.log(line)
  try {
    appendFileSync(LOG_FILE, `${row}\n`)
  } catch {
    /* ignore */
  }
}

function commandCenterRoutes() {
  const src = readFileSync(join(ROOT, 'frontend/src/TacticalApp.jsx'), 'utf8')
  const seen = new Set(['/command-center/'])
  for (const m of src.matchAll(/path="([^"]+)"/g)) {
    const p = m[1]
    if (!p || p === '*' || p === 'login' || p.includes(':')) continue
    seen.add(`/command-center/${p}`)
  }
  return [...seen]
}

const DANGEROUS =
  /isolate|nft\b|apply firewall|apply rules|delete client|revoke agent|wipe |destroy |genesis.?kill|factory reset|detonate|block host|safe mode|engage safe|scan all clients|all clients/i

async function clickTabs(page) {
  const tabs = page.locator('button[id^="cockpit-tab-"], [role="tab"]')
  const n = Math.min(await tabs.count(), 16)
  for (let i = 0; i < n; i += 1) {
    const tab = tabs.nth(i)
    const id = (await tab.getAttribute('id')) || `tab-${i}`
    await tab.click({ timeout: 4000 }).catch(() => {})
    log(`click tab ${id}`)
    await page.waitForTimeout(350)
  }
}

async function waitEnabled(page, selector, timeout = 90_000) {
  await page.waitForFunction(
    (sel) => {
      const el = document.querySelector(sel)
      return !!(el && !el.disabled)
    },
    selector,
    { timeout },
  )
}

async function clickSafeButtons(page, route) {
  const buttons = page.locator('button:visible')
  const n = Math.min(await buttons.count(), 18)
  let clicked = 0
  for (let i = 0; i < n; i += 1) {
    const btn = buttons.nth(i)
    const id = ((await btn.getAttribute('id', { timeout: 2000 }).catch(() => '')) || '').trim()
    const text = ((await btn.innerText().catch(() => '')) || '').trim().replace(/\s+/g, ' ')
    const label = `${id} ${text}`.trim()
    if (!label) continue
    if (DANGEROUS.test(label)) {
      log(`skip dangerous ${route} :: ${label.slice(0, 80)}`)
      continue
    }
    if (/unleash|max aggressive|war-unleash|war-max/i.test(label)) continue
    const looksAction =
      /scan|run|engage|refresh|reload|export|search|filter|apply|queue|harvest|start|probe|analyze/i.test(
        label,
      )
    if (!looksAction && !id.startsWith('cockpit-tab-')) continue
    if (/safe mode/i.test(label) && /on\b/i.test(label)) continue
    await btn.scrollIntoViewIfNeeded().catch(() => {})
    await btn.click({ timeout: 2500 }).catch(() => {})
    clicked += 1
    log(`click ${route} :: ${label.slice(0, 90)}`)
    await page.waitForTimeout(400)
    if (clicked >= 6) break
  }
}

async function main() {
  writeFileSync(LOG_FILE, `ui walk start ${new Date().toISOString()}\n`)
  const chrome =
    process.env.PLAYWRIGHT_CHROME ||
    ['/usr/bin/google-chrome-stable', '/usr/bin/google-chrome'].find((p) => {
      try {
        readFileSync(p)
        return true
      } catch {
        return false
      }
    }) || '/usr/bin/google-chrome'

  const browser = await chromium.launch({
    headless: false,
    executablePath: chrome,
    slowMo: 180,
    args: [
      '--start-maximized',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-dev-shm-usage',
    ],
  })
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
  page.setDefaultTimeout(45_000)
  page.on('pageerror', (err) => log(`pageerror ${err.message}`))

  try {
  log('UI login…')
  await page.goto(`${BASE}/command-center/login`, { waitUntil: 'domcontentloaded' })
  await page.locator('#email').waitFor({ state: 'visible', timeout: 20_000 })
  await page.locator('#email').click()
  await page.locator('#email').fill(EMAIL)
  await page.locator('#password').fill(PASSWORD)
  await page.locator('button[type="submit"]').click()
  await page.waitForURL((url) => !String(url).includes('/login'), { timeout: 60_000 })
  await page.getByText('Verifying session').waitFor({ state: 'hidden', timeout: 30_000 }).catch(() => {})
  log('login ok')

  log('Cockpit home…')
  await page.goto(`${BASE}/command-center/`, { waitUntil: 'domcontentloaded' })
  const clientBtn = page.locator('#cockpit-client-1, aside.cockpit-sidebar ul.space-y-px li button').first()
  await page.getByRole('button', { name: /augury/i }).first().waitFor({ state: 'visible', timeout: 20_000 })
  await page.getByRole('button', { name: /augury/i }).first().click()
  log('selected client augury')
  await page.waitForTimeout(1200)
  if (await clientBtn.count()) {
    await clientBtn.click().catch(() => {})
  }

  const mission = page.locator('#cockpit-tab-mission-control')
  if (await mission.count()) {
    await mission.click().catch(() => {})
    log('clicked mission-control tab')
  }

  const panel = page.locator('#ceo-war-power-panel')
  await panel.scrollIntoViewIfNeeded().catch(() => {})
  await panel.waitFor({ state: 'visible', timeout: 30_000 })
  try {
    log('War Power panel visible — clicking Unleash…')
    await waitEnabled(page, '#ceo-war-unleash-compute-btn', 20_000)
    await page.locator('#ceo-war-unleash-compute-btn').click()
    await waitEnabled(page, '#ceo-war-unleash-compute-btn', 90_000)
    log('Unleash finished — clicking Max aggressive…')
    await waitEnabled(page, '#ceo-war-max-aggressive-btn', 20_000)
    await page.locator('#ceo-war-max-aggressive-btn').click()
    await waitEnabled(page, '#ceo-war-max-aggressive-btn', 120_000)
    log('Max aggressive finished')
  } catch (err) {
    log(`War Power click failed (continuing walk): ${err.message}`)
  }

  const engage = page.locator('#cockpit-engage-scan-btn')
  if (await engage.count()) {
    await engage.click({ timeout: 5000 }).catch(() => {})
    log('clicked cockpit Engage')
    await page.waitForTimeout(2500)
  }

  await clickTabs(page)

  const routes = commandCenterRoutes()
  log(`walking ${routes.length} routes`)
  const broken = []
  for (const route of routes) {
    log(`Open ${route}`)
    try {
      const res = await page.goto(`${BASE}${route}`, { waitUntil: 'domcontentloaded', timeout: 45_000 })
      const status = res?.status() || 0
      await page.locator('#root').waitFor({ state: 'visible', timeout: 20_000 })
      await page.waitForTimeout(700)
      const body = ((await page.locator('#root').innerText().catch(() => '')) || '').slice(0, 80)
      if (status >= 400) {
        broken.push({ route, status, body })
        log(`BROKEN ${route} HTTP ${status}`)
      } else if (/not found|something went wrong|chunk load/i.test(body)) {
        broken.push({ route, status, body })
        log(`BROKEN ${route} ui ${body.replace(/\s+/g, ' ')}`)
      }
      await clickSafeButtons(page, route)
    } catch (err) {
      broken.push({ route, error: err.message })
      log(`BROKEN ${route} ${err.message}`)
    }
  }

  writeFileSync(
    join(LOG_DIR, 'ui-walk-broken.json'),
    JSON.stringify({ at: new Date().toISOString(), broken }, null, 2),
  )
  log(`walk done broken=${broken.length}`)

  log('Keeping headed browser open 120s so you can watch…')
  await page.waitForTimeout(120_000)
  } finally {
    await browser.close().catch(() => {})
    log('browser closed')
  }
}

main().catch((err) => {
  console.error(err?.message || err)
  process.exit(1)
})
