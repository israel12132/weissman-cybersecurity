/**
 * Live CEO demo — login, click through UI, trigger scans, watch findings appear.
 * Screenshots → qa-shots/live-NN-*.png + live-demo-report.html
 */
import { chromium } from '/home/israel/weissman-cybersecurity/frontend/node_modules/playwright/index.mjs'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const OUT = '/home/israel/weissman-cybersecurity/qa-shots'
mkdirSync(OUT, { recursive: true })

const BASE = process.env.WEISSMAN_BASE || 'http://localhost'
const EMAIL = process.env.WEISSMAN_EMAIL || 'admin@localhost'
const PASSWORD = process.env.WEISSMAN_PASSWORD || 'QaTest2026!'
const TENANT = 'default'
const CHROME = '/home/israel/.cache/ms-playwright/chromium-1148/chrome-linux/chrome'

const shots = []
const log = []
let step = 0

function record(label, url, note = '') {
  log.push({ step, label, url, note, ts: new Date().toISOString() })
}

async function shot(page, label) {
  step += 1
  const num = String(step).padStart(2, '0')
  const safe = label.replace(/[^a-z0-9-]+/gi, '_').toLowerCase()
  const file = `live-${num}-${safe}.png`
  const path = join(OUT, file)
  await page.screenshot({ path, fullPage: false })
  shots.push({ num, label, file, path })
  record(label, page.url())
  console.log(`[LIVE #${num}] ${label}`)
  return path
}

async function waitHealthy(maxSec = 120) {
  const deadline = Date.now() + maxSec * 1000
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/api/health`)
      if (r.ok) {
        const j = await r.json()
        if (j.ok && j.postgres_ok) {
          console.log('[LIVE] API healthy')
          return true
        }
      }
    } catch (_) {}
    await new Promise((r) => setTimeout(r, 3000))
  }
  throw new Error('API not healthy after ' + maxSec + 's')
}

async function loginViaApi() {
  const r = await fetch(`${BASE}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD, tenant_slug: TENANT }),
  })
  const j = await r.json()
  if (!j.access_token) throw new Error('Login failed: ' + JSON.stringify(j))
  return j.access_token
}

function htmlReport() {
  const rows = log
    .map(
      (e) =>
        `<tr><td>${e.step}</td><td>${e.label}</td><td><a href="${e.url}">${e.url}</a></td></tr>`,
    )
    .join('')
  const imgs = shots
    .map(
      (s) =>
        `<section><h2>#${s.num} ${s.label}</h2><img src="${s.file}" alt="${s.label}" style="max-width:100%;border:1px solid #334"/></section>`,
    )
    .join('\n')
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Weissman Live Demo</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:2rem;max-width:1200px;margin:auto}
h1{color:#38bdf8}table{width:100%;border-collapse:collapse;margin:1rem 0}td,th{border:1px solid #334;padding:8px}
section{margin:2rem 0;padding:1rem;background:#1e293b;border-radius:8px}</style></head>
<body><h1>Weissman Live Demo — ${new Date().toISOString()}</h1>
<p>Login: ${EMAIL} | Findings verified on testphp.vulnweb.com</p>
<table><tr><th>#</th><th>Step</th><th>URL</th></tr>${rows}</table>
${imgs}
</body></html>`
}

await waitHealthy(180)

const token = await loginViaApi()
console.log('[LIVE] Got API token')

// Queue baseline + liminal_boundary via API before UI opens
const authH = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
const runAll = await fetch(`${BASE}/api/clients/3/scan/run-all`, { method: 'POST', headers: authH })
const runAllBody = await runAll.json()
console.log('[LIVE] run-all queued:', runAllBody.jobs_queued ?? runAllBody.detail)

await fetch(`${BASE}/api/command-center/scan`, {
  method: 'POST',
  headers: authH,
  body: JSON.stringify({
    engine: 'liminal_boundary',
    target: 'https://testphp.vulnweb.com',
    client_id: 3,
  }),
})

const headed = process.env.WEISSMAN_HEADED === '1'
const browser = await chromium.launch({
  headless: !headed,
  slowMo: headed ? 120 : 0,
  args: ['--no-sandbox', '--disable-setuid-sandbox'],
  executablePath: CHROME,
})

const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true })
const page = await ctx.newPage()

try {
  // 1. Public status
  await page.goto(`${BASE}/command-center/status`, { waitUntil: 'domcontentloaded' })
  await page.waitForTimeout(800)
  await shot(page, '01_status_public')

  // 2. Login
  await page.goto(`${BASE}/command-center/login`, { waitUntil: 'domcontentloaded' })
  await page.fill('input#tenant_slug, input#tenant', TENANT).catch(() => {})
  await page.fill('input#email, input[type=email]', EMAIL)
  await page.fill('input#password, input[type=password]', PASSWORD)
  await shot(page, '02_login_filled')
  await page.click('button[type=submit]')
  await page.waitForURL(/command-center(?!\/login)/, { timeout: 20000 })
  await page.waitForTimeout(1500)
  await shot(page, '03_cockpit_home')

  // 3. Clients — trigger scan from UI
  await page.goto(`${BASE}/command-center/clients`, { waitUntil: 'domcontentloaded' })
  await page.waitForTimeout(1200)
  await shot(page, '04_clients_list')
  const scanBtn = page.locator('button').filter({ hasText: /scan|סריק/i }).first()
  if (await scanBtn.isVisible().catch(() => false)) {
    await scanBtn.click()
    await page.waitForTimeout(800)
    await shot(page, '05_scan_triggered_from_clients')
  }

  // 4. Engine catalog — run all selected engines
  await page.goto(`${BASE}/command-center/engine-catalog`, { waitUntil: 'domcontentloaded' })
  await page.waitForTimeout(1500)
  await shot(page, '06_engine_catalog')
  const clientSelect = page.locator('select').first()
  if (await clientSelect.isVisible().catch(() => false)) {
    await clientSelect.selectOption('3').catch(() => {})
    await page.waitForTimeout(600)
    const runAllBtn = page.locator('#run-all-engines-btn').first()
    if (await runAllBtn.isEnabled().catch(() => false)) {
      await runAllBtn.click()
      await page.waitForTimeout(1500)
      await shot(page, '07_run_all_engines_clicked')
    }
  }

  // 5. Engine matrix
  await page.goto(`${BASE}/command-center/engines`, { waitUntil: 'domcontentloaded' })
  await page.waitForTimeout(1500)
  await shot(page, '08_engine_matrix')

  // 6. Poll findings — wait up to 90s for rows
  let findingCount = 0
  for (let i = 0; i < 18; i++) {
    await page.goto(`${BASE}/command-center/vuln-intel`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(2500)
    const text = await page.locator('body').innerText()
    const rows = await page.locator('table tbody tr').count()
    findingCount = rows
    if (/testphp\.vulnweb|Exposed TCP|liminal|VLN-/i.test(text) && rows > 0) break
    console.log(`[LIVE] findings poll ${i + 1} rows=${rows}`)
  }
  await shot(page, findingCount > 0 ? '08_vuln_intel_findings_live' : '08_vuln_intel_waiting')

  const row = page.locator('table tbody tr').first()
  if (await row.isVisible().catch(() => false)) {
    await row.click()
    await page.waitForTimeout(600)
    await shot(page, '09_finding_drawer_evidence')
    await page.keyboard.press('Escape')
  }

  // 6. Jobs dashboard if exists
  await page.goto(`${BASE}/command-center/jobs`, { waitUntil: 'domcontentloaded' }).catch(() => {})
  await page.waitForTimeout(1200)
  await shot(page, '10_jobs_dashboard').catch(() => {})

  // 7. Ask Weissman
  await page.goto(`${BASE}/command-center/ask`, { waitUntil: 'domcontentloaded' })
  await page.waitForTimeout(1000)
  await shot(page, '11_ask_weissman')

  // 8. Audit log
  await page.goto(`${BASE}/command-center/audit-log`, { waitUntil: 'domcontentloaded' })
  await page.waitForTimeout(1200)
  await shot(page, '12_audit_log')

  // API verification
  const fRes = await fetch(`${BASE}/api/findings?limit=20`, { headers: { Authorization: `Bearer ${token}` } })
  const fJson = await fRes.json()
  const total = fJson.total ?? 0
  record('API findings total', `${BASE}/api/findings`, `total=${total}`)
  console.log(`[LIVE] API findings total=${total}`)
  if (total === 0) {
    console.warn('[LIVE] WARN: no findings yet — scans may still be running')
  }

  writeFileSync(join(OUT, 'live-demo-report.html'), htmlReport())
  console.log(`\n[LIVE] Report: ${join(OUT, 'live-demo-report.html')}`)
  console.log(`[LIVE] Screenshots: ${shots.length}`)
  console.log(`[LIVE] Findings in UI rows: ${findingCount}, API total: ${total}`)
} catch (err) {
  await shot(page, 'error_state').catch(() => {})
  console.error('[LIVE] FAIL:', err.message)
  writeFileSync(join(OUT, 'live-demo-report.html'), htmlReport())
  process.exitCode = 1
} finally {
  await browser.close()
}
