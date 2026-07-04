/**
 * Saves authenticated storage state for live UI tests (login once per run).
 */
import { test as setup } from '@playwright/test'
import { uiLogin, liveEnabled } from './live-helpers'
import path from 'node:path'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const AUTH_FILE = path.join(__dirname, '.auth', 'admin.json')

setup('authenticate admin', async ({ page }) => {
  setup.skip(!liveEnabled(), 'PLAYWRIGHT_LIVE=1 and WEISSMAN_ADMIN_PASSWORD required')
  fs.mkdirSync(path.dirname(AUTH_FILE), { recursive: true })
  await uiLogin(page)
  // storageState captures cookies + localStorage, not sessionStorage
  await page.evaluate(() => {
    const t = sessionStorage.getItem('weissman_access_token')
    if (t) localStorage.setItem('weissman_access_token', t)
  })
  await page.context().storageState({ path: AUTH_FILE })
})
