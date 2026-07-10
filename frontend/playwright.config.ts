import { defineConfig, devices } from '@playwright/test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const E2E_PORT = process.env.PLAYWRIGHT_PORT || '5199'
const MOCK_BASE = `http://localhost:${E2E_PORT}`
const LIVE_BASE = (process.env.WEISSMAN_E2E_BASE || 'http://127.0.0.1:8000').replace(/\/$/, '')
const UI_DEV_BASE = (process.env.PLAYWRIGHT_UI_DEV === '1' ? 'http://127.0.0.1:5173' : LIVE_BASE).replace(/\/$/, '')
const IS_LIVE = process.env.PLAYWRIGHT_LIVE === '1'
const AUTH_FILE = path.join(__dirname, 'tests-e2e', '.auth', 'admin.json')

// Escape hatch for sandboxes where the pinned Playwright browser build differs
// from the pre-installed one: point at an explicit Chromium executable. Unset in
// CI, so default browser resolution is unchanged there.
const PW_EXECUTABLE_PATH = process.env.PW_EXECUTABLE_PATH || undefined
const launchOptions = PW_EXECUTABLE_PATH ? { executablePath: PW_EXECUTABLE_PATH } : undefined

/**
 * Two projects:
 *  - chromium-mock: Vite dev server + API mocks (fast UI smoke)
 *  - chromium-live: real backend at WEISSMAN_E2E_BASE (Docker / run_e2e_stack.sh)
 */
export default defineConfig({
  testDir: './tests-e2e',
  timeout: 180_000,
  expect: { timeout: 30_000 },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  projects: IS_LIVE
    ? [
        {
          name: 'live-setup',
          testMatch: /auth\.setup\.ts/,
          use: {
            baseURL: UI_DEV_BASE,
            ...devices['Desktop Chrome'],
          },
        },
        {
          name: 'chromium-live',
          testMatch: /live-(journey|ui-crawl)\.spec\.ts/,
          dependencies: ['live-setup'],
          use: {
            baseURL: UI_DEV_BASE,
            storageState: AUTH_FILE,
            trace: 'on-first-retry',
            screenshot: 'only-on-failure',
            video: 'retain-on-failure',
            ...devices['Desktop Chrome'],
          },
        },
      ]
    : [
        {
          name: 'chromium-mock',
          testIgnore: /live-journey\.spec\.ts/,
          use: {
            baseURL: MOCK_BASE,
            trace: 'on-first-retry',
            screenshot: 'only-on-failure',
            video: 'retain-on-failure',
            ...devices['Desktop Chrome'],
            launchOptions,
          },
        },
      ],
  webServer: IS_LIVE
    ? undefined
    : {
        command: `npm run dev -- --port ${E2E_PORT} --strictPort`,
        url: `${MOCK_BASE}/command-center/operations`,
        reuseExistingServer: true,
        timeout: 120_000,
      },
})
