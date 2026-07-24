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

  // Wall-clock ceiling for the ENTIRE run. `timeout` above bounds ONE test and can never bound
  // the suite: the live selection is 110 serial tests (100 appNav routes + 6 named + 3 journey),
  // so the worst case was 110 x 90s x 2 retries = 5.5 h. CI step 36 was measured running
  // 150 min before the job died with NO report, because nothing inside Playwright ever stopped
  // it. globalTimeout makes Playwright self-terminate, flush both reporters and exit non-zero,
  // naming the test that was in flight. Sized generously on purpose so the gate cannot go
  // permanently red before the cost-model work (worker-scoped context) lands; tighten once the
  // crawl reuses its browser context. See docs/TECH_DEBT_live_e2e_runtime.md.
  globalTimeout: process.env.CI ? 50 * 60 * 1000 : 0,

  // A systemically broken live stack must abort in ~2 min, not grind 110 tests x 90s and then
  // retry every one of them. Local runs stay unbounded so a dev sees every failure at once.
  maxFailures: process.env.CI ? 10 : 0,

  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,

  // `list` prints nothing at test START on a non-TTY stream, so a killed CI run left no clue
  // which test was running. `github` adds ::error:: annotations with file/line; the CI step sets
  // PLAYWRIGHT_FORCE_TTY=1 so `list` also prints on test begin.
  reporter: process.env.CI
    ? [['list'], ['github'], ['html', { open: 'never' }]]
    : [['list'], ['html', { open: 'never' }]],
  projects: IS_LIVE
    ? [
        {
          name: 'live-setup',
          testMatch: /auth\.setup\.ts/,
          use: {
            baseURL: UI_DEV_BASE,
            ...devices['Desktop Chrome'],
            launchOptions,
          },
        },
        {
          name: 'chromium-live',
          testMatch: /live-(journey|ui-crawl|feature)\.spec\.ts/,
          dependencies: ['live-setup'],
          use: {
            baseURL: UI_DEV_BASE,
            storageState: AUTH_FILE,
            // Left unset these collapse to 0 (= no limit) rather than Playwright's 30s default,
            // so a stalled navigation absorbed the whole 90s test budget and surfaced as a
            // generic "Test timeout of 90000ms exceeded" instead of a pinpointed
            // "goto exceeded 30000ms" naming the route.
            actionTimeout: 15_000,
            navigationTimeout: 30_000,
            trace: 'on-first-retry',
            screenshot: 'only-on-failure',
            video: 'retain-on-failure',
            ...devices['Desktop Chrome'],
            launchOptions,
          },
        },
      ]
    : [
        {
          name: 'chromium-mock',
          testIgnore: /live-(journey|feature)\.spec\.ts/,
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
