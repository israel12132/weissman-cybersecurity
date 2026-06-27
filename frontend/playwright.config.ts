import { defineConfig, devices } from '@playwright/test'

const E2E_PORT = process.env.PLAYWRIGHT_PORT || '5199'
const E2E_BASE = `http://localhost:${E2E_PORT}`

/**
 * Command Center E2E — UI smoke only (Vite dev server + API mocks).
 * NOT a live-stack contract: real API/browser E2E runs in CI via
 * scripts/audit_ui_button_scan_paths.mjs against weissman-server.
 * Mocks live under tests-e2e/ only; they are never imported by the production SPA bundle.
 */
export default defineConfig({
  testDir: './tests-e2e',
  timeout: 120_000,
  expect: { timeout: 20_000 },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: E2E_BASE,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    ...devices['Desktop Chrome'],
  },
  webServer: {
    command: `npm run dev -- --port ${E2E_PORT} --strictPort`,
    url: `${E2E_BASE}/command-center/operations`,
    reuseExistingServer: true,
    timeout: 120_000,
  },
  projects: [{ name: 'chromium', use: {} }],
})
