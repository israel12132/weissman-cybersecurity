import { defineConfig, devices } from '@playwright/test'

/**
 * Command Center E2E — Vite dev server + API mocks (no Rust backend required).
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
    // Use localhost (not 127.0.0.1): Vite binds in a way that rejects 127.0.0.1 on some Linux setups.
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    ...devices['Desktop Chrome'],
  },
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:5173/command-center/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
  projects: [{ name: 'chromium', use: {} }],
})
