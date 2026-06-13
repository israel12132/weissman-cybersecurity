import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// Unit/component tests (jsdom). Playwright e2e specs live in tests-e2e/ and are run
// separately via `npm run test:e2e`, so they're excluded here.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: false,
    setupFiles: ['./src/test/setup.js'],
    include: ['src/**/*.{test,spec}.{js,jsx}'],
    exclude: ['node_modules', 'dist', 'tests-e2e'],
    css: false,
  },
})
