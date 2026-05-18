import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// base: '/command-center/' must match Rust static nest at /command-center (ServeDir).
// Production: run `npm run build` (or ../deploy/build-frontend.sh); Rust serves frontend/dist — no Vite in prod.
// The production bundle is traced only from index.html → src/**. Playwright-only mocks live under tests-e2e/ and must never be imported from src/.
export default defineConfig({
  base: '/command-center/',
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            const normalizedId = id.replace(/\\/g, '/')
            if (/(?:^|\/)node_modules\/framer-motion\//.test(normalizedId)) return 'vendor-motion'
            if (/(?:^|\/)node_modules\/recharts\//.test(normalizedId)) return 'vendor-recharts'
            if (/(?:^|\/)node_modules\/three\//.test(normalizedId)) return 'vendor-three'
            if (/(?:^|\/)node_modules\/@xyflow\//.test(normalizedId)) return 'vendor-xyflow'
            if (/(?:^|\/)node_modules\/lucide-react\//.test(normalizedId)) return 'vendor-lucide'
            if (/(?:^|\/)node_modules\/@tanstack\//.test(normalizedId)) return 'vendor-table'
            return 'vendor-core'
          }

          if (id.includes('/src/pages/')) {
            const file = id.split('/').pop()?.replace(/\.(jsx?|tsx?)$/, '') || 'page'
            return `page-${file.toLowerCase()}`
          }
        },
      },
    },
    chunkSizeWarningLimit: 600,
  },
  server: {
    port: 5173,
    // Dev-only: API lives on the Rust process. Do not use for production access.
    proxy: {
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
  preview: {
    port: 4173,
    // Optional: test production build locally with `npm run build && npm run preview`
    proxy: {
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
})
