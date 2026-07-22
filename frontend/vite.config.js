import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import forensicRouteCompliancePlugin from './plugins/vite-forensic-route-compliance.mjs'
import cspPlugin from './plugins/vite-csp.mjs'

const CONFIG_DIR = path.dirname(fileURLToPath(import.meta.url))

// Dev-only: the marketing/legal pages (signup/terms/privacy) are served from
// deploy/public by the backend in production. Serve them under `vite dev` too, so
// the Login footer links don't 404 in local / SPA-only development.
function serveDeployPublicHtml() {
  return {
    name: 'serve-deploy-public-html',
    apply: 'serve',
    configureServer(server) {
      const dir = path.resolve(CONFIG_DIR, '../deploy/public')
      server.middlewares.use((req, res, next) => {
        const m = req.url && req.url.match(/^\/([\w-]+\.html)(?:\?.*)?$/)
        if (m) {
          const fp = path.join(dir, m[1])
          if (fp.startsWith(dir) && fs.existsSync(fp)) {
            res.setHeader('Content-Type', 'text/html; charset=utf-8')
            res.end(fs.readFileSync(fp))
            return
          }
        }
        next()
      })
    },
  }
}

// NOTE ON CHUNKING (do not reintroduce a hand-rolled `manualChunks` without live-browser
// verification): a previous manual vendor/widget split forced React-consuming modules into their own
// chunks (vendor-lucide, widget-ast-tree, …). Those chunks execute their MODULE-TOP-LEVEL
// `React.forwardRef(...)` calls before the separate `vendor-react` chunk has initialised React's
// namespace, so the browser throws "Cannot read properties of undefined (reading 'forwardRef')" and
// the whole SPA fails to mount — a blank page where the login #email never renders. The Vite dev
// server does not chunk, so mock UI tests never saw it; it only surfaced in the built bundle under
// the live E2E. Rollup's default chunking evaluates modules in dependency order (React first) and
// still emits a separate chunk per dynamic import() — the i18n locale micro-chunks and every lazy
// route stay split, and shared modules are still deduplicated — so we simply let it decide.

export default defineConfig({
  base: '/command-center/',
  plugins: [serveDeployPublicHtml(), forensicRouteCompliancePlugin(), react(), cspPlugin()],
  worker: { format: 'es' },
  build: {
    target: 'es2020',
    // Strip console/debugger from production bundles: prevents leaking raw error objects
    // (response bodies, integration detail) into the browser console. Dev server is unaffected.
    esbuild: { drop: ['console', 'debugger'] },
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: {
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
    chunkSizeWarningLimit: 500,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        cookieDomainRewrite: '',
        cookiePathRewrite: '/',
      },
      '/ws': { target: 'ws://127.0.0.1:8000', ws: true, changeOrigin: true },
    },
  },
  preview: {
    port: 4173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        cookieDomainRewrite: '',
        cookiePathRewrite: '/',
      },
      '/ws': { target: 'ws://127.0.0.1:8000', ws: true, changeOrigin: true },
    },
  },
})
