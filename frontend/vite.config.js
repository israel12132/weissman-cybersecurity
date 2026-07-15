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

const VENDOR_REACT = ['react', 'react-dom', 'react-router', 'react-router-dom', 'scheduler']
const VENDOR_I18N = ['i18next', 'react-i18next', 'i18next-browser-languagedetector']

function matchVendor(id, needles) {
  return needles.some((n) => id.includes(`/node_modules/${n}`))
}

function manualChunkForId(id) {
  if (!id.includes('node_modules')) {
    // Single shared chunk for React contexts — prevents duplicate createContext instances
    // when cockpit-shell and lazy route chunks both import the same provider module.
    if (id.includes('/src/context/') || id.includes('/src/providers/')) {
      return 'app-context'
    }
    if (id.includes('/engineC2/EngineManifestContext') || id.includes('/engineC2/EngineC2Boundary')) {
      return 'app-context'
    }
    if (id.includes('enginesRegistry.js')) return 'data-engines-registry'
    if (id.includes('engineParamDefs.generated')) return 'data-engine-params'
    if (id.includes('engineUiManifests.seed')) return 'data-ui-manifests'
    if (id.includes('/locales/en.json')) return 'locale-en'
    if (id.includes('/locales/he.json')) return 'locale-he'
    if (id.includes('AstTreeViewer')) return 'widget-ast-tree'
    if (id.includes('battlespace/')) return 'widget-battlespace'
    if (id.includes('/Cockpit.jsx')) return 'cockpit-shell'
    if (id.includes('/TacticalApp.jsx')) return 'tactical-app'
    if (id.includes('/routing/routeChunks') || id.includes('/routing/routePrefetchMap')) {
      return 'route-registry'
    }
    return undefined
  }

  if (matchVendor(id, VENDOR_REACT)) return 'vendor-react'
  if (matchVendor(id, VENDOR_I18N)) return 'vendor-i18n'
  if (id.includes('three')) return 'vendor-three'
  if (id.includes('recharts')) return 'vendor-recharts'
  if (id.includes('@xyflow')) return 'vendor-xyflow'
  if (id.includes('framer-motion')) return 'vendor-motion'
  if (id.includes('lucide-react')) return 'vendor-lucide'
  if (id.includes('@tanstack/react-table')) return 'vendor-table'
  if (id.includes('react-window')) return 'vendor-window'
  if (id.includes('react-simple-maps')) return 'vendor-maps'

  return undefined
}

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
        manualChunks(id) {
          return manualChunkForId(id)
        },
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
