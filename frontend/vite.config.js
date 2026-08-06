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

  // three.js is large and genuinely independent (no React namespace use).
  if (id.includes('/node_modules/three')) return 'vendor-three'

  // The React ecosystem is a tightly interconnected graph: @xyflow imports
  // recharts, recharts + framer-motion + lucide + react-window all import
  // react, etc. Splitting these into sibling chunks forces cross-chunk cycles
  // that break CJS init order at runtime ("Cannot access 'X' before
  // initialization" / "reading 'forwardRef' of undefined", leaving the SPA
  // unmounted). Co-locating the whole ecosystem in ONE chunk keeps every one of
  // those edges intra-chunk, where Rollup orders modules topologically and
  // initializes react before its consumers. (The prerequisite source fix —
  // lib/cn no longer sharing the `clsx` module with these libs — means no app
  // chunk is dragged into this vendor chunk.)
  if (
    /\/node_modules\/(react|react-dom|react-router|react-router-dom|scheduler|recharts|@xyflow|framer-motion|lucide-react|@tanstack\/react-table|react-window|i18next|react-i18next|i18next-browser-languagedetector)\//.test(
      id,
    )
  ) {
    return 'vendor-react'
  }

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
