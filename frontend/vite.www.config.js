import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import cspPlugin from './plugins/vite-csp.mjs'

const CONFIG_DIR = path.dirname(fileURLToPath(import.meta.url))

/** Copy Command Center self-hosted fonts into dist-www so `/fonts/` works without the CC tree. */
function copyFlagshipFonts() {
  return {
    name: 'copy-flagship-fonts',
    apply: 'build',
    closeBundle() {
      const src = path.resolve(CONFIG_DIR, 'public/fonts')
      const dest = path.resolve(CONFIG_DIR, 'dist-www/fonts')
      if (!fs.existsSync(src)) return
      fs.mkdirSync(dest, { recursive: true })
      fs.cpSync(src, dest, { recursive: true })
    },
  }
}

/** Dev-only: fonts + legal HTML live next to Command Center / deploy/public in production. */
function serveFlagshipStatics() {
  const fontsDir = path.resolve(CONFIG_DIR, 'public/fonts')
  const legalDir = path.resolve(CONFIG_DIR, '../deploy/public')
  const favicon = path.resolve(CONFIG_DIR, 'public/favicon.svg')
  return {
    name: 'serve-flagship-statics',
    apply: 'serve',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url?.split('?')[0] || ''
        if (url === '/' || url === '/index.html') {
          const fp = path.join(legalDir, 'index.html')
          if (fp.startsWith(legalDir) && fs.existsSync(fp)) {
            res.setHeader('Content-Type', 'text/html; charset=utf-8')
            res.end(fs.readFileSync(fp))
            return
          }
        }
        if (url === '/favicon.svg' && fs.existsSync(favicon)) {
          res.setHeader('Content-Type', 'image/svg+xml')
          res.end(fs.readFileSync(favicon))
          return
        }
        if (url === '/og-cover.svg') {
          const fp = path.join(legalDir, 'og-cover.svg')
          if (fs.existsSync(fp)) {
            res.setHeader('Content-Type', 'image/svg+xml')
            res.end(fs.readFileSync(fp))
            return
          }
        }
        if (url.startsWith('/fonts/')) {
          const rel = url.slice('/fonts/'.length)
          const fp = path.join(fontsDir, rel)
          if (fp.startsWith(fontsDir) && fs.existsSync(fp) && fs.statSync(fp).isFile()) {
            const ext = path.extname(fp)
            const types = {
              '.css': 'text/css; charset=utf-8',
              '.woff2': 'font/woff2',
              '.woff': 'font/woff',
            }
            res.setHeader('Content-Type', types[ext] || 'application/octet-stream')
            res.end(fs.readFileSync(fp))
            return
          }
        }
        const legal = url.match(/^\/([\w.-]+\.html)$/)
        if (legal) {
          const fp = path.join(legalDir, legal[1])
          if (fp.startsWith(legalDir) && fs.existsSync(fp)) {
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

export default defineConfig({
  root: path.resolve(CONFIG_DIR, 'www'),
  base: '/',
  publicDir: path.resolve(CONFIG_DIR, 'www/public'),
  plugins: [serveFlagshipStatics(), copyFlagshipFonts(), react(), cspPlugin()],
  resolve: {
    alias: {
      '@cc': path.resolve(CONFIG_DIR, 'src'),
    },
  },
  css: {
    postcss: CONFIG_DIR,
  },
  build: {
    outDir: path.resolve(CONFIG_DIR, 'dist-www'),
    emptyOutDir: true,
    target: 'es2020',
    esbuild: { drop: ['console', 'debugger'] },
    modulePreload: { polyfill: false },
  },
  server: {
    port: 5174,
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
    port: 4174,
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
