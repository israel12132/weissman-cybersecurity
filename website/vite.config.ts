import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readdirSync, statSync } from 'node:fs'

const root = dirname(fileURLToPath(import.meta.url))

function collectHtml(dir: string, acc: Record<string, string> = {}): Record<string, string> {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'dist' || name === 'src') continue
    const full = resolve(dir, name)
    const st = statSync(full)
    if (st.isDirectory()) collectHtml(full, acc)
    else if (name.endsWith('.html')) {
      const rel = full.slice(root.length + 1).replace(/\\/g, '/')
      const key = rel.replace(/\.html$/, '').replace(/\/index$/, '') || 'home'
      acc[key] = full
    }
  }
  return acc
}

export default defineConfig({
  plugins: [react()],
  appType: 'mpa',
  resolve: {
    alias: { '@': resolve(root, 'src') },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    modulePreload: { polyfill: false },
    rollupOptions: {
      input: collectHtml(root),
    },
  },
})
