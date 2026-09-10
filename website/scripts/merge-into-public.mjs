/**
 * Copy the Vite marketing build into deploy/public without wiping legal extras
 * that are not part of the bundle (.well-known, leftover helper scripts).
 */
import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const dist = join(root, 'dist')
const dest = join(root, '..', 'deploy', 'public')

if (!existsSync(dist)) {
  throw new Error('website/dist missing — run vite build first')
}

mkdirSync(dest, { recursive: true })

const replaceable = [
  'index.html',
  '404.html',
  'pricing.html',
  'signup.html',
  'terms.html',
  'privacy.html',
  'terms-he.html',
  'privacy-he.html',
  'dpa.html',
  'subprocessors.html',
  'security-policy.html',
  'sitemap.xml',
  'robots.txt',
  'favicon.svg',
  'og-cover.svg',
  '_shared.css',
  'assets',
  'platform',
  'solutions',
  'technology',
  'resources',
  'about',
  'contact',
  'fonts',
  'he',
  'js',
]

for (const name of replaceable) {
  const from = join(dist, name)
  const to = join(dest, name)
  if (!existsSync(from)) continue
  rmSync(to, { recursive: true, force: true })
  cpSync(from, to, { recursive: true })
}

const obsolete = ['js/signup.js', 'js/cookie-banner.js', 'js/year.js']
for (const name of obsolete) {
  rmSync(join(dest, name), { force: true })
}

writeFileSync(join(dest, '.built-from-website'), `${new Date().toISOString()}\n`)
console.log(`merged website/dist → deploy/public`)
