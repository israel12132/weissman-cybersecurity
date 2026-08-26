import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { ORIGIN, pages } from './pages.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const legalIds = new Set([
  'terms',
  'privacy',
  'terms-he',
  'privacy-he',
  'dpa',
  'subprocessors',
  'security-policy',
])

function legalBody(id) {
  const p = join(root, 'src/content/legal', `${id}.html`)
  if (!existsSync(p)) return ''
  return `<article class="legal-doc">${readFileSync(p, 'utf8')}</article>`
}

function shell(page) {
  const lang = page.lang || 'en'
  const dir = page.dir || 'ltr'
  const robots = page.robots || 'index,follow'
  const canonical = `${ORIGIN}${page.path}`
  const ogImage = `${ORIGIN}/og-cover.svg`
  return `<!DOCTYPE html>
<html lang="${lang}" dir="${dir}" data-page="${page.id}">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <meta name="theme-color" content="#07090c" />
  <title>${escapeHtml(page.title)}</title>
  <meta name="description" content="${escapeHtml(page.description)}" />
  <meta name="robots" content="${robots}" />
  <link rel="canonical" href="${canonical}" />
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <meta property="og:type" content="website" />
  <meta property="og:site_name" content="Weissman Cybersecurity" />
  <meta property="og:title" content="${escapeHtml(page.title)}" />
  <meta property="og:description" content="${escapeHtml(page.description)}" />
  <meta property="og:image" content="${ogImage}" />
  <meta property="og:url" content="${canonical}" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="${escapeHtml(page.title)}" />
  <meta name="twitter:description" content="${escapeHtml(page.description)}" />
  <link rel="stylesheet" href="/src/styles/index.css" />
</head>
<body>
  <div id="root">${legalIds.has(page.id) ? legalBody(page.id) : ''}</div>
  <script type="module" src="/src/main.tsx"></script>
</body>
</html>
`
}

function escapeHtml(s) {
  return s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

for (const page of pages) {
  const dest = join(root, page.file)
  mkdirSync(dirname(dest), { recursive: true })
  writeFileSync(dest, shell(page))
}

const sitemapUrls = pages
  .filter((p) => p.id !== 'not-found')
  .map((p) => {
    const loc = `${ORIGIN}${p.path}`
    const legal = /^(terms|privacy|dpa|subprocessors|security-policy)/.test(p.file)
    const freq = p.path === '/' ? 'weekly' : legal ? 'yearly' : 'monthly'
    const pri = p.path === '/' ? '1.0' : p.path.startsWith('/platform') ? '0.9' : '0.7'
    return `  <url><loc>${loc}</loc><changefreq>${freq}</changefreq><priority>${pri}</priority></url>`
  })
  .join('\n')

writeFileSync(
  join(root, 'public/sitemap.xml'),
  `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${sitemapUrls}
</urlset>
`,
)

const allow = pages
  .filter((p) => p.id !== 'not-found')
  .map((p) => `Allow: ${p.path}`)
  .join('\n')

writeFileSync(
  join(root, 'public/robots.txt'),
  `User-agent: *
${allow}
Disallow: /command-center/
Disallow: /api/
Disallow: /ws/
Disallow: /hooks/
Disallow: /install/

Sitemap: ${ORIGIN}/sitemap.xml
`,
)

console.log(`wrote ${pages.length} HTML entries`)
