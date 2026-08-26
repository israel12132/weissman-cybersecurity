import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { ORIGIN, pages } from './pages.mjs'
import { en } from '../src/i18n/messages/en.ts'
import { he } from '../src/i18n/messages/he.ts'
import { localeMeta, localizeHref, type Locale } from '../src/i18n/locale.ts'

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
const nativeHeIds = new Set(['terms-he', 'privacy-he'])
const catalogs = { en, he }

type Page = (typeof pages)[number]

function seoFor(id: string, locale: Locale): { title: string; description: string } {
  const block = (catalogs[locale].seo as Record<string, { title: string; description: string }>)[id]
  const fallback = (en.seo as Record<string, { title: string; description: string }>)[id]
  return block || fallback || { title: 'Weissman Cybersecurity', description: '' }
}

function heFile(file: string): string {
  if (file === 'index.html') return 'he/index.html'
  return `he/${file}`
}

function hePath(path: string): string {
  return localizeHref(path, 'he')
}

function legalBody(id: string) {
  const p = join(root, 'src/content/legal', `${id}.html`)
  if (!existsSync(p)) return ''
  return `<article class="legal-doc">${readFileSync(p, 'utf8')}</article>`
}

function escapeHtml(s: string) {
  return s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;')
}

function jsonLd(locale: Locale) {
  const meta = localeMeta[locale]
  const home = locale === 'he' ? `${ORIGIN}/he/` : `${ORIGIN}/`
  const org = {
    '@context': 'https://schema.org',
    '@type': 'Organization',
    name: 'Weissman Cybersecurity Ltd.',
    url: home,
    email: 'sales@weissman.io',
    inLanguage: meta.htmlLang,
    address: {
      '@type': 'PostalAddress',
      addressLocality: locale === 'he' ? 'תל אביב-יפו' : 'Tel Aviv-Yafo',
      addressCountry: 'IL',
    },
  }
  const app = {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: catalogs[locale].brand.product,
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Web, Linux, macOS, Windows',
    url: home,
    inLanguage: meta.htmlLang,
    offers: { '@type': 'Offer', price: '499', priceCurrency: 'USD' },
    description: catalogs[locale].brand.jsonLdDescription,
  }
  return `<script id="weissman-ld-0" type="application/ld+json">${JSON.stringify(org)}</script>
  <script id="weissman-ld-1" type="application/ld+json">${JSON.stringify(app)}</script>`
}

function shell(page: Page, locale: Locale, urlPath: string) {
  const meta = localeMeta[locale]
  const seo = seoFor(page.id, locale)
  const robots = page.robots || 'index,follow'
  const canonical = `${ORIGIN}${urlPath}`
  const enUrl = `${ORIGIN}${localizeHref(page.path, 'en')}`
  const heUrl = `${ORIGIN}${localizeHref(page.path, 'he')}`
  const ogImage = `${ORIGIN}/og-cover.svg`
  const boot = locale === 'en' && urlPath === '/' ? '\n  <script src="/js/locale-boot.js"></script>' : ''
  return `<!DOCTYPE html>
<html lang="${meta.htmlLang}" dir="${meta.dir}" data-page="${page.id}" data-locale="${locale}">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <meta name="theme-color" content="#07090c" />
  <title>${escapeHtml(seo.title)}</title>
  <meta name="description" content="${escapeHtml(seo.description)}" />
  <meta name="robots" content="${robots}" />
  <link rel="canonical" href="${canonical}" />
  <link rel="alternate" hreflang="en" href="${enUrl}" />
  <link rel="alternate" hreflang="he" href="${heUrl}" />
  <link rel="alternate" hreflang="x-default" href="${enUrl}" />
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <meta property="og:type" content="website" />
  <meta property="og:site_name" content="Weissman Cybersecurity" />
  <meta property="og:locale" content="${meta.ogLocale}" />
  <meta property="og:locale:alternate" content="${locale === 'en' ? 'he_IL' : 'en_US'}" />
  <meta property="og:title" content="${escapeHtml(seo.title)}" />
  <meta property="og:description" content="${escapeHtml(seo.description)}" />
  <meta property="og:image" content="${ogImage}" />
  <meta property="og:url" content="${canonical}" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="${escapeHtml(seo.title)}" />
  <meta name="twitter:description" content="${escapeHtml(seo.description)}" />
  ${jsonLd(locale)}${boot}
  <link rel="stylesheet" href="/src/styles/index.css" />
</head>
<body>
  <div id="root">${legalIds.has(page.id) ? legalBody(page.id) : ''}</div>
  <script type="module" src="/src/main.tsx"></script>
</body>
</html>
`
}

type Written = { id: string; path: string; file: string; locale: Locale }

const written: Written[] = []

for (const page of pages) {
  const nativeHe = nativeHeIds.has(page.id)
  const locale: Locale = nativeHe || page.lang === 'he' ? 'he' : 'en'
  mkdirSync(dirname(join(root, page.file)), { recursive: true })
  writeFileSync(join(root, page.file), shell(page, locale, page.path))
  written.push({ id: page.id, path: page.path, file: page.file, locale })
}

for (const page of pages) {
  if (nativeHeIds.has(page.id)) continue
  if (page.id === 'terms' || page.id === 'privacy') continue
  const file = heFile(page.file)
  const path = hePath(page.path)
  mkdirSync(dirname(join(root, file)), { recursive: true })
  writeFileSync(join(root, file), shell(page, 'he', path))
  written.push({ id: page.id, path, file, locale: 'he' })
}

function xhtmlLinks(path: string) {
  const enUrl = `${ORIGIN}${localizeHref(path, 'en')}`
  const heUrl = `${ORIGIN}${localizeHref(path, 'he')}`
  return `    <xhtml:link rel="alternate" hreflang="en" href="${enUrl}"/>
    <xhtml:link rel="alternate" hreflang="he" href="${heUrl}"/>
    <xhtml:link rel="alternate" hreflang="x-default" href="${enUrl}"/>`
}

const sitemapUrls = written
  .filter((p) => p.id !== 'not-found')
  .map((p) => {
    const legal = /terms|privacy|dpa|subprocessors|security-policy/.test(p.file)
    const freq = p.path === '/' || p.path === '/he/' ? 'weekly' : legal ? 'yearly' : 'monthly'
    const pri = p.path === '/' ? '1.0' : p.path === '/he/' ? '0.9' : p.path.includes('/platform') ? '0.9' : '0.7'
    return `  <url>
    <loc>${ORIGIN}${p.path}</loc>
    <changefreq>${freq}</changefreq>
    <priority>${pri}</priority>
${xhtmlLinks(p.path)}
  </url>`
  })
  .join('\n')

writeFileSync(
  join(root, 'public/sitemap.xml'),
  `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">
${sitemapUrls}
</urlset>
`,
)

const allowPaths = [...new Set(written.filter((p) => p.id !== 'not-found').map((p) => p.path))]
writeFileSync(
  join(root, 'public/robots.txt'),
  `User-agent: *
${allowPaths.map((p) => `Allow: ${p}`).join('\n')}
Allow: /he/
Disallow: /command-center/
Disallow: /api/
Disallow: /ws/
Disallow: /hooks/
Disallow: /install/

Sitemap: ${ORIGIN}/sitemap.xml
`,
)

console.log(`wrote ${written.length} HTML entries`)
