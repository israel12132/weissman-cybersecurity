export const LOCALES = ['en', 'he'] as const
export type Locale = (typeof LOCALES)[number]

export const DEFAULT_LOCALE: Locale = 'en'
export const LOCALE_COOKIE = 'weissman_locale'
export const LOCALE_STORAGE_KEY = 'weissman_locale'

export const localeMeta: Record<Locale, { htmlLang: string; dir: 'ltr' | 'rtl'; ogLocale: string; bcp47: string }> =
  {
    en: { htmlLang: 'en', dir: 'ltr', ogLocale: 'en_US', bcp47: 'en-US' },
    he: { htmlLang: 'he', dir: 'rtl', ogLocale: 'he_IL', bcp47: 'he-IL' },
  }

/** Approved Hebrew legal URLs already in production (do not invent /he/terms.html). */
export const LEGAL_PAIRS: Record<string, Record<Locale, string>> = {
  '/terms.html': { en: '/terms.html', he: '/terms-he.html' },
  '/terms-he.html': { en: '/terms.html', he: '/terms-he.html' },
  '/privacy.html': { en: '/privacy.html', he: '/privacy-he.html' },
  '/privacy-he.html': { en: '/privacy.html', he: '/privacy-he.html' },
}

const PASS_PREFIXES = ['/command-center', '/api/', '/ws/', '/hooks/', '/install/', '/.well-known']
const PASS_EXACT = new Set(['/status', '/api/docs', '/api/docs/'])

export function isPassThroughHref(href: string): boolean {
  if (!href) return true
  if (
    href.startsWith('mailto:') ||
    href.startsWith('https://') ||
    href.startsWith('http://') ||
    href.startsWith('tel:') ||
    href.startsWith('#')
  ) {
    return true
  }
  if (!href.startsWith('/')) return true
  if (PASS_EXACT.has(href)) return true
  return PASS_PREFIXES.some((p) => href === p || href.startsWith(`${p}/`) || href.startsWith(p))
}

export function stripLocalePrefix(pathname: string): string {
  if (pathname === '/he' || pathname === '/he/') return '/'
  if (pathname.startsWith('/he/')) {
    const rest = pathname.slice(3)
    return rest.startsWith('/') ? rest : `/${rest}`
  }
  return pathname || '/'
}

export function localeFromPathname(pathname: string): Locale {
  const path = pathname.split('#')[0] || '/'
  if (path === '/he' || path === '/he/' || path.startsWith('/he/')) return 'he'
  if (path === '/terms-he.html' || path === '/privacy-he.html') return 'he'
  return 'en'
}

export function localeFromDocument(): Locale {
  if (typeof document === 'undefined') return DEFAULT_LOCALE
  const marked = document.documentElement.dataset.locale
  if (marked === 'he' || marked === 'en') return marked
  const lang = document.documentElement.lang
  if (lang === 'he') return 'he'
  return localeFromPathname(document.location.pathname)
}

export function localizeHref(href: string, locale: Locale): string {
  if (!href || isPassThroughHref(href)) return href
  const hashIndex = href.indexOf('#')
  const pathPart = hashIndex >= 0 ? href.slice(0, hashIndex) : href
  const hashPart = hashIndex >= 0 ? href.slice(hashIndex) : ''
  const path = pathPart || '/'
  const stripped = stripLocalePrefix(path)
  const pair = LEGAL_PAIRS[stripped] || LEGAL_PAIRS[path]
  if (pair) return pair[locale] + hashPart
  if (locale === 'en') return (stripped || '/') + hashPart
  if (stripped === '/') return `/he/${hashPart}`
  return `/he${stripped}${hashPart}`
}

export function alternatePath(currentPath: string, target: Locale): string {
  const [path, hash] = currentPath.split('#')
  const localized = localizeHref(stripLocalePrefix(path || '/') || '/', target)
  return hash ? `${localized.split('#')[0]}#${hash}` : localized
}

export function persistLocale(locale: Locale) {
  try {
    document.cookie = `${LOCALE_COOKIE}=${locale}; Path=/; Max-Age=31536000; SameSite=Lax`
    localStorage.setItem(LOCALE_STORAGE_KEY, locale)
  } catch {
    /* private mode */
  }
}

export function formatNumber(value: number, locale: Locale): string {
  return new Intl.NumberFormat(localeMeta[locale].bcp47).format(value)
}

export function formatDate(iso: string, locale: Locale): string {
  const d = new Date(`${iso}T00:00:00Z`)
  if (Number.isNaN(d.getTime())) return iso
  return new Intl.DateTimeFormat(localeMeta[locale].bcp47, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  }).format(d)
}
