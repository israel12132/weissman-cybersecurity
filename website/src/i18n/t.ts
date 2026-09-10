import { en } from './messages/en'
import { he } from './messages/he'
import type { Locale } from './locale'

export type Messages = typeof en
export type MessageCatalog = Messages

const catalogs: Record<Locale, Messages> = {
  en,
  he: he as unknown as Messages,
}

function lookup(source: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc == null || typeof acc !== 'object') return undefined
    return (acc as Record<string, unknown>)[key]
  }, source)
}

export function interpolate(template: string, vars?: Record<string, string | number>): string {
  if (!vars) return template
  return template.replace(/\{(\w+)\}/g, (_, key: string) =>
    vars[key] === undefined || vars[key] === null ? `{${key}}` : String(vars[key]),
  )
}

export type Translate = (path: string, vars?: Record<string, string | number>) => string

export function translate(locale: Locale, path: string, vars?: Record<string, string | number>): string {
  const hit = lookup(catalogs[locale], path)
  const fallback = lookup(en, path)
  const raw = typeof hit === 'string' ? hit : typeof fallback === 'string' ? fallback : path
  if (typeof hit !== 'string' && typeof fallback === 'string' && locale !== 'en') {
    if (import.meta.env?.DEV) {
      console.warn(`[i18n] missing ${locale} key: ${path}`)
    }
  }
  return interpolate(raw, vars)
}

export function makeT(locale: Locale): Translate {
  return (path, vars) => translate(locale, path, vars)
}

export function listMessageKeys(node: unknown, prefix = ''): string[] {
  if (typeof node === 'string') return prefix ? [prefix] : []
  if (Array.isArray(node)) {
    return node.flatMap((item, i) => listMessageKeys(item, prefix ? `${prefix}.${i}` : String(i)))
  }
  if (node && typeof node === 'object') {
    return Object.entries(node as Record<string, unknown>).flatMap(([k, v]) =>
      listMessageKeys(v, prefix ? `${prefix}.${k}` : k),
    )
  }
  return []
}

export { catalogs }
