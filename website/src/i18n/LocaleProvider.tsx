import { createContext, useContext, useEffect, useMemo, type ReactNode } from 'react'
import {
  formatDate,
  formatNumber,
  localeFromDocument,
  localeMeta,
  localizeHref,
  persistLocale,
  type Locale,
} from './locale'
import { makeT, type Translate } from './t'

export type I18nContextValue = {
  locale: Locale
  dir: 'ltr' | 'rtl'
  t: Translate
  href: (path: string) => string
  n: (value: number) => string
  date: (iso: string) => string
}

const I18nContext = createContext<I18nContextValue | null>(null)

export function LocaleProvider({ children }: { children: ReactNode }) {
  const value = useMemo<I18nContextValue>(() => {
    const locale = localeFromDocument()
    const t = makeT(locale)
    return {
      locale,
      dir: localeMeta[locale].dir,
      t,
      href: (path: string) => localizeHref(path, locale),
      n: (value: number) => formatNumber(value, locale),
      date: (iso: string) => formatDate(iso, locale),
    }
  }, [])

  useEffect(() => {
    persistLocale(value.locale)
  }, [value.locale])

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext)
  if (!ctx) throw new Error('useI18n must be used within LocaleProvider')
  return ctx
}
