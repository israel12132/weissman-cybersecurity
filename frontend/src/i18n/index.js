// i18n bootstrap: locales loaded as micro-chunks (see localeLoader.js).
// HTML <html dir> + <html lang> flip automatically on language switch.

import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'
import { prefetchLocale } from './localeLoader';

export const SUPPORTED_LANGUAGES = [
  { code: 'en', label: 'English', dir: 'ltr', flag: '🇺🇸' },
  { code: 'he', label: 'עברית', dir: 'rtl', flag: '🇮🇱' },
]

const RTL_LANGS = new Set(SUPPORTED_LANGUAGES.filter((l) => l.dir === 'rtl').map((l) => l.code))

function applyDir(lng) {
  if (typeof document === 'undefined') return
  const dir = RTL_LANGS.has(lng) ? 'rtl' : 'ltr'
  document.documentElement.setAttribute('dir', dir)
  document.documentElement.setAttribute('lang', lng)
  document.body?.classList.toggle('weissman-rtl', dir === 'rtl')
}

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {},
    fallbackLng: 'en',
    supportedLngs: SUPPORTED_LANGUAGES.map((l) => l.code),
    nonExplicitSupportedLngs: true,
    interpolation: { escapeValue: false },
    detection: {
      order: ['localStorage', 'navigator', 'htmlTag'],
      caches: ['localStorage'],
      lookupLocalStorage: 'weissman_lang',
    },
    returnNull: false,
  })

i18n.on('languageChanged', (lng) => {
  applyDir(lng)
  const code = (lng || 'en').split('-')[0]
  if (code !== 'en') prefetchLocale(code)
})

i18n.on('languageChanged', applyDir)
applyDir(i18n.language || 'en')

export default i18n
