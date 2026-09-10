import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'
import en from './locales/en.json'
import he from './locales/he.json'

const RTL = new Set(['he'])

export function applyDir(lng) {
  if (typeof document === 'undefined') return
  const code = (lng || 'en').slice(0, 2)
  const dir = RTL.has(code) ? 'rtl' : 'ltr'
  document.documentElement.setAttribute('dir', dir)
  document.documentElement.setAttribute('lang', code)
}

i18n.use(LanguageDetector).use(initReactI18next).init({
  resources: { en: { translation: en }, he: { translation: he } },
  fallbackLng: 'en',
  supportedLngs: ['en', 'he'],
  interpolation: { escapeValue: false },
  detection: {
    order: ['localStorage', 'navigator', 'htmlTag'],
    caches: ['localStorage'],
    lookupLocalStorage: 'weissman_lang',
  },
  react: { useSuspense: false },
})

i18n.on('languageChanged', applyDir)
applyDir(i18n.language || 'en')

export default i18n
