/**
 * Locale micro-chunk loader — English core at boot, full locales on demand.
 */
import i18n from 'i18next'

/** @type {Set<string>} */
const loaded = new Set()

const localeImporters = {
  en: () => import(/* webpackChunkName: "locale-en" */ './locales/en.json'),
  he: () => import(/* webpackChunkName: "locale-he" */ './locales/he.json'),
}

export async function loadLocale(lng) {
  const code = (lng || 'en').split('-')[0]
  if (loaded.has(code)) return
  const importer = localeImporters[code]
  if (!importer) return
  const mod = await importer()
  const bundle = mod.default || mod
  i18n.addResourceBundle(code, 'translation', bundle, true, true)
  loaded.add(code)
}

/** Boot-critical strings only — keeps first paint under tactical budget. */
export async function bootstrapLocales() {
  await loadLocale('en')
  const detected = (i18n.language || 'en').split('-')[0]
  if (detected !== 'en') {
    await loadLocale(detected)
  }
}

export function prefetchLocale(lng) {
  void loadLocale(lng)
}
