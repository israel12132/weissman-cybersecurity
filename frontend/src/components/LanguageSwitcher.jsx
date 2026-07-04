import React from 'react'
import { useTranslation } from 'react-i18next'
import { SUPPORTED_LANGUAGES } from '../i18n'
import { loadLocale } from '../i18n/localeLoader'

/**
 * Compact language picker — segmented button (EN / עברית). Drop into any header. Persists to
 * localStorage automatically via i18next-browser-languagedetector.
 */
export default function LanguageSwitcher({ className = '' }) {
  const { t, i18n } = useTranslation()
  const current = (i18n.resolvedLanguage || i18n.language || 'en').slice(0, 2)

  return (
    <div
      className={`inline-flex items-center gap-1 rounded-lg border border-white/10 bg-black/30 p-1 ${className}`}
      role="group"
      aria-label={t('common.language')}
    >
      {SUPPORTED_LANGUAGES.map((lang) => {
        const active = current === lang.code
        return (
          <button
            key={lang.code}
            type="button"
            onClick={async () => {
              await loadLocale(lang.code)
              await i18n.changeLanguage(lang.code)
            }}
            className={`px-2 py-1 rounded-md text-[11px] font-mono transition-colors ${
              active
                ? 'bg-cyan-500/20 text-cyan-200 border border-cyan-500/40'
                : 'text-white/55 hover:text-white/85 border border-transparent'
            }`}
            aria-pressed={active}
            title={lang.label}
          >
            <span className="mr-1">{lang.flag}</span>
            {lang.label}
          </button>
        )
      })}
    </div>
  )
}
