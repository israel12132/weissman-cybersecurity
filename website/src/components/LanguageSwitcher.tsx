import { useId } from 'react'
import { alternatePath, persistLocale, type Locale } from '../i18n/locale'
import { useI18n } from '../i18n'
import { track } from '../lib/analytics'

function Globe({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" width="16" height="16" aria-hidden fill="none">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.6" />
      <path d="M3 12h18M12 3c2.5 2.8 3.8 5.8 3.8 9S14.5 18.2 12 21c-2.5-2.8-3.8-5.8-3.8-9S9.5 5.8 12 3Z" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  )
}

export function LanguageSwitcher({ variant = 'bar' }: { variant?: 'bar' | 'drawer' }) {
  const { locale, t } = useI18n()
  const labelId = useId()
  const path = typeof window !== 'undefined' ? window.location.pathname + window.location.hash : '/'

  function go(next: Locale) {
    persistLocale(next)
    track('language_change', { from: locale, to: next })
  }

  const enHref = alternatePath(path, 'en')
  const heHref = alternatePath(path, 'he')
  const compact = variant === 'bar'

  return (
    <div
      className={
        compact
          ? 'inline-flex items-center gap-0.5 rounded-[12px] border border-[var(--line)] px-1.5 py-1 sm:gap-1 sm:px-2'
          : 'flex items-center justify-between gap-3 rounded-[12px] border border-[var(--line)] px-3 py-3'
      }
      role="navigation"
      aria-labelledby={labelId}
    >
      <span id={labelId} className="sr-only">
        {t('a11y.language')}
      </span>
      <span className="text-dim" aria-hidden>
        <Globe />
      </span>
      <a
        href={enHref}
        lang="en"
        hrefLang="en"
        onClick={() => go('en')}
        aria-current={locale === 'en' ? 'true' : undefined}
        aria-label={t('a11y.languageEn')}
        className={`inline-flex min-h-11 min-w-9 items-center justify-center rounded-[10px] px-1.5 text-xs font-semibold tracking-[0.08em] transition duration-swift sm:min-w-11 sm:px-2 ${
          locale === 'en' ? 'bg-white/10 text-accent' : 'text-muted hover:text-ink'
        }`}
      >
        {t('lang.enShort')}
      </a>
      <span className="text-dim" aria-hidden>
        /
      </span>
      <a
        href={heHref}
        lang="he"
        hrefLang="he"
        onClick={() => go('he')}
        aria-current={locale === 'he' ? 'true' : undefined}
        aria-label={t('a11y.languageHe')}
        className={`min-h-11 inline-flex items-center justify-center rounded-[10px] px-2 text-sm font-semibold transition duration-swift ${
          locale === 'he' ? 'bg-white/10 text-accent' : 'text-muted hover:text-ink'
        }`}
      >
        {t('lang.heShort')}
      </a>
    </div>
  )
}
