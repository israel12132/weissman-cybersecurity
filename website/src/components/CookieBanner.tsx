import { useState } from 'react'
import { useI18n } from '../i18n'
import { A } from './A'
import { Button } from './Button'

const KEY = 'weissman_cookie_consent_v1'

export function CookieBanner() {
  const { t } = useI18n()
  const [open, setOpen] = useState(() => {
    try {
      return !localStorage.getItem(KEY)
    } catch {
      return true
    }
  })

  if (!open) return null

  const privacy = (
    <A className="text-accent underline" href="/privacy.html">
      {t('cookie.privacy')}
    </A>
  )

  return (
    <div
      id="cookie-banner"
      role="dialog"
      aria-label={t('a11y.cookie')}
      className="fixed bottom-4 inset-inline-4 z-[70] mx-auto flex max-w-3xl flex-wrap items-center justify-between gap-3 rounded-[14px] border border-accent/30 bg-[#0b1120] px-4 py-3 text-sm text-muted shadow-[var(--shadow)]"
    >
      <p className="m-0 min-w-[220px] flex-1">
        {t('cookie.body').split('{privacy}')[0]}
        {privacy}
        {t('cookie.body').split('{privacy}')[1]}
      </p>
      <Button
        type="button"
        onClick={() => {
          try {
            localStorage.setItem(KEY, '1')
          } catch {
            /* ignore quota */
          }
          setOpen(false)
        }}
      >
        {t('cookie.accept')}
      </Button>
    </div>
  )
}
