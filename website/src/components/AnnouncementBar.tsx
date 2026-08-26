import { useState } from 'react'
import { announcement } from '../content/site'
import { useI18n } from '../i18n'
import { A } from './A'

export function AnnouncementBar() {
  const { t } = useI18n()
  const key = `weissman_announce_${announcement.id}`
  const [open, setOpen] = useState(() => {
    try {
      return localStorage.getItem(key) !== '1'
    } catch {
      return true
    }
  })

  if (!open) return null

  return (
    <div className="border-b border-[var(--line)] bg-[#0c1218] text-sm text-muted">
      <div className="site-wrap flex min-h-11 items-center justify-between gap-4 py-2">
        <p className="m-0">
          <span className="me-2 font-semibold text-accent">{t('announcement.kicker')}</span>
          {t('announcement.text')}{' '}
          <A className="font-semibold text-ink underline-offset-2 hover:text-accent hover:underline" href={announcement.href}>
            {t('announcement.hrefLabel')}
          </A>
        </p>
        <button
          type="button"
          className="min-h-11 min-w-11 shrink-0 text-muted hover:text-ink"
          aria-label={t('a11y.dismissAnnouncement')}
          onClick={() => {
            try {
              localStorage.setItem(key, '1')
            } catch {
              /* ignore */
            }
            setOpen(false)
          }}
        >
          ×
        </button>
      </div>
    </div>
  )
}
