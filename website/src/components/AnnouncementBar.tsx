import { useState } from 'react'
import { announcement } from '../content/site'

export function AnnouncementBar() {
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
          <span className="mr-2 font-semibold text-accent">{announcement.kicker}</span>
          {announcement.text}{' '}
          <a className="font-semibold text-ink underline-offset-2 hover:text-accent hover:underline" href={announcement.href}>
            {announcement.hrefLabel}
          </a>
        </p>
        <button
          type="button"
          className="min-h-11 min-w-11 shrink-0 text-muted hover:text-ink"
          aria-label="Dismiss announcement"
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
