import { useState } from 'react'
import { Button } from './Button'

const KEY = 'weissman_cookie_consent_v1'

export function CookieBanner() {
  const [open, setOpen] = useState(() => {
    try {
      return !localStorage.getItem(KEY)
    } catch {
      return true
    }
  })

  if (!open) return null

  return (
    <div
      id="cookie-banner"
      role="dialog"
      aria-label="Cookie notice"
      className="fixed bottom-4 left-4 right-4 z-[70] mx-auto flex max-w-3xl flex-wrap items-center justify-between gap-3 rounded-[14px] border border-accent/30 bg-[#0b1120] px-4 py-3 text-sm text-muted shadow-[var(--shadow)]"
    >
      <p className="m-0 min-w-[220px] flex-1">
        We use functional cookies only — never tracking pixels. By using Weissman you accept our{' '}
        <a className="text-accent underline" href="/privacy.html">
          Privacy Policy
        </a>
        .
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
        Accept
      </Button>
    </div>
  )
}
