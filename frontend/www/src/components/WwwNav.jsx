import { useEffect, useState } from 'react'
import { Link, NavLink } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Menu, X } from 'lucide-react'
import Logo from '@cc/components/Logo'
import Button from '@cc/components/ui/Button'
import { probeExistingSession } from '../lib/session'
import i18n from '../i18n'

const LINKS = [
  { to: '/platform', key: 'nav.platform' },
  { to: '/engines', key: 'nav.engines' },
  { to: '/how-it-works', key: 'nav.how' },
  { to: '/pricing', key: 'nav.pricing' },
  { to: '/security', key: 'nav.security' },
  { to: '/contact', key: 'nav.contact' },
]

export default function WwwNav() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [authed, setAuthed] = useState(false)
  const lang = (i18n.resolvedLanguage || i18n.language || 'en').slice(0, 2)

  useEffect(() => {
    let cancelled = false
    probeExistingSession().then((session) => {
      if (!cancelled) setAuthed(Boolean(session?.ok))
    })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <header className="sticky top-0 z-50 border-b border-white/10 bg-[#030712]/80 backdrop-blur-xl">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-5 py-3.5">
        <a href="/" className="shrink-0" aria-label="Weissman">
          <Logo size={36} />
        </a>
        <nav className="hidden items-center gap-6 lg:flex" aria-label="Primary">
          {LINKS.map((l) => (
            <NavLink
              key={l.to}
              to={l.to}
              className={({ isActive }) =>
                `text-sm transition-colors ${isActive ? 'text-cyan-200' : 'text-white/55 hover:text-white'}`
              }
            >
              {t(l.key)}
            </NavLink>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          <div className="hidden sm:inline-flex items-center gap-1 rounded-lg border border-white/10 p-0.5" role="group" aria-label={t('auth.language')}>
            {['en', 'he'].map((code) => (
              <Button
                key={code}
                variant="unstyled"
                type="button"
                className={`rounded-md px-2 py-1 text-[11px] ${lang === code ? 'bg-cyan-500/15 text-cyan-200' : 'text-white/50 hover:text-white'}`}
                onClick={() => i18n.changeLanguage(code)}
                aria-pressed={lang === code}
              >
                {code === 'he' ? 'עב' : 'EN'}
              </Button>
            ))}
          </div>
          <a
            href={authed ? '/command-center/' : '/login'}
            className="hidden rounded-lg border border-white/15 px-3 py-1.5 text-sm text-white/80 hover:border-cyan-400/40 hover:text-cyan-100 sm:inline-flex"
          >
            {authed ? t('nav.enter') : t('nav.sign_in')}
          </a>
          <Link
            to="/signup"
            className="hidden rounded-lg bg-cyan-400 px-3 py-1.5 text-sm font-semibold text-[#041018] hover:bg-cyan-300 sm:inline-flex"
          >
            {t('nav.trial')}
          </Link>
          <Button
            variant="unstyled"
            type="button"
            className="rounded-lg border border-white/10 p-2 text-white/70 lg:hidden"
            aria-label={open ? t('nav.close') : t('nav.menu')}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </Button>
        </div>
      </div>
      {open && (
        <div className="border-t border-white/10 px-5 py-4 lg:hidden">
          <div className="flex flex-col gap-3">
            {LINKS.map((l) => (
              <NavLink key={l.to} to={l.to} onClick={() => setOpen(false)} className="text-white/80">
                {t(l.key)}
              </NavLink>
            ))}
            <a href={authed ? '/command-center/' : '/login'} className="text-cyan-200">
              {authed ? t('nav.enter') : t('nav.sign_in')}
            </a>
            <Link to="/signup" onClick={() => setOpen(false)} className="text-cyan-200">
              {t('nav.trial')}
            </Link>
            <div className="flex gap-2 pt-2">
              {['en', 'he'].map((code) => (
                <Button
                  key={code}
                  variant="unstyled"
                  type="button"
                  className={`rounded-md px-2 py-1 text-[11px] ${lang === code ? 'bg-cyan-500/15 text-cyan-200' : 'text-white/50'}`}
                  onClick={() => i18n.changeLanguage(code)}
                >
                  {code === 'he' ? 'עב' : 'EN'}
                </Button>
              ))}
            </div>
          </div>
        </div>
      )}
    </header>
  )
}
