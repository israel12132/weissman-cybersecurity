import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import {
  ChevronDown,
  LogOut,
  MessageSquare,
  Zap,
  Building2,
  Settings,
  Users,
  ScrollText,
  Activity,
  Sun,
  Moon,
  Contrast,
  KeyRound,
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext'
import { sessionIdentityLabel, isClientUser } from '../../lib/clientScope'
import { canAccessNavItem } from '../../lib/appNav'
import { useTheme } from '../../context/ThemeContext'
import { SUPPORTED_LANGUAGES } from '../../i18n'
import useFocusTrap from '../../hooks/useFocusTrap'
import Button from './Button'

const QUICK_LINKS = [
  { to: '/ask', labelKey: 'nav.ask_weissman', icon: MessageSquare },
  { to: '/playbooks', labelKey: 'nav.playbooks', icon: Zap },
  { to: '/clients', labelKey: 'nav.clients', icon: Building2 },
  { to: '/system-config', labelKey: 'nav.system_config', icon: Settings },
  { to: '/admin', labelKey: 'nav.admin', icon: Users },
  { to: '/audit-log', labelKey: 'nav.audit_log', icon: ScrollText },
  { to: '/status', labelKey: 'nav.status', icon: Activity },
]

/**
 * Profile dropdown — avatar, email, role, language picker, quick links, logout.
 * `variant="sidebar"` renders a full-width footer trigger for GlobalNexus.
 */
export default function ProfileMenu({ variant = 'header' }) {
  const { t, i18n } = useTranslation()
  const { session, logout, isCeo } = useAuth()
  const { theme, cycleTheme } = useTheme()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  const menuRef = useRef(null)
  const isSidebar = variant === 'sidebar'
  useFocusTrap(menuRef, open)

  useEffect(() => {
    if (!open) return undefined
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false) }
    const onClick = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', onClick)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', onClick)
    }
  }, [open])

  const email = session?.email || t('profile.signed_in')
  const initial = (String(email).replace(/[^a-zA-Z0-9]/g, '')[0] || '?').toUpperCase()
  const identity = sessionIdentityLabel(session, t)
  const portal = isClientUser(session)
  const lang = (i18n.resolvedLanguage || i18n.language || 'en').slice(0, 2)
  const visibleLinks = QUICK_LINKS.filter((item) => canAccessNavItem(item, session))

  const triggerClass = isSidebar
    ? 'w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[var(--text-secondary)] hover:border-[var(--border-strong)] hover:bg-[var(--row-hover-bg)] transition-colors'
    : 'inline-flex items-center gap-2 px-2 py-1 rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] text-[var(--text-secondary)] hover:border-[var(--border-strong)] hover:text-[var(--text-primary)]'

  return (
    <div ref={ref} className={`relative ${isSidebar ? 'w-full' : ''}`}>
      <Button variant="unstyled"
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={triggerClass}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={t('a11y.open_account_menu')}
      >
        <span className="w-7 h-7 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 text-[11px] font-bold text-black flex items-center justify-center shrink-0">
          {initial}
        </span>
        {isSidebar ? (
          <span className="flex-1 min-w-0 text-start">
            <span className="block text-[11px] text-[var(--text-primary)] font-mono truncate">{email}</span>
            <span className="block text-[9px] uppercase tracking-widest text-[var(--text-muted)] mt-0.5">
              {identity}
            </span>
          </span>
        ) : (
          <span className="hidden sm:inline text-[11px] font-mono uppercase tracking-widest">
            {identity}
          </span>
        )}
        <ChevronDown
          className={`w-3.5 h-3.5 shrink-0 opacity-50 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
          strokeWidth={2}
        />
      </Button>

      {open && (
        <div
          ref={menuRef}
          role="menu"
          aria-label={t('a11y.account_menu')}
          className={`${
            isSidebar ? 'absolute bottom-full mb-2 start-0 end-0' : 'absolute end-0 mt-2'
          } w-64 rounded-xl border border-[var(--border-default)] bg-[var(--bg-elevated)] backdrop-blur-md shadow-2xl z-50 p-3 space-y-3`}
        >
          <div className="px-1">
            <div className="text-[13px] text-[var(--text-primary)] font-mono truncate">{email}</div>
            <div className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] mt-1">
              {identity}{portal ? ` · ${t('profile.bound_workspace')}` : ''}
            </div>
          </div>

          <div className="border-t border-[var(--border-default)] pt-3">
            <div className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] mb-1.5 px-1">
              {t('common.language')}
            </div>
            <div className="flex gap-1">
              {SUPPORTED_LANGUAGES.map((l) => {
                const active = lang === l.code
                return (
                  <Button variant="unstyled"
                    key={l.code}
                    type="button"
                    onClick={() => i18n.changeLanguage(l.code)}
                    className={`flex-1 px-2 py-1 rounded text-[11px] font-mono ${
                      active
                        ? 'bg-cyan-500/20 text-cyan-200 border border-cyan-500/40'
                        : 'text-[var(--text-tertiary)] border border-transparent hover:border-[var(--border-default)]'
                    }`}
                    aria-pressed={active}
                  >
                    {l.flag} {l.label}
                  </Button>
                )
              })}
            </div>
          </div>

          <div className="border-t border-[var(--border-default)] pt-3">
            <div className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] mb-1.5 px-1">
              {t('common.theme')}
            </div>
            <Button variant="unstyled"
              type="button"
              onClick={cycleTheme}
              className="w-full flex items-center justify-between gap-2 px-2 py-1.5 rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[12px] font-mono text-[var(--text-secondary)] hover:border-[var(--border-strong)] hover:text-[var(--text-primary)] transition-colors"
              aria-label={t('common.cycle_theme')}
            >
              <span className="flex items-center gap-2">
                {theme === 'light' ? (
                  <Sun className="w-3.5 h-3.5" />
                ) : theme === 'high-contrast' ? (
                  <Contrast className="w-3.5 h-3.5" />
                ) : (
                  <Moon className="w-3.5 h-3.5" />
                )}
                {theme === 'light'
                  ? t('common.theme_light')
                  : theme === 'high-contrast'
                    ? t('common.theme_high_contrast')
                    : t('common.theme_dark')}
              </span>
              <span className="text-[9px] uppercase tracking-widest text-[var(--text-muted)]">
                {t('common.switch')}
              </span>
            </Button>
          </div>

          <div className="border-t border-[var(--border-default)] pt-3 space-y-0.5">
            {visibleLinks.map(({ to, labelKey, icon: Icon }) => (
              <MenuLink
                key={to}
                to={to}
                label={t(labelKey)}
                icon={Icon}
                onClick={() => setOpen(false)}
              />
            ))}
            {isCeo && (
              <MenuLink
                to="/ceo-keys"
                label={t('nav.ceo_keys')}
                icon={KeyRound}
                onClick={() => setOpen(false)}
              />
            )}
          </div>

          <div className="border-t border-[var(--border-default)] pt-3">
            <Button variant="unstyled"
              type="button"
              onClick={() => { setOpen(false); logout() }}
              className="w-full flex items-center gap-2 px-2 py-1.5 rounded text-[12px] font-mono text-rose-300 hover:bg-rose-500/10"
            >
              <LogOut className="w-3.5 h-3.5 shrink-0" strokeWidth={1.75} />
              {t('common.logout')}
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

function MenuLink({ to, label, icon: Icon, onClick }) {
  return (
    <Link
      to={to}
      onClick={onClick}
      className="flex items-center gap-2 px-2 py-1.5 rounded text-[12px] font-mono text-[var(--text-secondary)] hover:bg-[var(--row-hover-bg)] hover:text-[var(--text-primary)]"
      role="menuitem"
    >
      <Icon className="w-3.5 h-3.5 shrink-0 text-[var(--text-muted)]" strokeWidth={1.75} />
      <span className="flex-1 truncate">{label}</span>
    </Link>
  )
}
