import React, { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
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
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext'
import { SUPPORTED_LANGUAGES } from '../../i18n'

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
  const { session, logout } = useAuth()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  const isSidebar = variant === 'sidebar'

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

  const email = session?.email || 'admin@localhost'
  const initial = (email[0] || '?').toUpperCase()
  const role = (session?.role || 'viewer').toLowerCase()
  const isSuper = session?.is_superadmin === true
  const lang = (i18n.resolvedLanguage || i18n.language || 'en').slice(0, 2)

  const triggerClass = isSidebar
    ? 'w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg border border-white/[0.08] bg-white/[0.03] text-white/80 hover:border-white/20 hover:bg-white/[0.05] transition-colors'
    : 'inline-flex items-center gap-2 px-2 py-1 rounded-lg border border-white/10 bg-black/30 text-white/80 hover:border-white/30 hover:text-white'

  return (
    <div ref={ref} className={`relative ${isSidebar ? 'w-full' : ''}`}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={triggerClass}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        <span className="w-7 h-7 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 text-[11px] font-bold text-black flex items-center justify-center shrink-0">
          {initial}
        </span>
        {isSidebar ? (
          <span className="flex-1 min-w-0 text-start">
            <span className="block text-[11px] text-white/85 font-mono truncate">{email}</span>
            <span className="block text-[9px] uppercase tracking-widest text-white/35 mt-0.5">
              {isSuper ? 'CEO' : role}
            </span>
          </span>
        ) : (
          <span className="hidden sm:inline text-[11px] font-mono uppercase tracking-widest">
            {isSuper ? 'CEO' : role}
          </span>
        )}
        <ChevronDown
          className={`w-3.5 h-3.5 shrink-0 opacity-50 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
          strokeWidth={2}
        />
      </button>

      {open && (
        <div
          role="menu"
          aria-label="Account menu"
          className={`${
            isSidebar ? 'absolute bottom-full mb-2 start-0 end-0' : 'absolute end-0 mt-2'
          } w-64 rounded-xl border border-white/10 bg-[#0b1120]/98 backdrop-blur-md shadow-2xl z-50 p-3 space-y-3`}
        >
          <div className="px-1">
            <div className="text-[13px] text-white/85 font-mono truncate">{email}</div>
            <div className="text-[10px] uppercase tracking-widest text-white/40 mt-1">
              {isSuper ? 'Superadmin' : role}{session?.tenant_id ? ` · tenant ${session.tenant_id}` : ''}
            </div>
          </div>

          <div className="border-t border-white/10 pt-3">
            <div className="text-[10px] uppercase tracking-widest text-white/40 mb-1.5 px-1">
              {t('common.language')}
            </div>
            <div className="flex gap-1">
              {SUPPORTED_LANGUAGES.map((l) => {
                const active = lang === l.code
                return (
                  <button
                    key={l.code}
                    type="button"
                    onClick={() => i18n.changeLanguage(l.code)}
                    className={`flex-1 px-2 py-1 rounded text-[11px] font-mono ${
                      active
                        ? 'bg-cyan-500/20 text-cyan-200 border border-cyan-500/40'
                        : 'text-white/55 border border-transparent hover:border-white/10'
                    }`}
                    aria-pressed={active}
                  >
                    {l.flag} {l.label}
                  </button>
                )
              })}
            </div>
          </div>

          <div className="border-t border-white/10 pt-3 space-y-0.5">
            {QUICK_LINKS.map(({ to, labelKey, icon: Icon }) => (
              <MenuLink
                key={to}
                to={to}
                label={t(labelKey)}
                icon={Icon}
                onClick={() => setOpen(false)}
              />
            ))}
          </div>

          <div className="border-t border-white/10 pt-3">
            <button
              type="button"
              onClick={() => { setOpen(false); logout() }}
              className="w-full flex items-center gap-2 px-2 py-1.5 rounded text-[12px] font-mono text-rose-300 hover:bg-rose-500/10"
            >
              <LogOut className="w-3.5 h-3.5 shrink-0" strokeWidth={1.75} />
              {t('common.logout')}
            </button>
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
      className="flex items-center gap-2 px-2 py-1.5 rounded text-[12px] font-mono text-white/70 hover:bg-white/5 hover:text-white"
      role="menuitem"
    >
      <Icon className="w-3.5 h-3.5 shrink-0 text-white/40" strokeWidth={1.75} />
      <span className="flex-1 truncate">{label}</span>
    </Link>
  )
}
