import React, { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useAuth } from '../../context/AuthContext'
import { SUPPORTED_LANGUAGES } from '../../i18n'

/**
 * Top-right profile dropdown — avatar (initial), email, role, language picker, logout.
 * Closes on Escape and on outside click.
 */
export default function ProfileMenu() {
  const { t, i18n } = useTranslation()
  const { session, logout } = useAuth()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

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

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-2 px-2 py-1 rounded-lg border border-white/10 bg-black/30 text-white/80 hover:border-white/30 hover:text-white"
        aria-haspopup="menu"
        aria-expanded={open}
      >
        <span className="w-6 h-6 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 text-[11px] font-bold text-black flex items-center justify-center">
          {initial}
        </span>
        <span className="hidden sm:inline text-[11px] font-mono uppercase tracking-widest">
          {isSuper ? 'CEO' : role}
        </span>
        <span aria-hidden="true" className="text-[10px] opacity-60">▾</span>
      </button>

      {open && (
        <div
          role="menu"
          aria-label="Account menu"
          className="absolute end-0 mt-2 w-64 rounded-xl border border-white/10 bg-[#0b1120]/98 backdrop-blur-md shadow-2xl z-50 p-3 space-y-3"
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

          <div className="border-t border-white/10 pt-3 space-y-1">
            <MenuLink to="/system-config" label={t('nav.system_config')} icon="⚙" onClick={() => setOpen(false)} />
            <MenuLink to="/admin" label={t('nav.admin')} icon="👥" onClick={() => setOpen(false)} />
            <MenuLink to="/audit-log" label={t('nav.audit_log', { defaultValue: 'Audit log' })} icon="📋" onClick={() => setOpen(false)} />
            <MenuLink to="/status" label={t('nav.status')} icon="✔" external onClick={() => setOpen(false)} />
          </div>

          <div className="border-t border-white/10 pt-3">
            <button
              type="button"
              onClick={() => { setOpen(false); logout() }}
              className="w-full text-left px-2 py-1.5 rounded text-[12px] font-mono text-rose-300 hover:bg-rose-500/10"
            >
              ↩ {t('common.logout')}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function MenuLink({ to, label, icon, onClick }) {
  return (
    <Link
      to={to}
      onClick={onClick}
      className="flex items-center gap-2 px-2 py-1.5 rounded text-[12px] font-mono text-white/70 hover:bg-white/5 hover:text-white"
      role="menuitem"
    >
      <span className="opacity-60 w-4 text-center" aria-hidden="true">{icon}</span>
      <span className="flex-1 truncate">{label}</span>
    </Link>
  )
}
