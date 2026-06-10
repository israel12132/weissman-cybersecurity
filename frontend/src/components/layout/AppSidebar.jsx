import React, { useEffect, useMemo, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ChevronDown, Menu, X } from 'lucide-react'
import Logo from '../Logo'
import { NAV_GROUPS, PRIMARY_NAV, isNavActive, canAccessNavItem } from '../../lib/appNav'
import { useAuth } from '../../context/AuthContext'

function NavLink({ item, label, active, onNavigate, betaLabel }) {
  return (
    <Link
      to={item.to}
      onClick={onNavigate}
      className={[
        'flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-[11px] font-mono transition-colors',
        active
          ? 'bg-cyan-500/15 text-cyan-200 border border-cyan-500/25'
          : 'text-white/55 hover:bg-white/5 hover:text-white/85 border border-transparent',
      ].join(' ')}
    >
      {item.icon && (
        <span className="w-4 text-center shrink-0 text-[12px] opacity-80" aria-hidden>
          {item.icon}
        </span>
      )}
      <span className="truncate flex-1 min-w-0">{label}</span>
      {item.beta && betaLabel && (
        <span
          className="shrink-0 text-[8px] font-mono px-1 py-0.5 rounded border border-violet-500/30 bg-violet-500/10 text-violet-300/85 uppercase tracking-wider"
          aria-label={betaLabel}
        >
          {betaLabel}
        </span>
      )}
    </Link>
  )
}

export default function AppSidebar() {
  const { t } = useTranslation()
  const { session } = useAuth()
  const { pathname } = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)
  const [collapsedGroups, setCollapsedGroups] = useState({})

  const betaLabel = t('nav.beta')
  const primaryItems = useMemo(
    () => PRIMARY_NAV.filter((item) => canAccessNavItem(item, session)),
    [session],
  )

  const activeGroupId = useMemo(() => {
    if (primaryItems.some((item) => isNavActive(pathname, item.to, item.exact))) {
      return 'primary'
    }
    for (const group of NAV_GROUPS) {
      if (group.items.some((item) => isNavActive(pathname, item.to, item.exact))) {
        return group.id
      }
    }
    return 'primary'
  }, [pathname, primaryItems])

  useEffect(() => {
    setMobileOpen(false)
  }, [pathname])

  useEffect(() => {
    if (!mobileOpen) return undefined
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = prev
    }
  }, [mobileOpen])

  const toggleGroup = (id) => {
    setCollapsedGroups((prev) => ({ ...prev, [id]: !prev[id] }))
  }

  const sidebarBody = (
    <div className="flex flex-col h-full">
      <div className="px-3 py-4 border-b border-white/10 shrink-0">
        <Link to="/" className="flex items-center gap-2.5 min-w-0" aria-label={t('nav.dashboard')}>
          <Logo compact size={28} />
          <div className="min-w-0 hidden lg:block">
            <div className="text-[11px] font-semibold text-white/90 truncate">Weissman</div>
            <div className="text-[9px] font-mono uppercase tracking-widest text-white/35 truncate">
              Command Center
            </div>
          </div>
        </Link>
      </div>

      <nav className="flex-1 overflow-y-auto overflow-x-hidden py-3 px-2 space-y-1 min-h-0">
        {primaryItems.length > 0 && (
          <div className="mb-2 pb-2 border-b border-white/10">
            <div className="px-2 py-1.5 text-[9px] font-mono uppercase tracking-widest text-white/35">
              {t('nav.groups.primary')}
            </div>
            <div className="mt-0.5 space-y-0.5">
              {primaryItems.map((item) => (
                <NavLink
                  key={item.to}
                  item={item}
                  label={t(item.labelKey)}
                  active={isNavActive(pathname, item.to, item.exact)}
                  onNavigate={() => setMobileOpen(false)}
                  betaLabel={betaLabel}
                />
              ))}
            </div>
          </div>
        )}

        {NAV_GROUPS.map((group) => {
          const visibleItems = group.items.filter((item) => canAccessNavItem(item, session))
          if (visibleItems.length === 0) return null
          const isCollapsed = collapsedGroups[group.id] && group.id !== activeGroupId
          const groupHasActive = visibleItems.some((item) => isNavActive(pathname, item.to, item.exact))

          return (
            <div key={group.id} className="mb-1">
              <button
                type="button"
                onClick={() => toggleGroup(group.id)}
                className={[
                  'w-full flex items-center justify-between gap-2 px-2 py-1.5 rounded-md text-[9px] font-mono uppercase tracking-widest transition-colors',
                  groupHasActive ? 'text-cyan-400/80' : 'text-white/35 hover:text-white/55',
                ].join(' ')}
                aria-expanded={!isCollapsed}
              >
                <span className="truncate">{t(group.labelKey)}</span>
                <ChevronDown
                  className={`w-3 h-3 shrink-0 transition-transform ${isCollapsed ? '-rotate-90' : ''}`}
                />
              </button>
              {!isCollapsed && (
                <div className="mt-0.5 space-y-0.5">
                  {visibleItems.map((item) => (
                    <NavLink
                      key={item.to}
                      item={item}
                      label={t(item.labelKey)}
                      active={isNavActive(pathname, item.to, item.exact)}
                      onNavigate={() => setMobileOpen(false)}
                      betaLabel={betaLabel}
                    />
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </nav>
    </div>
  )

  return (
    <>
      <button
        type="button"
        className="lg:hidden fixed top-3 left-3 z-40 p-2 rounded-lg border border-white/15 bg-black/60 backdrop-blur-md text-white/80 hover:text-white"
        onClick={() => setMobileOpen(true)}
        aria-label={t('nav.open_menu')}
      >
        <Menu className="w-5 h-5" />
      </button>

      {mobileOpen && (
        <button
          type="button"
          className="lg:hidden fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
          aria-label={t('nav.close_menu')}
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={[
          'fixed lg:sticky top-0 z-50 lg:z-10 h-[100dvh] w-[15.5rem] shrink-0',
          'bg-black/50 backdrop-blur-xl border-r border-white/10',
          'transition-transform duration-200 ease-out',
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0',
        ].join(' ')}
      >
        <button
          type="button"
          className="lg:hidden absolute top-3 right-3 p-1.5 rounded-md text-white/60 hover:text-white hover:bg-white/10"
          onClick={() => setMobileOpen(false)}
          aria-label={t('nav.close_menu')}
        >
          <X className="w-4 h-4" />
        </button>
        {sidebarBody}
      </aside>
    </>
  )
}
