import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ChevronDown, Menu, X, Search, Star } from 'lucide-react'
import Logo from '../Logo'
import {
  NAV_GROUPS,
  PRIMARY_NAV_GROUP,
  isNavActive,
  canAccessNavItem,
  findNavMatch,
} from '../../lib/appNav'
import { useAuth } from '../../context/AuthContext'
import Button from '../ui/Button'

const FAV_KEY = 'weissman_nav_favs'
const REC_KEY = 'weissman_nav_recents'

function loadArr(key) {
  try {
    const v = JSON.parse(localStorage.getItem(key))
    return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []
  } catch {
    return []
  }
}
function saveArr(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value))
  } catch {
    /* localStorage may be unavailable (private mode) — favorites are a convenience only */
  }
}

function SectionLabel({ children }) {
  return (
    <div className="px-2 py-1.5 text-[9px] font-mono uppercase tracking-widest text-[var(--text-muted)] flex items-center gap-1.5">
      {children}
    </div>
  )
}

function NavRow({ item, label, active, onNavigate, betaLabel, isFav, onToggleFav, favOnLabel, favOffLabel }) {
  return (
    <div
      className={[
        'group/nav relative flex items-center rounded-lg border',
        active
          ? 'bg-cyan-500/15 border-cyan-500/25'
          : 'border-transparent hover:bg-[var(--row-hover-bg)]',
      ].join(' ')}
    >
      <Link
        to={item.to}
        onClick={onNavigate}
        aria-current={active ? 'page' : undefined}
        className={[
          'flex-1 min-w-0 flex items-center gap-2.5 pl-2.5 pr-1 py-2 rounded-lg text-[11px] font-mono transition-colors',
          active
            ? 'text-cyan-200'
            : 'text-[var(--text-tertiary)] group-hover/nav:text-[var(--text-secondary)]',
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
      <Button
        variant="unstyled"
        type="button"
        onClick={() => onToggleFav(item.to)}
        aria-pressed={isFav}
        aria-label={isFav ? favOnLabel : favOffLabel}
        title={isFav ? favOnLabel : favOffLabel}
        className={[
          'shrink-0 mr-1 w-6 h-6 grid place-items-center rounded-md transition-colors focus-visible:opacity-100',
          isFav
            ? 'text-amber-300'
            : 'text-[var(--text-muted)] opacity-0 group-hover/nav:opacity-100 hover:text-amber-300',
        ].join(' ')}
      >
        <Star className="w-3 h-3" fill={isFav ? 'currentColor' : 'none'} aria-hidden />
      </Button>
    </div>
  )
}

export default function AppSidebar() {
  const { t } = useTranslation()
  const { session } = useAuth()
  const { pathname } = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)
  const [collapsedGroups, setCollapsedGroups] = useState({})
  const [query, setQuery] = useState('')
  const [favs, setFavs] = useState(() => loadArr(FAV_KEY))
  const [recents, setRecents] = useState(() => loadArr(REC_KEY))
  const searchRef = useRef(null)

  const betaLabel = t('nav.beta')
  const favOnLabel = t('nav.remove_favorite')
  const favOffLabel = t('nav.add_favorite')

  // RBAC-filtered, route-deduped navigation model — a screen the session cannot
  // reach is never rendered (the same gate the route guards enforce).
  const groups = useMemo(() => {
    const seen = new Set()
    const out = []
    for (const group of [PRIMARY_NAV_GROUP, ...NAV_GROUPS]) {
      const items = []
      for (const item of group.items) {
        if (!canAccessNavItem(item, session)) continue
        if (seen.has(item.to)) continue
        seen.add(item.to)
        items.push(item)
      }
      if (items.length) out.push({ ...group, items })
    }
    return out
  }, [session])

  const allItems = useMemo(() => groups.flatMap((g) => g.items), [groups])
  const itemByRoute = useMemo(() => {
    const m = {}
    allItems.forEach((it) => {
      m[it.to] = it
    })
    return m
  }, [allItems])

  const activeGroupId = useMemo(() => {
    for (const group of groups) {
      if (group.items.some((item) => isNavActive(pathname, item.to, item.exact))) return group.id
    }
    return groups[0]?.id
  }, [pathname, groups])

  // Record the current screen into "recent" — only routes the session can access.
  useEffect(() => {
    const match = findNavMatch(pathname)
    const to = match?.item?.to
    if (!to || !itemByRoute[to]) return
    setRecents((prev) => {
      const next = [to, ...prev.filter((r) => r !== to)].slice(0, 6)
      saveArr(REC_KEY, next)
      return next
    })
  }, [pathname, itemByRoute])

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

  const toggleGroup = useCallback((id) => {
    setCollapsedGroups((prev) => ({ ...prev, [id]: !prev[id] }))
  }, [])

  const toggleFav = useCallback((to) => {
    setFavs((prev) => {
      const next = prev.includes(to) ? prev.filter((r) => r !== to) : [...prev, to]
      saveArr(FAV_KEY, next)
      return next
    })
  }, [])

  const closeMobile = useCallback(() => setMobileOpen(false), [])

  const q = query.trim().toLowerCase()
  const searchHits = useMemo(() => {
    if (!q) return null
    return allItems.filter((it) => {
      const lbl = String(t(it.labelKey) || '').toLowerCase()
      return lbl.includes(q) || it.to.toLowerCase().includes(q)
    })
  }, [q, allItems, t])

  const favItems = favs.map((r) => itemByRoute[r]).filter(Boolean)
  const recItems = recents
    .map((r) => itemByRoute[r])
    .filter(Boolean)
    .filter((it) => !favs.includes(it.to))
    .slice(0, 5)

  const rowProps = (item) => ({
    item,
    label: t(item.labelKey),
    active: isNavActive(pathname, item.to, item.exact),
    onNavigate: closeMobile,
    betaLabel,
    isFav: favs.includes(item.to),
    onToggleFav: toggleFav,
    favOnLabel,
    favOffLabel,
  })

  const sidebarBody = (
    <div className="flex flex-col h-full">
      <div className="px-3 py-4 border-b border-[var(--border-default)] shrink-0 flex items-center justify-between gap-2">
        <Link to="/" className="flex items-center gap-2.5 min-w-0" aria-label={t('nav.dashboard')}>
          <Logo compact size={28} />
          <div className="min-w-0 hidden lg:block">
            <div className="text-[11px] font-semibold text-[var(--text-primary)] truncate">Weissman</div>
            <div className="text-[9px] font-mono uppercase tracking-widest text-[var(--text-muted)] truncate">
              Command Center
            </div>
          </div>
        </Link>
        <span className="hidden lg:block text-[8px] font-mono text-[var(--text-muted)] whitespace-nowrap tabular-nums">
          {t('nav.screens_count', { n: allItems.length })}
        </span>
      </div>

      <div className="px-2 pt-2.5 shrink-0">
        <label className="flex items-center gap-2 rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] px-2.5 py-1.5 focus-within:border-cyan-500/40">
          <Search className="w-3.5 h-3.5 text-[var(--text-muted)] shrink-0" aria-hidden />
          <input
            ref={searchRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            type="search"
            placeholder={t('nav.search_placeholder')}
            aria-label={t('nav.search_aria')}
            spellCheck={false}
            autoComplete="off"
            className="flex-1 min-w-0 bg-transparent outline-none text-[11px] font-mono text-[var(--text-primary)] placeholder:text-[var(--text-muted)]"
          />
        </label>
      </div>

      <nav className="flex-1 overflow-y-auto overflow-x-hidden py-3 px-2 space-y-0.5 min-h-0">
        {searchHits ? (
          <div>
            <SectionLabel>
              <span>{t('nav.results')}</span>
              <span className="text-[var(--text-tertiary)] tracking-normal">{searchHits.length}</span>
            </SectionLabel>
            {searchHits.length ? (
              searchHits.map((item) => <NavRow key={item.to} {...rowProps(item)} />)
            ) : (
              <div className="px-2 py-6 text-center text-[11px] font-mono text-[var(--text-muted)]">
                {t('nav.no_results')}
              </div>
            )}
          </div>
        ) : (
          <>
            {favItems.length > 0 && (
              <div className="mb-2 pb-2 border-b border-[var(--border-default)]">
                <SectionLabel>
                  <Star className="w-2.5 h-2.5 text-amber-300" fill="currentColor" aria-hidden />
                  <span>{t('nav.favorites')}</span>
                </SectionLabel>
                <div className="mt-0.5 space-y-0.5">
                  {favItems.map((item) => (
                    <NavRow key={`fav-${item.to}`} {...rowProps(item)} />
                  ))}
                </div>
              </div>
            )}

            {recItems.length > 0 && (
              <div className="mb-2 pb-2 border-b border-[var(--border-default)]">
                <SectionLabel>
                  <span>{t('nav.recent')}</span>
                </SectionLabel>
                <div className="mt-0.5 space-y-0.5">
                  {recItems.map((item) => (
                    <NavRow key={`rec-${item.to}`} {...rowProps(item)} />
                  ))}
                </div>
              </div>
            )}

            {groups.map((group) => {
              const isCollapsed = collapsedGroups[group.id] && group.id !== activeGroupId
              const groupHasActive = group.items.some((item) =>
                isNavActive(pathname, item.to, item.exact),
              )
              return (
                <div key={group.id} className="mb-1">
                  <Button
                    variant="unstyled"
                    type="button"
                    onClick={() => toggleGroup(group.id)}
                    className={[
                      'w-full flex items-center justify-between gap-2 px-2 py-1.5 rounded-md text-[9px] font-mono uppercase tracking-widest transition-colors',
                      groupHasActive
                        ? 'text-cyan-400/80'
                        : 'text-[var(--text-muted)] hover:text-[var(--text-tertiary)]',
                    ].join(' ')}
                    aria-expanded={!isCollapsed}
                  >
                    <span className="truncate flex items-center gap-1.5">
                      <ChevronDown
                        className={`w-3 h-3 shrink-0 transition-transform ${isCollapsed ? '-rotate-90' : ''}`}
                        aria-hidden
                      />
                      {t(group.labelKey)}
                    </span>
                    <span className="shrink-0 tabular-nums opacity-70">{group.items.length}</span>
                  </Button>
                  {!isCollapsed && (
                    <div className="mt-0.5 space-y-0.5">
                      {group.items.map((item) => (
                        <NavRow key={item.to} {...rowProps(item)} />
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </>
        )}
      </nav>
    </div>
  )

  return (
    <>
      <Button
        variant="unstyled"
        type="button"
        className="print:hidden lg:hidden fixed top-3 left-3 z-40 p-2 rounded-lg border border-[var(--border-strong)] bg-[var(--sidebar-surface)] backdrop-blur-md text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
        onClick={() => setMobileOpen(true)}
        aria-label={t('nav.open_menu')}
      >
        <Menu className="w-5 h-5" />
      </Button>

      {mobileOpen && (
        <Button
          variant="unstyled"
          type="button"
          className="lg:hidden fixed inset-0 z-40 bg-[var(--scrim)] backdrop-blur-sm"
          aria-label={t('nav.close_menu')}
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={[
          'print:hidden fixed lg:sticky top-0 z-50 lg:z-10 h-[100dvh] w-[15.5rem] shrink-0',
          'bg-[var(--sidebar-surface)] backdrop-blur-xl border-r border-[var(--border-default)]',
          'transition-transform duration-200 ease-out',
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0',
        ].join(' ')}
        aria-label={t('nav.mobile_label')}
      >
        <Button
          variant="unstyled"
          type="button"
          className="lg:hidden absolute top-3 right-3 z-10 p-1.5 rounded-md text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-[var(--row-hover-bg)]"
          onClick={() => setMobileOpen(false)}
          aria-label={t('nav.close_menu')}
        >
          <X className="w-4 h-4" />
        </Button>
        {sidebarBody}
      </aside>
    </>
  )
}
