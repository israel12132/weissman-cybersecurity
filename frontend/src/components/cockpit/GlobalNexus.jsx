import { useState, useEffect, useMemo } from 'react'
import { Link, useLocation } from 'react-router'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import {
  LayoutDashboard,
  ShieldAlert,
  Bug,
  Clock,
  MessageSquare,
  Radar,
  GitBranch,
  Zap,
  CalendarClock,
  Bell,
  Building2,
  Server,
  Cpu,
  ScrollText,
  Settings,
  Shield,
  CreditCard,
  ChevronDown,
  PanelLeftClose,
  PanelLeft,
  Trash2,
  UserPlus,
} from 'lucide-react'
import { PRIMARY_NAV, canAccessNavItem } from '../../lib/appNav'
import { useClient } from '../../context/ClientContext'
import { useAuth } from '../../context/AuthContext'
import { formatApiErrorResponse } from '../../lib/apiError.js'
import { apiFetch } from '../../utils/apiFetch'
import { useProductionEngines } from '../../lib/useProductionEngines'
import TacticalNavLink from '../nav/TacticalNavLink'
import Logo from '../Logo'
import ProfileMenu from '../ui/ProfileMenu'
import LanguageSwitcher from '../LanguageSwitcher'
import { useToast } from '../ui/Toaster'
import { confirmDialog } from '../../utils/confirmDialog'
import Button from '../ui/Button'

const STORAGE_KEY = 'weissman.nav.sections'
const GN = 'components.cockpitWidgets.globalNexus'

function readSectionState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) : {}
  } catch {
    return {}
  }
}

function writeSectionState(state) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
  } catch { /* ignore */ }
}

function isRouteActive(pathname, to, matchPaths) {
  if (matchPaths?.length) {
    return matchPaths.some((p) => (p === '/' ? pathname === '/' : pathname === p || pathname.startsWith(`${p}/`)))
  }
  if (to === '/') return pathname === '/' || pathname === '/operations'
  return pathname === to || pathname.startsWith(`${to}/`)
}

function NavLink({ to, label, icon: Icon, id, matchPaths, badge, beta, betaLabel }) {
  const { pathname } = useLocation()
  const active = isRouteActive(pathname, to, matchPaths)

  return (
    <TacticalNavLink
      id={id}
      to={to}
      className={`group relative flex items-center gap-2.5 pl-3 pr-2.5 py-[7px] rounded-lg text-[11px] font-medium tracking-wide transition-all duration-200 ${
        active
          ? 'text-cyan-100 bg-cyan-500/[0.08] shadow-[inset_0_0_20px_rgba(34,211,238,0.06)]'
          : 'text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:bg-[var(--row-hover-bg)]'
      }`}
    >
      <span
        className={`absolute start-0 top-1/2 -translate-y-1/2 w-[3px] rounded-full transition-all duration-200 ${
          active ? 'h-[70%] bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.7)]' : 'h-0 bg-transparent'
        }`}
        aria-hidden
      />
      <Icon
        className={`w-[15px] h-[15px] shrink-0 transition-colors ${
          active ? 'text-cyan-400' : 'text-[var(--text-muted)] group-hover:text-[var(--text-tertiary)]'
        }`}
        strokeWidth={active ? 2.25 : 1.75}
      />
      <span className="flex-1 truncate min-w-0">{label}</span>
      {beta && betaLabel && (
        <span className="shrink-0 text-[8px] font-mono px-1 py-0.5 rounded border border-violet-500/30 bg-violet-500/10 text-violet-300/85 uppercase tracking-wider">
          {betaLabel}
        </span>
      )}
      {badge != null && (
        <span className="shrink-0 text-[9px] font-mono tabular-nums px-1.5 py-0.5 rounded border border-cyan-500/25 bg-cyan-500/10 text-cyan-300/80">
          {badge}
        </span>
      )}
    </TacticalNavLink>
  )
}

function NavSection({ id, title, children, open, onToggle }) {
  return (
    <div className="mb-0.5">
      <Button variant="unstyled"
        type="button"
        onClick={() => onToggle(id)}
        className="w-full flex items-center justify-between gap-2 px-2 py-2 rounded-md text-[9px] font-mono uppercase tracking-[0.22em] text-[var(--text-muted)] hover:text-[var(--text-tertiary)] hover:bg-[var(--row-hover-bg)] transition-colors"
        aria-expanded={open}
      >
        <span className="truncate">{title}</span>
        <motion.span
          animate={{ rotate: open ? 0 : -90 }}
          transition={{ duration: 0.2, ease: [0.4, 0, 0.2, 1] }}
          className="shrink-0"
        >
          <ChevronDown className="w-3 h-3" strokeWidth={2} />
        </motion.span>
      </Button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.4, 0, 0.2, 1] }}
            className="overflow-hidden"
          >
            <div className="space-y-0.5 pb-1.5 pt-0.5">{children}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default function GlobalNexus({ ceoIntegrated = false }) {
  const { t } = useTranslation()
  const { isCeo, session, canCreateClients, canDeleteClients, isClientUser } = useAuth()
  const { toast } = useToast()
  const { clients, clientsError, dismissClientsError, selectedClientId, setSelectedClientId, refreshClients, clientScopeLocked } = useClient()
  const [stats, setStats] = useState({ total_vulnerabilities: 0, security_score: 0, active_scans: 0 })
  const [deletingId, setDeletingId] = useState(null)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [sectionOpen, setSectionOpen] = useState(() => {
    const saved = readSectionState()
    return {
      command: saved.command ?? true,
      intelligence: saved.intelligence ?? true,
      automation: saved.automation ?? false,
      clients_agents: saved.clients_agents ?? true,
      platform: saved.platform ?? false,
    }
  })
  const { productionCount, catalogCount } = useProductionEngines({ prefetch: true })
  const engineCountLabel = productionCount > 0 ? productionCount : catalogCount

  const toggleSection = (id) => {
    setSectionOpen((prev) => {
      const next = { ...prev, [id]: !prev[id] }
      writeSectionState(next)
      return next
    })
  }

  const primaryNavItems = useMemo(() => {
    const meta = {
      '/clients': { icon: Building2, id: 'nav-clients' },
      '/vuln-intel': { icon: Bug, id: 'nav-vuln-intel' },
      '/engines': { icon: Cpu, id: 'nav-engine-matrix', badge: engineCountLabel },
      '/billing': { icon: CreditCard, id: 'nav-billing' },
      '/playbooks': { icon: Zap, id: 'nav-playbooks' },
      '/ask': { icon: MessageSquare, id: 'nav-ask-weissman' },
    }
    return PRIMARY_NAV.map((item) => {
      if (!canAccessNavItem(item, session)) return null
      const m = meta[item.to]
      if (!m) return null
      return {
        to: item.to,
        label: t(item.labelKey),
        icon: m.icon,
        id: m.id,
        badge: m.badge,
        beta: item.beta,
        betaLabel: t('nav.beta'),
      }
    }).filter(Boolean)
  }, [t, engineCountLabel, session])

  const navSections = useMemo(() => {
    const sections = [
      {
        id: 'command',
        title: t('nav.groups.command'),
        defaultOpen: true,
        items: [
          { to: '/', label: t('nav.dashboard'), icon: LayoutDashboard, id: 'nav-dashboard', matchPaths: ['/', '/operations'] },
          { to: '/findings', label: t('nav.findings'), icon: ShieldAlert, id: 'nav-findings-c2' },
          { to: '/jobs', label: t('nav.jobs'), icon: Clock, id: 'nav-jobs' },
        ],
      },
      {
        id: 'intelligence',
        title: t('nav.groups.intelligence'),
        defaultOpen: true,
        items: [
          { to: '/threat-intel', label: t('nav.threat_intel'), icon: Radar, id: 'nav-threat-intel' },
          { to: '/risk-graph', label: t('nav.attack_paths'), icon: GitBranch, id: 'nav-attack-paths' },
        ],
      },
      {
        id: 'automation',
        title: t('nav.groups.automation'),
        items: [
          { to: '/scan-scheduler', label: t('nav.scan_scheduler'), icon: CalendarClock, id: 'nav-scan-scheduler' },
          { to: '/alert-rules', label: t('nav.alert_rules'), icon: Bell, id: 'nav-alert-rules' },
        ],
      },
      {
        id: 'clients_agents',
        title: t('nav.groups.clients_agents'),
        defaultOpen: true,
        items: [
          { to: '/agents', label: t('nav.agent_management'), icon: Server, id: 'nav-agents' },
          { to: '/nexus-swarm', label: t('nav.nexus_swarm'), icon: Zap, id: 'nav-nexus-swarm' },
        ],
      },
      {
        id: 'platform',
        title: t('nav.groups.platform'),
        items: [
          { to: '/audit-log', label: t('nav.audit_log'), icon: ScrollText, id: 'nav-audit-log' },
          { to: '/system-config', label: t('nav.system_config'), icon: Settings, id: 'nav-system-config' },
          ...(isCeo ? [{ to: '/admin', label: t('nav.admin'), icon: Shield, id: 'nav-admin-management' }] : []),
        ],
      },
    ]
    return sections
  }, [t, isCeo])


  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const d = await apiFetch('/api/dashboard/stats')
        if (!cancelled) {
          setStats({
            total_vulnerabilities: d.total_vulnerabilities ?? 0,
            security_score: d.security_score ?? 0,
            active_scans: d.active_scans ? 1 : 0,
          })
        }
      } catch { /* best-effort; non-fatal */ }
    }
    load()
    const interval = setInterval(load, 15000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  const healthColor = stats.security_score >= 70 ? '#4ade80' : stats.security_score >= 40 ? '#fbbf24' : '#f87171'

  const sidebarContent = (
    <>
      {/* Brand */}
      <div className="shrink-0 px-4 pt-4 pb-3 border-b border-[var(--border-subtle)]">
        {isCeo && (
          <Link
            to="/"
            className="mb-3 block text-center text-[9px] font-mono uppercase tracking-[0.2em] py-1.5 rounded-md border border-amber-500/30 text-amber-200/90 hover:bg-amber-950/30 transition-colors"
          >
            {ceoIntegrated ? t(`${GN}.ceo_integrated`) : t(`${GN}.ceo_home`)}
          </Link>
        )}
        <Link to="/" aria-label={t('a11y.home')} className="block group">
          <Logo size={26} className="opacity-95 group-hover:opacity-100 transition-opacity" />
          <p className="mt-2 text-[9px] font-mono uppercase tracking-[0.28em] text-cyan-400/70">
            {t('nav.command_center')}
          </p>
        </Link>
        <div className="mt-3 grid grid-cols-2 gap-2">
          <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--row-hover-bg)] px-2.5 py-2">
            <div className="text-[8px] font-mono uppercase tracking-[0.18em] text-[var(--text-muted)] mb-1">
              {t('nav.active_threats')}
            </div>
            <div className="text-sm font-semibold font-mono tabular-nums text-cyan-300">
              {stats.total_vulnerabilities.toLocaleString()}
            </div>
          </div>
          <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--row-hover-bg)] px-2.5 py-2">
            <div className="text-[8px] font-mono uppercase tracking-[0.18em] text-[var(--text-muted)] mb-1">
              {t('nav.system_health')}
            </div>
            <div className="text-sm font-semibold font-mono tabular-nums" style={{ color: healthColor }}>
              {stats.security_score}%
            </div>
          </div>
        </div>
        {stats.active_scans > 0 && (
          <div className="mt-2 flex items-center gap-1.5 text-[9px] font-mono uppercase tracking-wider text-emerald-400/80">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            {t('nav.scan_active')}
          </div>
        )}
      </div>

      {/* Grouped navigation */}
      <nav className="flex-1 min-h-0 overflow-y-auto overflow-x-hidden px-2 py-2 scrollbar-thin" aria-label={t('a11y.nav_label')}>
        <div className="mb-2 pb-2 border-b border-[var(--border-subtle)]">
          <div className="px-2 py-1.5 text-[9px] font-mono uppercase tracking-[0.22em] text-[var(--text-muted)]">
            {t('nav.groups.primary')}
          </div>
          <div className="space-y-0.5 pb-1">
            {primaryNavItems.map((item) => (
              <NavLink key={item.id} {...item} />
            ))}
          </div>
        </div>

        {navSections.map((section) => (
          <NavSection
            key={section.id}
            id={section.id}
            title={section.title}
            open={sectionOpen[section.id] ?? section.defaultOpen ?? false}
            onToggle={toggleSection}
          >
            {section.items
              .filter((item) => canAccessNavItem(item, session))
              .map((item) => (
              <NavLink key={item.id} {...item} />
            ))}
          </NavSection>
        ))}
      </nav>

      {/* Client roster */}
      <div className="shrink-0 border-t border-[var(--border-subtle)] max-h-[28vh] lg:max-h-[22vh] flex flex-col min-h-0">
        <div className="px-4 py-2 text-[9px] font-mono uppercase tracking-[0.22em] text-[var(--text-muted)]">
          {isClientUser ? t('nav.portal_workspace') : t('nav.client_roster')}
        </div>
        <div className="flex-1 overflow-y-auto min-h-0">
          {clientsError && (
            <div
              className="mx-3 mb-2 rounded-lg border border-rose-500/30 bg-rose-950/30 px-2 py-2 text-[10px] text-rose-200"
              role="alert"
            >
              <div className="flex justify-between gap-2 items-start">
                <span className="min-w-0 break-words">{clientsError}</span>
                <Button variant="unstyled"
                  type="button"
                  className="text-rose-400 underline shrink-0 text-[9px]"
                  onClick={dismissClientsError}
                >
                  {t('common.dismiss')}
                </Button>
              </div>
            </div>
          )}
          {clientScopeLocked ? (
            <div className="px-4 py-3">
              {clients[0] ? (
                <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2">
                  <div className="text-[12px] font-medium text-[var(--text-primary)] truncate">
                    {clients[0].name || `Client ${clients[0].id}`}
                  </div>
                  <div className="text-[9px] font-mono uppercase tracking-widest text-cyan-400/70 mt-0.5">
                    {t('nav.portal_locked')}
                  </div>
                </div>
              ) : (
                <p className="text-[11px] text-[var(--text-muted)]">{t('common.no_data')}</p>
              )}
            </div>
          ) : (
          <ul className="space-y-px pb-1">
            {clients.length === 0 && !clientsError && (
              <li className="px-4 py-2 text-[11px] text-[var(--text-muted)]">{t('common.no_data')}</li>
            )}
            {clients.length === 0 && clientsError && (
              <li className="px-4 py-2 text-[11px] text-rose-300/80">Client list unavailable.</li>
            )}
            {clients.map((c) => {
              const id = String(c.id)
              const selected = id === String(selectedClientId)
              const isDeleting = deletingId === id
              return (
                <li key={id} className="flex items-center group">
                  <Button variant="unstyled"
                    type="button"
                    onClick={() => {
                      if (clientScopeLocked) return
                      setSelectedClientId(id)
                    }}
                    disabled={clientScopeLocked && !selected}
                    className={`relative flex-1 min-w-0 text-start ps-4 pe-2 py-2 text-[12px] font-medium transition-all border-s-2 ${
                      selected
                        ? 'bg-cyan-500/[0.07] border-cyan-400 text-[var(--text-primary)] shadow-[inset_0_0_16px_rgba(34,211,238,0.05)]'
                        : 'border-transparent text-[var(--text-tertiary)] hover:bg-[var(--row-hover-bg)] hover:text-[var(--text-secondary)]'
                    }`}
                  >
                    <span className="block truncate">{c.name || `Client ${id}`}</span>
                    {clientScopeLocked && selected && (
                      <span className="block text-[9px] font-mono uppercase tracking-widest text-cyan-400/70 mt-0.5">
                        {t('nav.portal_locked')}
                      </span>
                    )}
                  </Button>
                  {canDeleteClients && (
                  <Button variant="unstyled"
                    type="button"
                    onClick={async (e) => {
                      e.stopPropagation()
                      if (isDeleting) return
                      if (!(await confirmDialog(t(`${GN}.delete_client_confirm`, { name: c.name || id })))) return
                      setDeletingId(id)
                      try {
                        await apiFetch(`/api/clients/${id}`, { method: 'DELETE' })
                        if (String(selectedClientId) === id) setSelectedClientId(null)
                        await refreshClients()
                      } catch (err) {
                        if (err?.response) {
                          toast.error(await formatApiErrorResponse(err.response))
                        } else {
                          toast.error(err?.message || t(`${GN}.network_error`))
                        }
                      }
                      setDeletingId(null)
                    }}
                    disabled={isDeleting}
                    className="shrink-0 p-2 text-[var(--text-disabled)] hover:text-rose-400 opacity-0 group-hover:opacity-100 transition-opacity disabled:opacity-50"
                    aria-label={t('a11y.delete_client')}
                  >
                    {isDeleting ? (
                      <span className="text-[10px]">…</span>
                    ) : (
                      <Trash2 className="w-3.5 h-3.5" strokeWidth={1.75} />
                    )}
                  </Button>
                  )}
                </li>
              )
            })}
          </ul>
          )}
        </div>
      </div>

      {/* New client — routes to the dedicated onboarding surface (full parameter set:
          scope, engine modules, AWS/GCP/Azure/OT integrations, RoE, stealth, eBPF).
          The inline quick-add form was removed to avoid a weaker duplicate path. */}
      {canCreateClients && (
      <div className="border-t border-[var(--border-subtle)] p-3 shrink-0 bg-[var(--bg-1)]/90">
        <Link
          id="nav-new-client"
          to="/clients/new"
          onClick={() => setMobileOpen(false)}
          className="w-full flex items-center justify-center gap-2 py-2 rounded-lg text-[11px] font-medium bg-cyan-500/15 text-cyan-300 border border-cyan-500/35 hover:bg-cyan-500/25 hover:border-cyan-400/50 transition-all"
        >
          <UserPlus className="w-3.5 h-3.5" strokeWidth={1.9} />
          {t('nav.add_client')}
        </Link>
      </div>
      )}

      {/* Footer: profile + language */}
      <div className="shrink-0 border-t border-[var(--border-subtle)] px-3 py-3 bg-[var(--bg-1)]/95 space-y-2.5">
        <ProfileMenu variant="sidebar" />
        <LanguageSwitcher className="w-full justify-center" />
      </div>
    </>
  )

  return (
    <>
      {/* Mobile toggle */}
      <Button variant="unstyled"
        type="button"
        onClick={() => setMobileOpen((v) => !v)}
        className="lg:hidden fixed bottom-4 start-4 z-50 flex items-center gap-2 px-3 py-2 rounded-xl border border-[var(--border-strong)] bg-[var(--bg-1)]/95 backdrop-blur-md text-[var(--text-secondary)] shadow-xl"
        aria-expanded={mobileOpen}
        aria-label={mobileOpen ? t('a11y.collapse_nav') : t('a11y.expand_nav')}
      >
        {mobileOpen ? <PanelLeftClose className="w-4 h-4" /> : <PanelLeft className="w-4 h-4" />}
        <span className="text-[10px] font-mono uppercase tracking-widest">{t('nav.mobile_label')}</span>
      </Button>

      <aside
        className={`cockpit-sidebar flex flex-col w-full lg:w-[17rem] lg:shrink-0 h-auto lg:h-full border-b lg:border-b-0 lg:border-e border-[var(--border-subtle)] overflow-hidden shrink-0 transition-all duration-300 ${
          mobileOpen
            ? 'max-h-[min(85dvh,640px)] lg:max-h-none opacity-100 pointer-events-auto'
            : 'max-h-0 lg:max-h-none opacity-0 lg:opacity-100 pointer-events-none lg:pointer-events-auto'
        }`}
        style={{
          background: 'var(--sidebar-bg)',
          boxShadow: 'inset -1px 0 0 var(--border-subtle)',
        }}
      >
        {sidebarContent}
      </aside>
    </>
  )
}
