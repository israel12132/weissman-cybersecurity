import React, { useState, useEffect, useMemo } from 'react'
import { Link, useLocation } from 'react-router-dom'
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
  ChevronDown,
  PanelLeftClose,
  PanelLeft,
  Trash2,
} from 'lucide-react'
import { useClient } from '../../context/ClientContext'
import { useAuth } from '../../context/AuthContext'
import { formatApiErrorFromBody, formatApiErrorResponse } from '../../lib/apiError.js'
import { apiFetch } from '../../lib/apiBase'
import { useProductionEngines } from '../../lib/useProductionEngines'
import Logo from '../Logo'
import ProfileMenu from '../ui/ProfileMenu'
import LanguageSwitcher from '../LanguageSwitcher'
import { useToast } from '../ui/Toaster'

const STORAGE_KEY = 'weissman.nav.sections'

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

function NavLink({ to, label, icon: Icon, id, matchPaths, badge }) {
  const { pathname } = useLocation()
  const active = isRouteActive(pathname, to, matchPaths)

  return (
    <Link
      id={id}
      to={to}
      className={`group relative flex items-center gap-2.5 pl-3 pr-2.5 py-[7px] rounded-lg text-[11px] font-medium tracking-wide transition-all duration-200 ${
        active
          ? 'text-cyan-100 bg-cyan-500/[0.08] shadow-[inset_0_0_20px_rgba(34,211,238,0.06)]'
          : 'text-white/55 hover:text-white/85 hover:bg-white/[0.04]'
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
          active ? 'text-cyan-400' : 'text-white/35 group-hover:text-white/55'
        }`}
        strokeWidth={active ? 2.25 : 1.75}
      />
      <span className="flex-1 truncate">{label}</span>
      {badge != null && (
        <span className="shrink-0 text-[9px] font-mono tabular-nums px-1.5 py-0.5 rounded border border-cyan-500/25 bg-cyan-500/10 text-cyan-300/80">
          {badge}
        </span>
      )}
    </Link>
  )
}

function NavSection({ id, title, children, defaultOpen = true, open, onToggle }) {
  return (
    <div className="mb-0.5">
      <button
        type="button"
        onClick={() => onToggle(id)}
        className="w-full flex items-center justify-between gap-2 px-2 py-2 rounded-md text-[9px] font-mono uppercase tracking-[0.22em] text-white/35 hover:text-white/55 hover:bg-white/[0.03] transition-colors"
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
      </button>
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
  const { isCeo } = useAuth()
  const { toast } = useToast()
  const { clients, clientsError, dismissClientsError, selectedClientId, setSelectedClientId, refreshClients } = useClient()
  const [stats, setStats] = useState({ total_vulnerabilities: 0, security_score: 0, active_scans: 0 })
  const [addName, setAddName] = useState('')
  const [addDomains, setAddDomains] = useState('')
  const [addContactEmail, setAddContactEmail] = useState('')
  const [addIpRanges, setAddIpRanges] = useState('')
  const [addTechStack, setAddTechStack] = useState('')
  const [addAutoDetectTech, setAddAutoDetectTech] = useState(true)
  const [addAwsArn, setAddAwsArn] = useState('')
  const [addAwsExt, setAddAwsExt] = useState('')
  const [addGcp, setAddGcp] = useState('')
  const [addSubmitting, setAddSubmitting] = useState(false)
  const [addMessage, setAddMessage] = useState(null)
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
  const { productionCount, catalogCount } = useProductionEngines()
  const engineCountLabel = productionCount > 0 ? productionCount : catalogCount

  const toggleSection = (id) => {
    setSectionOpen((prev) => {
      const next = { ...prev, [id]: !prev[id] }
      writeSectionState(next)
      return next
    })
  }

  const navSections = useMemo(() => {
    const sections = [
      {
        id: 'command',
        title: t('nav.groups.command'),
        defaultOpen: true,
        items: [
          { to: '/', label: t('nav.dashboard'), icon: LayoutDashboard, id: 'nav-dashboard', matchPaths: ['/', '/operations'] },
          { to: '/findings', label: t('nav.findings'), icon: ShieldAlert, id: 'nav-findings-c2' },
          { to: '/vuln-intel', label: t('nav.vuln_intel'), icon: Bug, id: 'nav-vuln-intel' },
          { to: '/jobs', label: t('nav.jobs'), icon: Clock, id: 'nav-jobs' },
        ],
      },
      {
        id: 'intelligence',
        title: t('nav.groups.intelligence'),
        defaultOpen: true,
        items: [
          { to: '/ask', label: t('nav.ask_weissman'), icon: MessageSquare, id: 'nav-ask-weissman' },
          { to: '/threat-intel', label: t('nav.threat_intel'), icon: Radar, id: 'nav-threat-intel' },
          { to: '/risk-graph', label: t('nav.attack_paths'), icon: GitBranch, id: 'nav-attack-paths' },
        ],
      },
      {
        id: 'automation',
        title: t('nav.groups.automation'),
        items: [
          { to: '/playbooks', label: t('nav.playbooks'), icon: Zap, id: 'nav-playbooks' },
          { to: '/scan-scheduler', label: t('nav.scan_scheduler'), icon: CalendarClock, id: 'nav-scan-scheduler' },
          { to: '/alert-rules', label: t('nav.alert_rules'), icon: Bell, id: 'nav-alert-rules' },
        ],
      },
      {
        id: 'clients_agents',
        title: t('nav.groups.clients_agents'),
        defaultOpen: true,
        items: [
          { to: '/clients', label: t('nav.clients'), icon: Building2, id: 'nav-clients' },
          { to: '/agents', label: t('nav.agent_management'), icon: Server, id: 'nav-agents' },
        ],
      },
      {
        id: 'platform',
        title: t('nav.groups.platform'),
        items: [
          { to: '/engines', label: t('nav.engines'), icon: Cpu, id: 'nav-engine-matrix', badge: engineCountLabel },
          { to: '/audit-log', label: t('nav.audit_log'), icon: ScrollText, id: 'nav-audit-log' },
          { to: '/system-config', label: t('nav.system_config'), icon: Settings, id: 'nav-system-config' },
          ...(isCeo ? [{ to: '/admin', label: t('nav.admin'), icon: Shield, id: 'nav-admin-management' }] : []),
        ],
      },
    ]
    return sections
  }, [t, isCeo, engineCountLabel])

  const handleAddClient = async (e) => {
    if (e) e.preventDefault()
    const name = addName.trim()
    if (!name) {
      setAddMessage({ error: 'Enter client name' })
      return
    }
    setAddMessage(null)
    setAddSubmitting(true)
    try {
      const toJsonArray = (raw) => {
        const trimmed = (raw || '').trim()
        if (!trimmed) return '[]'
        if (trimmed.startsWith('[')) return trimmed
        return JSON.stringify(trimmed.split(/[\s,]+/).filter(Boolean))
      }
      const domains = toJsonArray(addDomains)
      const ip_ranges = toJsonArray(addIpRanges)
      const tech_stack = toJsonArray(addTechStack)
      const payload = {
        name,
        domains,
        ip_ranges,
        tech_stack,
        contact_email: addContactEmail.trim(),
        auto_detect_tech_stack: addAutoDetectTech,
        aws_cross_account_role_arn: addAwsArn.trim(),
        aws_external_id: addAwsExt.trim(),
        gcp_project_id: addGcp.trim(),
      }
      const r = await apiFetch('/api/clients', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const d = await r.json().catch(() => ({}))
      if (r.ok && d.id != null) {
        setAddMessage({ success: true })
        setSelectedClientId(String(d.id))
        setAddName('')
        setAddDomains('')
        setAddContactEmail('')
        setAddIpRanges('')
        setAddTechStack('')
        setAddAutoDetectTech(true)
        setAddAwsArn('')
        setAddAwsExt('')
        setAddGcp('')
        await refreshClients()
        toast.success(`Client "${name}" added`)
        setTimeout(() => setAddMessage(null), 2000)
      } else {
        const errMsg = r.status === 401 ? 'Please log in again' : formatApiErrorFromBody(d, r.status)
        setAddMessage({ error: errMsg })
        toast.error(errMsg)
      }
    } catch (_) {
      setAddMessage({ error: 'Network error' })
      toast.error('Network error — could not reach API.')
    }
    setAddSubmitting(false)
  }

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const r = await apiFetch('/api/dashboard/stats')
        if (r.ok && !cancelled) {
          const d = await r.json()
          setStats({
            total_vulnerabilities: d.total_vulnerabilities ?? 0,
            security_score: d.security_score ?? 0,
            active_scans: d.active_scans ? 1 : 0,
          })
        }
      } catch (_) {}
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
      <div className="shrink-0 px-4 pt-4 pb-3 border-b border-white/[0.06]">
        {isCeo && (
          <Link
            to="/"
            className="mb-3 block text-center text-[9px] font-mono uppercase tracking-[0.2em] py-1.5 rounded-md border border-amber-500/30 text-amber-200/90 hover:bg-amber-950/30 transition-colors"
          >
            {ceoIntegrated ? 'Cockpit · mission control' : 'CEO cockpit home'}
          </Link>
        )}
        <Link to="/" aria-label="Weissman Cybersecurity home" className="block group">
          <Logo size={26} className="opacity-95 group-hover:opacity-100 transition-opacity" />
          <p className="mt-2 text-[9px] font-mono uppercase tracking-[0.28em] text-cyan-400/70">
            {t('nav.command_center')}
          </p>
        </Link>
        <div className="mt-3 grid grid-cols-2 gap-2">
          <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] px-2.5 py-2">
            <div className="text-[8px] font-mono uppercase tracking-[0.18em] text-white/35 mb-1">
              {t('nav.active_threats')}
            </div>
            <div className="text-sm font-semibold font-mono tabular-nums text-cyan-300">
              {stats.total_vulnerabilities.toLocaleString()}
            </div>
          </div>
          <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] px-2.5 py-2">
            <div className="text-[8px] font-mono uppercase tracking-[0.18em] text-white/35 mb-1">
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
      <nav className="flex-1 min-h-0 overflow-y-auto overflow-x-hidden px-2 py-2 scrollbar-thin" aria-label="Command center navigation">
        {navSections.map((section) => (
          <NavSection
            key={section.id}
            id={section.id}
            title={section.title}
            open={sectionOpen[section.id] ?? section.defaultOpen ?? false}
            onToggle={toggleSection}
          >
            {section.items.map((item) => (
              <NavLink key={item.id} {...item} />
            ))}
          </NavSection>
        ))}
      </nav>

      {/* Client roster */}
      <div className="shrink-0 border-t border-white/[0.06] max-h-[28vh] lg:max-h-[22vh] flex flex-col min-h-0">
        <div className="px-4 py-2 text-[9px] font-mono uppercase tracking-[0.22em] text-white/35">
          {t('nav.client_roster')}
        </div>
        <div className="flex-1 overflow-y-auto min-h-0">
          {clientsError && (
            <div
              className="mx-3 mb-2 rounded-lg border border-rose-500/30 bg-rose-950/30 px-2 py-2 text-[10px] text-rose-200"
              role="alert"
            >
              <div className="flex justify-between gap-2 items-start">
                <span className="min-w-0 break-words">{clientsError}</span>
                <button
                  type="button"
                  className="text-rose-400 underline shrink-0 text-[9px]"
                  onClick={dismissClientsError}
                >
                  Dismiss
                </button>
              </div>
            </div>
          )}
          <ul className="space-y-px pb-1">
            {clients.length === 0 && !clientsError && (
              <li className="px-4 py-2 text-[11px] text-white/35">{t('common.no_data')}</li>
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
                  <button
                    type="button"
                    onClick={() => setSelectedClientId(id)}
                    className={`relative flex-1 min-w-0 text-left ps-4 pe-2 py-2 text-[12px] font-medium transition-all border-s-2 ${
                      selected
                        ? 'bg-cyan-500/[0.07] border-cyan-400 text-white shadow-[inset_0_0_16px_rgba(34,211,238,0.05)]'
                        : 'border-transparent text-white/55 hover:bg-white/[0.03] hover:text-white/80'
                    }`}
                  >
                    <span className="block truncate">{c.name || `Client ${id}`}</span>
                  </button>
                  <button
                    type="button"
                    onClick={async (e) => {
                      e.stopPropagation()
                      if (isDeleting) return
                      if (!window.confirm(`Delete "${c.name || id}"?`)) return
                      setDeletingId(id)
                      try {
                        const r = await apiFetch(`/api/clients/${id}`, { method: 'DELETE' })
                        if (r.ok || r.status === 204) {
                          if (String(selectedClientId) === id) setSelectedClientId(null)
                          await refreshClients()
                        } else {
                          setAddMessage({ error: await formatApiErrorResponse(r) })
                        }
                      } catch (err) {
                        setAddMessage({ error: err?.message || 'Network error' })
                      }
                      setDeletingId(null)
                    }}
                    disabled={isDeleting}
                    className="shrink-0 p-2 text-white/25 hover:text-rose-400 opacity-0 group-hover:opacity-100 transition-opacity disabled:opacity-50"
                    aria-label={t('a11y.delete_client')}
                  >
                    {isDeleting ? (
                      <span className="text-[10px]">…</span>
                    ) : (
                      <Trash2 className="w-3.5 h-3.5" strokeWidth={1.75} />
                    )}
                  </button>
                </li>
              )
            })}
          </ul>
        </div>
      </div>

      {/* Add client */}
      <div className="border-t border-white/[0.06] p-3 shrink-0 relative z-[100] bg-[#060a12]/90">
        <div className="text-[9px] uppercase tracking-[0.2em] text-white/40 mb-2 font-mono">
          {t('nav.add_client')}
        </div>
        <div className="space-y-2">
          <input
            type="text"
            value={addName}
            onChange={(e) => setAddName(e.target.value)}
            placeholder="Client name *"
            className="w-full px-2.5 py-1.5 rounded-lg bg-black/40 border border-white/[0.08] text-white text-[12px] placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
          />
          <input
            type="text"
            value={addDomains}
            onChange={(e) => setAddDomains(e.target.value)}
            placeholder="Domains: a.com, b.com"
            className="w-full px-2.5 py-1.5 rounded-lg bg-black/40 border border-white/[0.08] text-white text-[12px] placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
          />
          <details className="text-[10px] text-white/45">
            <summary className="cursor-pointer text-cyan-400/70 hover:text-cyan-300 py-0.5">
              Advanced scope
            </summary>
            <div className="space-y-2 pt-2">
              <input
                type="email"
                value={addContactEmail}
                onChange={(e) => setAddContactEmail(e.target.value)}
                placeholder="Contact email"
                className="w-full px-2.5 py-1.5 rounded-lg bg-black/40 border border-white/[0.08] text-white text-[12px] placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
              />
              <input
                type="text"
                value={addIpRanges}
                onChange={(e) => setAddIpRanges(e.target.value)}
                placeholder="IP ranges"
                className="w-full px-2.5 py-1.5 rounded-lg bg-black/40 border border-white/[0.08] text-white text-[12px] placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
              />
              <input
                type="text"
                value={addTechStack}
                onChange={(e) => setAddTechStack(e.target.value)}
                placeholder="Tech stack hints"
                className="w-full px-2.5 py-1.5 rounded-lg bg-black/40 border border-white/[0.08] text-white text-[12px] placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
              />
              <label className="flex items-center gap-2 text-[10px] text-white/55 cursor-pointer">
                <input
                  type="checkbox"
                  checked={addAutoDetectTech}
                  onChange={(e) => setAddAutoDetectTech(e.target.checked)}
                  className="rounded border-white/20"
                />
                Auto-detect tech stack
              </label>
              <input
                type="text"
                value={addAwsArn}
                onChange={(e) => setAddAwsArn(e.target.value)}
                placeholder="AWS role ARN"
                className="w-full px-2.5 py-1.5 rounded-lg bg-black/40 border border-white/[0.08] text-white text-[12px] placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
              />
              <input
                type="text"
                value={addAwsExt}
                onChange={(e) => setAddAwsExt(e.target.value)}
                placeholder="AWS external ID"
                className="w-full px-2.5 py-1.5 rounded-lg bg-black/40 border border-white/[0.08] text-white text-[12px] placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
              />
              <input
                type="text"
                value={addGcp}
                onChange={(e) => setAddGcp(e.target.value)}
                placeholder="GCP project ID"
                className="w-full px-2.5 py-1.5 rounded-lg bg-black/40 border border-white/[0.08] text-white text-[12px] placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
              />
            </div>
          </details>
          {addMessage?.error && (
            <p id="add-client-error-msg" className="text-[10px] text-red-400">{addMessage.error}</p>
          )}
          {addMessage?.success && (
            <p id="add-client-success-msg" className="text-[10px] text-emerald-400">Client added.</p>
          )}
          <button
            id="add-client-submit-btn"
            type="button"
            disabled={addSubmitting}
            onClick={() => handleAddClient()}
            className="w-full py-2 rounded-lg text-[11px] font-medium bg-cyan-500/15 text-cyan-300 border border-cyan-500/35 hover:bg-cyan-500/25 hover:border-cyan-400/50 disabled:opacity-50 transition-all"
          >
            {addSubmitting ? 'Adding…' : 'Add Client'}
          </button>
        </div>
      </div>

      {/* Footer: profile + language */}
      <div className="shrink-0 border-t border-white/[0.06] px-3 py-3 bg-[#050810]/95 space-y-2.5">
        <ProfileMenu variant="sidebar" />
        <LanguageSwitcher className="w-full justify-center" />
      </div>
    </>
  )

  return (
    <>
      {/* Mobile toggle */}
      <button
        type="button"
        onClick={() => setMobileOpen((v) => !v)}
        className="lg:hidden fixed bottom-4 start-4 z-50 flex items-center gap-2 px-3 py-2 rounded-xl border border-white/15 bg-[#0a0f1a]/95 backdrop-blur-md text-white/80 shadow-xl"
        aria-expanded={mobileOpen}
        aria-label={mobileOpen ? 'Collapse navigation' : 'Expand navigation'}
      >
        {mobileOpen ? <PanelLeftClose className="w-4 h-4" /> : <PanelLeft className="w-4 h-4" />}
        <span className="text-[10px] font-mono uppercase tracking-widest">Nav</span>
      </button>

      <aside
        className={`flex flex-col w-full lg:w-[17rem] lg:shrink-0 h-auto lg:h-full border-b lg:border-b-0 lg:border-r border-white/[0.06] overflow-hidden shrink-0 transition-all duration-300 ${
          mobileOpen
            ? 'max-h-[min(85dvh,640px)] lg:max-h-none opacity-100 pointer-events-auto'
            : 'max-h-0 lg:max-h-none opacity-0 lg:opacity-100 pointer-events-none lg:pointer-events-auto'
        }`}
        style={{
          background: 'linear-gradient(180deg, rgba(10,15,26,0.97) 0%, rgba(5,8,16,0.99) 55%, rgba(3,6,12,1) 100%)',
          boxShadow: 'inset -1px 0 0 rgba(255,255,255,0.03)',
        }}
      >
        {sidebarContent}
      </aside>
    </>
  )
}
