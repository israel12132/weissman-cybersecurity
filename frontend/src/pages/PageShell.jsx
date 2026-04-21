/**
 * Shared page shell for all intelligence hubs.
 * Professional two-row header: branding + status row, then categorised navigation.
 */
import React, { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { apiFetch } from '../lib/apiBase'

// ─── Nav categories ──────────────────────────────────────────────────────────

const NAV_SECTIONS = [
  {
    label: 'Operations',
    color: '#22d3ee',
    links: [
      { id: 'ps-nav-dashboard',   to: '/',                 label: '⌂ Dashboard' },
      { id: 'ps-nav-hub',         to: '/platform-hub',     label: '⬡ Platform Hub' },
      { id: 'ps-nav-findings',    to: '/findings',         label: '◉ Findings C2' },
      { id: 'ps-nav-ir',          to: '/incident-response',label: '🚨 IR Center' },
      { id: 'ps-nav-status',      to: '/system-status',    label: '✓ System Status' },
    ],
  },
  {
    label: 'Engines',
    color: '#8b5cf6',
    links: [
      { id: 'ps-nav-engines',     to: '/engines',          label: '⬡ Engine Matrix' },
      { id: 'ps-nav-threat-intel',to: '/threat-intel',     label: '🎯 Threat Intel' },
      { id: 'ps-nav-emulation',   to: '/threat-emulation', label: '◈ APT Emulation' },
      { id: 'ps-nav-threat-hunt', to: '/threat-hunting',   label: '🔎 Threat Hunting' },
      { id: 'ps-nav-vuln-intel',  to: '/vuln-intel',       label: '⚡ Vuln Intel' },
    ],
  },
  {
    label: 'Discovery',
    color: '#06b6d4',
    links: [
      { id: 'ps-nav-discovery',   to: '/domain-discovery', label: '🌐 Domains' },
      { id: 'ps-nav-network',     to: '/network',          label: '📡 Network' },
      { id: 'ps-nav-cloud',       to: '/cloud',            label: '☁ Cloud Tower' },
      { id: 'ps-nav-supply',      to: '/supply-chain',     label: '⛓ Supply Chain' },
      { id: 'ps-nav-dark-web',    to: '/dark-web',         label: '🕵 Dark Web' },
    ],
  },
  {
    label: 'Platform',
    color: '#f59e0b',
    links: [
      { id: 'ps-nav-oast',        to: '/oast',             label: '⊂ OAST / OOB' },
      { id: 'ps-nav-pqc',         to: '/pqc-radar',        label: '🔐 PQC Radar' },
      { id: 'ps-nav-twin',        to: '/digital-twin',     label: '⟐ Digital Twin' },
      { id: 'ps-nav-council',     to: '/council-queue',    label: '⚖ Council Queue' },
      { id: 'ps-nav-sso',         to: '/sso-config',       label: '🔑 SSO Config' },
      { id: 'ps-nav-admin',       to: '/admin',            label: '👤 Admin' },
    ],
  },
]

// ─── Health dot ──────────────────────────────────────────────────────────────

function HealthDot({ ok }) {
  if (ok === null) return <span className="w-2 h-2 rounded-full bg-white/20 inline-block" />
  return ok
    ? <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block animate-pulse" />
    : <span className="w-2 h-2 rounded-full bg-red-400 inline-block" />
}

// ─── Section dropdown ────────────────────────────────────────────────────────

function NavSection({ section, currentPath }) {
  const [open, setOpen] = useState(false)
  const isActive = section.links.some((l) => l.to === currentPath)

  return (
    <div
      className="relative"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      <button
        type="button"
        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all duration-150"
        style={{
          color: isActive ? section.color : `${section.color}99`,
          backgroundColor: isActive ? `${section.color}15` : 'transparent',
          border: `1px solid ${isActive ? `${section.color}40` : 'transparent'}`,
        }}
      >
        {section.label}
        <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor" className="opacity-60">
          <path d="M2 3.5l3 3 3-3" stroke="currentColor" strokeWidth="1.2" fill="none" strokeLinecap="round" />
        </svg>
      </button>
      {open && (
        <div
          className="absolute top-full left-0 mt-1 z-50 min-w-[180px] rounded-xl border border-white/10 bg-[#0a0f1e]/95 backdrop-blur-xl shadow-2xl py-1"
          style={{ boxShadow: `0 8px 32px rgba(0,0,0,0.6), 0 0 0 1px ${section.color}20` }}
        >
          {section.links.map((l) => (
            <Link
              key={l.id}
              id={l.id}
              to={l.to}
              className="flex items-center gap-2 px-4 py-2 text-xs font-mono transition-colors hover:bg-white/5"
              style={{ color: currentPath === l.to ? section.color : 'rgba(255,255,255,0.6)' }}
            >
              {l.label}
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── PageShell ───────────────────────────────────────────────────────────────

export default function PageShell({ title, subtitle, badge, badgeColor = '#22d3ee', children, actions }) {
  const location = useLocation()
  const [health, setHealth] = useState(null)
  const [publicCfg, setPublicCfg] = useState(null)

  useEffect(() => {
    let cancelled = false
    const check = async () => {
      try {
        const r = await fetch('/api/health')
        if (!cancelled) setHealth(r.ok)
      } catch {
        if (!cancelled) setHealth(false)
      }
    }
    check()
    const t = setInterval(check, 30000)
    return () => { cancelled = true; clearInterval(t) }
  }, [])

  useEffect(() => {
    apiFetch('/api/config/public')
      .then((r) => r.ok ? r.json() : null)
      .then((d) => { if (d) setPublicCfg(d) })
      .catch(() => {})
  }, [])

  const region = publicCfg?.region || publicCfg?.WEISSMAN_REGION || null
  const version = publicCfg?.version || null

  return (
    <div
      className="min-h-[100dvh] text-slate-100"
      style={{ background: 'radial-gradient(ellipse 140% 70% at 50% 0%, #0d1526 0%, #020617 55%, #000 100%)' }}
    >
      {/* ── Top brand bar ─────────────────────────────────────────────────── */}
      <div
        className="sticky top-0 z-30 border-b border-white/10"
        style={{ background: 'linear-gradient(180deg, rgba(6,9,20,0.98) 0%, rgba(4,7,18,0.95) 100%)', backdropFilter: 'blur(20px)' }}
      >
        {/* Brand row */}
        <div className="max-w-screen-2xl mx-auto px-6 py-2 flex items-center justify-between gap-4">
          {/* Logo + name */}
          <Link to="/platform-hub" className="flex items-center gap-3 group shrink-0">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center text-sm font-black"
              style={{ background: 'linear-gradient(135deg, #22d3ee 0%, #6366f1 100%)', boxShadow: '0 0 12px rgba(34,211,238,0.4)' }}
            >
              W
            </div>
            <div className="leading-none">
              <div className="text-sm font-black tracking-widest text-white uppercase">Weissman</div>
              <div className="text-[9px] font-mono text-white/30 tracking-[0.2em] uppercase">Cyber Intelligence</div>
            </div>
          </Link>

          {/* Page title */}
          <div className="flex items-center gap-3 flex-1 min-w-0 justify-center">
            {badge && (
              <span
                className="hidden sm:inline text-[9px] font-mono px-2 py-0.5 rounded-full uppercase tracking-widest border shrink-0"
                style={{ color: badgeColor, borderColor: `${badgeColor}40`, backgroundColor: `${badgeColor}10` }}
              >
                {badge}
              </span>
            )}
            {title && (
              <h1 className="text-sm font-bold text-white truncate">{title}</h1>
            )}
            {subtitle && (
              <span className="hidden lg:inline text-[10px] font-mono text-white/30 truncate">{subtitle}</span>
            )}
          </div>

          {/* Status + meta */}
          <div className="flex items-center gap-4 shrink-0">
            {actions && <div className="flex items-center gap-2">{actions}</div>}
            {region && (
              <span className="hidden md:inline text-[9px] font-mono text-white/30 uppercase tracking-widest border border-white/10 px-2 py-1 rounded">
                {region}
              </span>
            )}
            {version && (
              <span className="hidden lg:inline text-[9px] font-mono text-white/20 tracking-wider">
                v{version}
              </span>
            )}
            <div className="flex items-center gap-1.5 text-[10px] font-mono text-white/40">
              <HealthDot ok={health} />
              <span className="hidden sm:inline">{health === null ? 'checking…' : health ? 'Online' : 'Offline'}</span>
            </div>
            <Link
              to="/system-status"
              id="ps-header-system-status"
              className="hidden sm:flex items-center gap-1 text-[10px] font-mono text-white/30 hover:text-white/70 transition-colors border border-white/10 hover:border-white/20 px-2 py-1 rounded"
            >
              ⚙ Status
            </Link>
          </div>
        </div>

        {/* Navigation row */}
        <div className="max-w-screen-2xl mx-auto px-6 pb-1.5 flex items-center gap-1 overflow-x-auto scrollbar-none">
          {NAV_SECTIONS.map((s) => (
            <NavSection key={s.label} section={s} currentPath={location.pathname} />
          ))}
        </div>
      </div>

      {/* ── Main content ──────────────────────────────────────────────────── */}
      <main className="max-w-screen-2xl mx-auto px-4 py-8">
        {children}
      </main>
    </div>
  )
}
